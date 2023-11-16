// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/spi/spi.h>
#include <linux/errno.h>
#include <linux/phylink.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/of_mdio.h>
#include <linux/of_device.h>
#include <linux/netdev_features.h>
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/dsa/netc.h>
#include "netc.h"

int netc_is_vlan_configured(struct netc_private *priv, uint16_t vid)
{
	struct netc_vlan_entry *vlan;
	int count, i;

	vlan = priv->config.vlan;
	count = priv->config.vlan_count;

	for (i = 0; i < count; i++) {
		if (vlan[i].vid == vid)
			return i;
	}

	/* Return an invalid entry index if not found */
	return -1;
}

static int netc_drop_untagged(struct dsa_switch *ds, int port, bool drop)
{
	struct netc_private *priv = ds->priv;
	struct netc_mac_config *mac;

	mac = &priv->config.mac[port];
	if (mac->drpuntag == drop)
		return 0;

	mac->drpuntag = drop;

	return netc_port_dropuntag_set(priv, port, drop);
}

static int netc_pvid_apply(struct netc_private *priv, int port, uint16_t pvid)
{
	struct netc_mac_config *mac;

	mac = &priv->config.mac[port];
	if (mac->vlanid == pvid)
		return 0;

	mac->vlanid = pvid;

	return netc_port_pvid_set(priv, port, pvid);
}

static int netc_commit_pvid(struct dsa_switch *ds, int port)
{
	struct dsa_port *dp = dsa_to_port(ds, port);
	struct net_device *br = dsa_port_bridge_dev_get(dp);
	struct netc_private *priv = ds->priv;
	bool drop_untagged = false;
	int rc;
	uint16_t pvid;

	if (br && br_vlan_enabled(br))
		pvid = priv->bridge_pvid[port];
	else
		pvid = priv->tag_8021q_pvid[port];

	rc = netc_pvid_apply(priv, port, pvid);
	if (rc)
		return rc;

	/*
	 * Only force dropping of untagged packets when the port is under a
	 * VLAN-aware bridge. When the tag_8021q pvid is used, we are
	 * deliberately removing the RX VLAN from the port's VMEMB_PORT list,
	 * to prevent DSA tag spoofing from the link partner. Untagged packets
	 * are the only ones that should be received with tag_8021q, so
	 * definitely don't drop them.
	 */
	if (dsa_is_cpu_port(ds, port) || dsa_is_dsa_port(ds, port))
		drop_untagged = true;

	return netc_drop_untagged(ds, port, drop_untagged);
}

static int netc_fdb_add(struct dsa_switch *ds, int port,
			const unsigned char *addr, uint16_t vid,
			struct dsa_db db)
{
	struct netc_private *priv = ds->priv;

	if (!vid) {
		switch (db.type) {
		case DSA_DB_PORT:
			vid = dsa_tag_8021q_standalone_vid(db.dp);
			break;
		case DSA_DB_BRIDGE:
			vid = dsa_tag_8021q_bridge_vid(db.bridge.num);
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	/* Allow enough time between consecutive calls for adding FDB entry */
	usleep_range(NETC_SPI_MSG_RESPONSE_TIME,
		     NETC_SPI_MSG_RESPONSE_TIME * 10);

	return netc_fdb_entry_add(priv, addr, vid, port);
}

static int netc_fdb_del(struct dsa_switch *ds, int port,
			const unsigned char *addr, uint16_t vid,
			struct dsa_db db)
{
	struct netc_private *priv = ds->priv;

	if (!vid) {
		switch (db.type) {
		case DSA_DB_PORT:
			vid = dsa_tag_8021q_standalone_vid(db.dp);
			break;
		case DSA_DB_BRIDGE:
			vid = dsa_tag_8021q_bridge_vid(db.bridge.num);
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	return netc_fdb_entry_del(priv, addr, vid);
}

static int netc_fdb_dump(struct dsa_switch *ds, int port,
			 dsa_fdb_dump_cb_t *cb, void *data)
{
	struct netc_private *priv = ds->priv;
	struct device *dev = ds->dev;
	u32 entry_id = 0, next_id = 0;
	int rc;

	while (1) {
		struct netc_fdb_entry fdb = {0};

		rc = netc_fdb_entry_get(priv, &fdb, entry_id, &next_id);
		/* No fdb entry at i, not an issue */
		if (rc) {
			dev_err(dev, "Failed to dump FDB: %d\n", rc);
			return rc;
		}

		if (next_id == 0) /* This entry is empty */
			return 0;

		/*
		 * FDB dump callback is per port. This means we have to
		 * disregard a valid entry if it's not for this port, even if
		 * only to revisit it later. This is inefficient because the
		 * 1024-sized FDB table needs to be traversed 4 times through
		 * SPI during a 'bridge fdb show' command.
		 */
		if (fdb.port_map & BIT(port)) {
			/* Need to hide the dsa_8021q VLANs from the user. */
			if (vid_is_dsa_8021q(fdb.vid))
				fdb.vid = 0;

			rc = cb(fdb.mac_addr, fdb.vid, fdb.dynamic, data);
			if (rc)
				return rc;
		}

		entry_id = next_id;

		if (entry_id == 0 || entry_id == 0xffffffff)
			break;
	}

	return 0;
}

static int netc_parse_ports_node(struct netc_private *priv,
				    struct device_node *ports_node)
{
	struct device *dev = &priv->spidev->dev;
	struct device_node *child;

	for_each_available_child_of_node(ports_node, child) {
		struct device_node *phy_node;
		phy_interface_t phy_mode;
		u32 index;
		int err;

		/* Get switch port number from DT */
		if (of_property_read_u32(child, "reg", &index) < 0) {
			dev_err(dev, "Port number not defined in device tree\n");
			of_node_put(child);
			return -ENODEV;
		}

		/* Get PHY mode from DT */
		err = of_get_phy_mode(child, &phy_mode);
		if (err) {
			dev_err(dev, "Failed to read phy-mode or phy-interface-type %d\n",
				index);
			of_node_put(child);
			return -ENODEV;
		}

		phy_node = of_parse_phandle(child, "phy-handle", 0);
		if (!phy_node) {
			if (!of_phy_is_fixed_link(child)) {
				dev_err(dev, "phy-handle or fixed-link properties missing!\n");
				of_node_put(child);
				return -ENODEV;
			}
			/* phy-handle is missing, but fixed-link isn't.
			 * So it's a fixed link. Default to PHY role.
			 */
			priv->fixed_link[index] = true;
		} else {
			of_node_put(phy_node);
		}

		priv->phy_mode[index] = phy_mode;
	}

	return 0;
}

static int netc_parse_dt(struct netc_private *priv)
{
	struct device *dev = &priv->spidev->dev;
	struct device_node *switch_node = dev->of_node;
	struct device_node *ports_node;
	int rc;

	ports_node = of_get_child_by_name(switch_node, "ports");
	if (!ports_node)
		ports_node = of_get_child_by_name(switch_node, "ethernet-ports");
	if (!ports_node) {
		dev_err(dev, "Incorrect bindings: absent \"ports\" node\n");
		return -ENODEV;
	}

	rc = netc_parse_ports_node(priv, ports_node);
	of_node_put(ports_node);

	return rc;
}

static void netc_mac_link_down(struct dsa_switch *ds, int port,
			       unsigned int mode,
			       phy_interface_t interface)
{
	struct netc_private *priv = ds->priv;
	struct netc_mac_config *mac;

	mac = &priv->config.mac[port];

	mac->egress = false;

	netc_port_link_set(priv, port, false);
}

static void netc_mac_link_up(struct dsa_switch *ds, int port,
			     unsigned int mode,
			     phy_interface_t interface,
			     struct phy_device *phydev,
			     int speed, int duplex,
			     bool tx_pause, bool rx_pause)
{
	struct netc_private *priv = ds->priv;
	struct netc_mac_config *mac;

	mac = &priv->config.mac[port];

	mac->speed = speed;
	mac->egress = true;

	netc_port_phylink_mode_set(priv, mac);
	netc_port_link_set(priv, port, true);
}

static void netc_phylink_get_caps(struct dsa_switch *ds, int port,
				  struct phylink_config *config)
{
	struct netc_private *priv = ds->priv;
	phy_interface_t phy_mode;

	phy_mode = priv->phy_mode[port];
	__set_bit(phy_mode, config->supported_interfaces);

	/*
	 * The MAC does not support pause frames, and also doesn't
	 * support half-duplex traffic modes.
	 */
	config->mac_capabilities = MAC_10FD | MAC_100FD;
	config->mac_capabilities |= MAC_1000FD;
}

static int netc_bridge_member(struct dsa_switch *ds, int port,
			      struct dsa_bridge bridge, bool member)
{
	int rc;

	rc = netc_commit_pvid(ds, port);
	if (rc)
		return rc;

	return 0;
}

static int netc_bridge_join(struct dsa_switch *ds, int port,
			    struct dsa_bridge bridge,
			    bool *tx_fwd_offload,
			    struct netlink_ext_ack *extack)
{
	int rc;

	rc = netc_bridge_member(ds, port, bridge, true);
	if (rc)
		return rc;

	rc = dsa_tag_8021q_bridge_join(ds, port, bridge);
	if (rc) {
		netc_bridge_member(ds, port, bridge, false);
		return rc;
	}

	*tx_fwd_offload = true;

	return 0;
}

static void netc_bridge_leave(struct dsa_switch *ds, int port,
				 struct dsa_bridge bridge)
{
	dsa_tag_8021q_bridge_leave(ds, port, bridge);
	netc_bridge_member(ds, port, bridge, false);
}

static enum dsa_tag_protocol
netc_get_tag_protocol(struct dsa_switch *ds, int port,
			 enum dsa_tag_protocol mp)
{
	struct netc_private *priv = ds->priv;

	return priv->info->tag_proto;
}

int netc_vlan_filtering(struct dsa_switch *ds, int port, bool enabled,
			struct netlink_ext_ack *extack)
{
	struct netc_private *priv = ds->priv;
	struct netc_config *config = &priv->config;
	int rc;

	if (enabled) {
		/* Enable VLAN filtering. */
		config->tpid  = ETH_P_8021Q;
		config->tpid2 = ETH_P_8021AD;
	} else {
		/* Disable VLAN filtering. */
		config->tpid  = ETH_P_8021Q;
		config->tpid2 = ETH_P_NETC;
	}

	for (port = 0; port < ds->num_ports; port++) {
		if (dsa_is_unused_port(ds, port))
			continue;

		rc = netc_commit_pvid(ds, port);
		if (rc)
			return rc;
	}

	return 0;
}

static int netc_bridge_vlan_add(struct dsa_switch *ds, int port,
				const struct switchdev_obj_port_vlan *vlan,
				struct netlink_ext_ack *extack)
{
	struct netc_private *priv = ds->priv;
	uint16_t flags = vlan->flags;
	bool untagged = false;
	int rc;

	/* Be sure to deny the configuration done by tag_8021q. */
	if (vid_is_dsa_8021q(vlan->vid)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Range 3072-4095 reserved for dsa_8021q operation");
		return -EBUSY;
	}

	/* Always install bridge VLANs as egress-tagged on CPU and DSA ports */
	if (dsa_is_cpu_port(ds, port) || dsa_is_dsa_port(ds, port))
		flags = 0;

	if (flags & BRIDGE_VLAN_INFO_UNTAGGED)
		untagged = true;

	rc = netc_vlan_entry_add(priv, vlan->vid, port, untagged);
	if (rc)
		return rc;

	if (vlan->flags & BRIDGE_VLAN_INFO_PVID)
		priv->bridge_pvid[port] = vlan->vid;

	/* Allow enough time between adding VLAN entry and setting PVID */
	usleep_range(NETC_SPI_MSG_RESPONSE_TIME,
		     NETC_SPI_MSG_RESPONSE_TIME * 10);

	return netc_commit_pvid(ds, port);
}

static int netc_bridge_vlan_del(struct dsa_switch *ds, int port,
				const struct switchdev_obj_port_vlan *vlan)
{
	struct netc_private *priv = ds->priv;
	int rc;

	rc = netc_vlan_entry_del(priv, vlan->vid, port);
	if (rc)
		return rc;

	/*
	 * In case the pvid was deleted, make sure that untagged packets will
	 * be dropped.
	 */
	return netc_commit_pvid(ds, port);
}

static int netc_8021q_vlan_add(struct dsa_switch *ds, int port,
			       uint16_t vid, uint16_t flags)
{
	struct netc_private *priv = ds->priv;
	int rc;

	rc = netc_vlan_entry_add(priv, vid, port, false);
	if (rc)
		return rc;

	if (flags & BRIDGE_VLAN_INFO_PVID)
		priv->tag_8021q_pvid[port] = vid;

	/* Allow enough time between adding VLAN entry and setting PVID */
	usleep_range(NETC_SPI_MSG_RESPONSE_TIME,
		     NETC_SPI_MSG_RESPONSE_TIME * 10);

	return netc_commit_pvid(ds, port);
}

static int netc_8021q_vlan_del(struct dsa_switch *ds, int port, uint16_t vid)
{
	struct netc_private *priv = ds->priv;

	return netc_vlan_entry_del(priv, vid, port);
}

static int netc_prechangeupper(struct dsa_switch *ds, int port,
			       struct netdev_notifier_changeupper_info *info)
{
	struct netlink_ext_ack *extack = info->info.extack;
	struct net_device *upper = info->upper_dev;
	struct dsa_switch_tree *dst = ds->dst;
	struct dsa_port *dp;

	if (is_vlan_dev(upper)) {
		NL_SET_ERR_MSG_MOD(extack, "8021q uppers are not supported");
		return -EBUSY;
	}

	if (netif_is_bridge_master(upper)) {
		list_for_each_entry(dp, &dst->ports, list) {
			struct net_device *br = dsa_port_bridge_dev_get(dp);

			if (br && br != upper && br_vlan_enabled(br)) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Only one VLAN-aware bridge is supported");
				return -EBUSY;
			}
		}
	}

	return 0;
}

#define work_to_xmit_work(w) \
		container_of((w), struct netc_deferred_xmit_work, work)

static void netc_port_deferred_xmit(struct kthread_work *work)
{
	struct netc_deferred_xmit_work *xmit_work = work_to_xmit_work(work);
	struct sk_buff *clone, *skb = xmit_work->skb;
	struct dsa_switch *ds = xmit_work->dp->ds;
	int port = xmit_work->dp->index;

	clone = NETC_SKB_CB(skb)->clone;

	/* Transfer skb to the host port. */
	dsa_enqueue_skb(skb, dsa_to_port(ds, port)->slave);

	/* The clone, if there, was made by dsa_skb_tx_timestamp */
	if (clone)
		netc_ptp_txtstamp_skb(ds, port, clone);

	kfree(xmit_work);
}

static int netc_connect_tag_protocol(struct dsa_switch *ds,
					enum dsa_tag_protocol proto)
{
	struct netc_private *priv = ds->priv;
	struct netc_tagger_data *tagger_data;

	if (proto != priv->info->tag_proto)
		return -EPROTONOSUPPORT;

	tagger_data = netc_tagger_data(ds);
	tagger_data->xmit_work_fn = netc_port_deferred_xmit;

	return 0;
}

static int netc_change_mtu(struct dsa_switch *ds, int port, int new_mtu)
{
	struct netc_private *priv = ds->priv;
	int maxlen = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	if (dsa_is_cpu_port(ds, port) || dsa_is_dsa_port(ds, port))
		maxlen += VLAN_HLEN;

	return netc_port_mtu_set(priv, port, maxlen);
}

static int netc_get_max_mtu(struct dsa_switch *ds, int port)
{
	return 2000 - VLAN_ETH_HLEN - ETH_FCS_LEN;
}

static int netc_mac_init(struct netc_private *priv)
{
	struct netc_mac_config *mac;
	struct dsa_switch *ds = priv->ds;
	struct dsa_port *dp;

	mac = priv->config.mac;

	dsa_switch_for_each_port(dp, ds) {
		mac[dp->index].speed = 1000;
		mac[dp->index].vlanid = 1;
		mac[dp->index].drpuntag = false;
		mac[dp->index].retag = false;

		if (dsa_port_is_dsa(dp))
			dp->learning = true;

		/* Disallow untagged packets from being received on the
		 * CPU and DSA ports.
		 */
		if (dsa_port_is_cpu(dp) || dsa_port_is_dsa(dp))
			mac[dp->index].drpuntag = true;
	}

	return 0;
}

static int netc_dsa_init(struct netc_private *priv)
{
	struct dsa_switch *ds = priv->ds;
	struct dsa_port *dp, *cpu_dp = NULL;
	const u8 *mac;
	int port;

	for (port = 0; port < ds->num_ports; port++) {
		if (dsa_is_cpu_port(ds, port)) {
			cpu_dp = dsa_to_port(ds, port);
			break;
		}
	}

	if (!cpu_dp) {
		dev_err(ds->dev, "Failed to find cpu port\n");
		return -ENODEV;
	}

	if (!is_zero_ether_addr(cpu_dp->mac))
		mac = cpu_dp->mac;
	else
		mac = cpu_dp->master->dev_addr;

	pr_info("NETC DSA: cpu port:%d master:%s\n",
		cpu_dp->index, cpu_dp->master->name);

	for (port = 0; port < ds->num_ports; port++) {
		dp = dsa_to_port(ds, port);

		if (dsa_port_is_unused(dp))
			continue;
		if (dsa_port_is_cpu(dp))
			continue;

		pr_info("NETC DSA: add switch port:%d\n", port);

		netc_port_dsa_add(priv, cpu_dp->index, port, mac);
	}

	return 0;
}

static int netc_setup(struct dsa_switch *ds)
{
	struct netc_private *priv = ds->priv;
	int rc;

	rc = netc_config_setup(&priv->config);
	if (rc < 0) {
		dev_err(ds->dev, "Failed to setup config: %d\n", rc);
		return rc;
	}

	netc_mac_init(priv);
	netc_dsa_init(priv);

	rc = netc_devlink_setup(ds);
	if (rc < 0)
		goto out_config_free;

	rtnl_lock();
	rc = dsa_tag_8021q_register(ds, htons(ETH_P_8021Q));
	rtnl_unlock();
	if (rc)
		goto out_devlink_teardown;

	/*
	 * On netc, VLAN filtering per se is always enabled in hardware.
	 * The only thing we can do to disable it is lie about what the 802.1Q
	 * EtherType is.
	 * So it will still try to apply VLAN filtering, but all ingress
	 * traffic (except frames received with EtherType of ETH_P_NETC)
	 * will be internally tagged with a distorted VLAN header where the
	 * TPID is ETH_P_NETC, and the VLAN ID is the port pvid.
	 */
	ds->vlan_filtering_is_global = true;
	ds->untag_bridge_pvid = true;
	ds->fdb_isolation = true;
	/* tag_8021q has 3 bits for the VBID, and the value 0 is reserved */
	ds->max_num_bridges = 7;

	/* Advertise the 8 egress queues */
	ds->num_tx_queues = NETC_NUM_TC;

	ds->mtu_enforcement_ingress = true;
	ds->assisted_learning_on_cpu_port = true;

	return 0;

out_devlink_teardown:
	netc_devlink_teardown(ds);
out_config_free:
	netc_config_free(&priv->config);

	return rc;
}

static void netc_teardown(struct dsa_switch *ds)
{
	struct netc_private *priv = ds->priv;

	rtnl_lock();
	dsa_tag_8021q_unregister(ds);
	rtnl_unlock();

	netc_devlink_teardown(ds);
	netc_config_free(&priv->config);
}

static const struct dsa_switch_ops netc_switch_ops = {
	.get_tag_protocol	= netc_get_tag_protocol,
	.connect_tag_protocol	= netc_connect_tag_protocol,
	.setup			= netc_setup,
	.teardown		= netc_teardown,
	.port_change_mtu	= netc_change_mtu,
	.port_max_mtu		= netc_get_max_mtu,
	.phylink_get_caps	= netc_phylink_get_caps,
	.phylink_mac_link_up	= netc_mac_link_up,
	.phylink_mac_link_down	= netc_mac_link_down,
	.get_strings		= netc_get_strings,
	.get_ethtool_stats	= netc_get_ethtool_stats,
	.get_sset_count		= netc_get_sset_count,
	.port_fdb_dump          = netc_fdb_dump,
	.port_fdb_add           = netc_fdb_add,
	.port_fdb_del           = netc_fdb_del,
	.port_bridge_join	= netc_bridge_join,
	.port_bridge_leave	= netc_bridge_leave,
	.port_vlan_filtering	= netc_vlan_filtering,
	.port_vlan_add		= netc_bridge_vlan_add,
	.port_vlan_del		= netc_bridge_vlan_del,
	.devlink_info_get	= netc_devlink_info_get,
	.tag_8021q_vlan_add	= netc_8021q_vlan_add,
	.tag_8021q_vlan_del	= netc_8021q_vlan_del,
	.port_prechangeupper	= netc_prechangeupper,
};

static const struct of_device_id netc_dt_ids[];
static int netc_check_device_id(struct netc_private *priv)
{
	struct device *dev = &priv->spidev->dev;
	struct netc_config *config = &priv->config;
	int rc;

	rc = netc_get_devinfo(priv, config);
	if (rc < 0)
		return rc;

	if (config->device_id != priv->info->device_id) {
		dev_err(dev, "Device tree specifies device ID 0x%x, but found 0x%x please fix it!\n",
			priv->info->device_id, config->device_id);
		return -ENODEV;
	}

	return 0;
}

static int netc_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct netc_private *priv;
	struct dsa_switch *ds;
	size_t max_xfer, max_msg;
	int rc;

	if (!dev->of_node) {
		dev_err(dev, "No DTS bindings for netc driver\n");
		return -EINVAL;
	}

	priv = devm_kzalloc(dev, sizeof(struct netc_private), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/*
	 * Populate our driver private structure (priv) based on
	 * the device tree node that was probed (spi)
	 */
	priv->spidev = spi;
	spi_set_drvdata(spi, priv);

	/* Configure the SPI bus */
	spi->bits_per_word = NETC_SPI_WORD_BITS;
	rc = spi_setup(spi);
	if (rc < 0) {
		dev_err(dev, "Could not init SPI\n");
		return rc;
	}

	max_xfer = spi_max_transfer_size(spi);
	max_msg = spi_max_message_size(spi);

	/*
	 * We need to send at least one 64-bit word of SPI payload per message
	 * in order to be able to make useful progress.
	 */
	if (max_msg < NETC_SPI_MSG_HEADER_SIZE + 8) {
		dev_err(dev, "SPI master cannot send large enough buffers, aborting\n");
		return -EINVAL;
	}

	priv->max_xfer_len = NETC_SPI_MSG_MAXLEN;
	if (priv->max_xfer_len > max_xfer)
		priv->max_xfer_len = max_xfer;
	if (priv->max_xfer_len > max_msg - NETC_SPI_MSG_HEADER_SIZE)
		priv->max_xfer_len = max_msg - NETC_SPI_MSG_HEADER_SIZE;

	priv->info = of_device_get_match_data(dev);

	/* Detect hardware device */
	rc = netc_check_device_id(priv);
	if (rc < 0) {
		dev_err(dev, "Device ID check failed: %d\n", rc);
		return rc;
	}

	dev_info(dev, "Probed switch chip:%s ID:0x%x firmware:%d.%d.%d\n",
		 priv->info->name,
		 priv->config.device_id,
		 priv->config.version_major,
		 priv->config.version_minor,
		 priv->config.version_revision);

	ds = devm_kzalloc(dev, sizeof(*ds), GFP_KERNEL);
	if (!ds)
		return -ENOMEM;

	ds->dev = dev;
	ds->num_ports = priv->info->num_ports;
	ds->ops = &netc_switch_ops;
	ds->priv = priv;
	priv->ds = ds;

	mutex_init(&priv->mgmt_lock);

	rc = netc_parse_dt(priv);
	if (rc < 0) {
		dev_err(ds->dev, "Failed to parse DT: %d\n", rc);
		return rc;
	}

	return dsa_register_switch(priv->ds);
}

static void netc_remove(struct spi_device *spi)
{
	struct netc_private *priv = spi_get_drvdata(spi);

	if (!priv)
		return;

	dsa_unregister_switch(priv->ds);
}

static void netc_shutdown(struct spi_device *spi)
{
	struct netc_private *priv = spi_get_drvdata(spi);

	if (!priv)
		return;

	dsa_switch_shutdown(priv->ds);

	spi_set_drvdata(spi, NULL);
}

const struct netc_info netc_info = {
	.device_id		= NETC_RT1180_DEVICE_ID,
	.tag_proto		= DSA_TAG_PROTO_NETC_VALUE,
	.can_limit_mcast_flood	= false,
	.num_ports		= NETC_NUM_PORTS,
	.name			= "netc",
};

static const struct of_device_id netc_dt_ids[] = {
	{ .compatible = "nxp,imxrt1180-netc", .data = &netc_info},
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, netc_dt_ids);

static const struct spi_device_id netc_spi_ids[] = {
	{ "netc" },
	{ },
};
MODULE_DEVICE_TABLE(spi, netc_spi_ids);

static struct spi_driver netc_driver = {
	.driver = {
		.name  = "netc-spi",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(netc_dt_ids),
	},
	.id_table = netc_spi_ids,
	.probe  = netc_probe,
	.remove = netc_remove,
	.shutdown = netc_shutdown,
};

module_spi_driver(netc_driver);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@nxp.com>");

MODULE_DESCRIPTION("NETC DSA Driver");
MODULE_LICENSE("GPL v2");
