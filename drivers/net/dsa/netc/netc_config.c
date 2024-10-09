// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include "netc.h"

int netc_get_devinfo(struct netc_private *priv, struct netc_config *config)
{
	struct netc_cmd_sysinfo info;
	int rc;

	rc = netc_xfer_get_cmd(priv, NETC_CMD_SYS_INFO_GET, 0,
			       &info, sizeof(info));
	if (rc < 0)
		return rc;

	config->device_id = info.device_id;
	config->vendor_id = info.vendor_id;
	config->version_major = info.version_major;
	config->version_minor = info.version_minor;
	config->version_revision = info.version_revision;
	config->cpu_port_mode = info.cpu_port;

	return 0;
}

int netc_port_mtu_set(struct netc_private *priv, int port, int mtu)
{
	struct netc_cmd_port_mtu mtu_cmd = {0};

	mtu_cmd.port = (uint8_t)port;
	mtu_cmd.mtu = (uint16_t)mtu;

	return netc_xfer_set_cmd(priv, NETC_CMD_PORT_MTU_SET,
				 &mtu_cmd, sizeof(mtu_cmd));
}

int netc_port_mtu_get(struct netc_private *priv, int port, int *mtu)
{
	int rc;
	struct netc_cmd_port_mtu mtu_resp = {0};

	rc = netc_xfer_get_cmd(priv, NETC_CMD_PORT_MTU_GET, port,
			       &mtu_resp, sizeof(mtu_resp));

	if (rc != 0)
		return rc;

	*mtu = mtu_resp.mtu;

	return 0;
}

/* Set link speed in the MAC configuration for a specific port. */
int netc_port_phylink_mode_set(struct netc_private *priv,
			       struct netc_mac_config *mac)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_port_phylink_mode phylink_mode = {0};
	int rc;

	phylink_mode.port = mac->port;
	phylink_mode.duplex = mac->duplex;
	phylink_mode.speed = mac->speed;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PORT_PHYLINK_MODE_SET,
			       &phylink_mode, sizeof(phylink_mode));
	if (rc < 0) {
		dev_err(dev, "Failed to write phylink_mode: %d\n", rc);
		return rc;
	}

	return 0;
}

/* Get link speed in the MAC configuration for a specific port. */
int netc_port_phylink_status_get(struct netc_private *priv,
				 struct netc_mac_config *mac)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_port_phylink_status phylink_status = {0};
	int rc;

	rc = netc_xfer_get_cmd(priv, NETC_CMD_PORT_PHYLINK_STATUS_GET,
				mac->port,
				&phylink_status, sizeof(phylink_status));
	if (rc < 0) {
		dev_err(dev, "Failed to get phylink status: %d\n", rc);
		return rc;
	}

	mac->link = phylink_status.link;
	mac->speed = phylink_status.speed;
	mac->duplex = phylink_status.duplex;

	return 0;
}

int netc_port_pvid_set(struct netc_private *priv, int port, uint16_t pvid)
{
	int rc = 0;
	struct netc_cmd_port_pvid cmd_pvid = {0};

	cmd_pvid.port = (uint8_t)port;
	cmd_pvid.pvid = pvid;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PORT_PVID_SET,
			       &cmd_pvid, sizeof(cmd_pvid));

	return rc;
}

int netc_port_link_set(struct netc_private *priv, int port, bool up)
{
	int rc = 0;
	struct netc_cmd_port_link egress = {0};

	egress.port = (uint8_t)port;
	egress.link =  up;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PORT_LINK_SET,
			       &egress, sizeof(egress));

	return rc;
}

int netc_port_dropuntag_set(struct netc_private *priv, int port, bool drop)
{
	int rc = 0;
	struct netc_cmd_port_dropuntag dropuntag = {0};

	dropuntag.port = (uint8_t)port;
	dropuntag.drop = (uint16_t)drop;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PORT_DROPUNTAG_SET,
			       &dropuntag, sizeof(dropuntag));

	return rc;
}

int netc_port_dsa_add(struct netc_private *priv, int cpu_port,
		      int slave_port, const unsigned char *mac_addr)
{
	int rc = 0;
	struct netc_cmd_port_dsa_add dsa_add = {0};

	dsa_add.cpu_port = (uint8_t)cpu_port;
	dsa_add.slave_port = (uint8_t)slave_port;
	ether_addr_copy(dsa_add.mac_addr, mac_addr);

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PORT_DSA_ADD,
			       &dsa_add, sizeof(dsa_add));

	return rc;
}

int netc_port_dsa_del(struct netc_private *priv, int slave_port)
{
	int rc = 0;
	struct netc_cmd_port_dsa_del dsa_del = {0};

	dsa_del.slave_port = (uint8_t)slave_port;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PORT_DSA_DEL,
			       &dsa_del, sizeof(dsa_del));

	return rc;
}

int netc_vlan_entry_add(struct netc_private *priv,
			uint16_t vid, int port, bool untagged)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_vlan cmd_vlan = {0};
	int rc;

	cmd_vlan.vid = vid;
	cmd_vlan.port = (uint8_t)port;
	cmd_vlan.untagged = untagged;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_VLAN_ADD,
			      &cmd_vlan, sizeof(cmd_vlan));
	if (rc < 0) {
		dev_err(dev, "Failed to add vlan entry: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_vlan_entry_del(struct netc_private *priv, uint16_t vid, int port)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_vlan cmd_vlan = {0};
	int rc;

	cmd_vlan.vid = vid;
	cmd_vlan.port = (uint8_t)port;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_VLAN_DEL,
			       &cmd_vlan, sizeof(cmd_vlan));
	if (rc < 0) {
		dev_err(dev, "Failed to add vlan entry: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_vlan_entry_read(struct netc_private *priv,
			 struct netc_vlan_entry *vlan,
			 uint32_t entry_id, uint32_t *next_id)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_vlan_dump vlan_dump = {0};
	int rc;

	rc = netc_xfer_get_cmd(priv, NETC_CMD_VLAN_DUMP, entry_id,
			       &vlan_dump, sizeof(vlan_dump));
	if (rc < 0) {
		dev_err(dev, "Failed to read vlan entry 0x%08x: %d\n",
			entry_id, rc);
		return rc;
	}

	vlan->entry_id = entry_id;
	vlan->vid = vlan_dump.vid;
	vlan->port_map = vlan_dump.port_map;
	*next_id = vlan_dump.resume_entry_id;

	return 0;
}

int netc_fdb_entry_add(struct netc_private *priv,
		       const unsigned char *mac_addr,
		       uint16_t vid, int port)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_fdb fdb_add = {0};
	int rc;

	ether_addr_copy(fdb_add.mac_addr, mac_addr);
	fdb_add.vid = vid;
	fdb_add.port = (uint8_t)port;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_FDB_ADD,
			       &fdb_add, sizeof(fdb_add));
	if (rc < 0) {
		dev_err(dev, "Failed to add fdb: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_fdb_entry_del(struct netc_private *priv,
		       const unsigned char *mac_addr,
		       uint16_t vid, int port)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_fdb fdb_del = {0};
	int rc;

	ether_addr_copy(fdb_del.mac_addr, mac_addr);
	fdb_del.vid = vid;
	fdb_del.port = (uint8_t)port;;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_FDB_DEL,
			       &fdb_del, sizeof(fdb_del));
	if (rc < 0) {
		dev_err(dev, "Failed to delete fdb: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_fdb_entry_get(struct netc_private *priv, struct netc_fdb_entry *fdb,
		       uint32_t entry_id, uint32_t *next_id)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_fdb_dump fdb_dump = {0};
	int rc;

	rc = netc_xfer_get_cmd(priv, NETC_CMD_FDB_DUMP, entry_id,
			       &fdb_dump, sizeof(fdb_dump));
	if (rc < 0) {
		dev_err(dev, "Failed to get fdb entry: %d\n", rc);
		return rc;
	}

	*next_id = fdb_dump.resume_entry_id;

	ether_addr_copy(fdb->mac_addr, fdb_dump.mac_addr);
	fdb->vid = fdb_dump.vid;
	fdb->port_map = fdb_dump.port_map;
	fdb->dynamic = fdb_dump.dynamic;

	return 0;
}

int netc_streamid_set(struct netc_private *priv, int port_mask, uint16_t handle,
		const unsigned char *mac, uint16_t vid, tsn_cb_streamid_type type)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_nullstreamid streamid = {0};
	int rc;

	streamid.type = type;
	streamid.handle = handle;
	streamid.vid = vid;
	streamid.port_mask = port_mask;
	ether_addr_copy(streamid.mac_addr, mac);

	rc = netc_xfer_set_cmd(priv, NETC_CMD_STREAMID_SET, &streamid, sizeof(streamid));
	if (rc < 0) {
		dev_err(dev, "failed to add streamid: %d\n", handle);
		return rc;
	}

	return 0;
}

int netc_streamid_del(struct netc_private *priv, uint16_t stream_handle)
{
	struct device *dev = priv->ds->dev;
	int rc;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_STREAMID_DEL, &stream_handle, sizeof(stream_handle));
	if (rc < 0) {
		dev_err(dev, "failed to delete streamid: %d\n", stream_handle);
		return rc;
	}

	return 0;
}

int netc_port_priority_map(struct netc_private *priv, int port, uint8_t *map, int reset)
{
	struct netc_cmd_priority_map prio_map;
	int rc;

	prio_map.port = port;
	prio_map.reset = reset;
	memcpy(prio_map.map, map, sizeof(prio_map.map));

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PRIORITY_MAP_SET, &prio_map, sizeof(prio_map));

	return rc;
}

int netc_qbv_set(struct netc_private *priv, int port, int enable,
		 struct tc_taprio_qopt_offload *taprio)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_qbv_set_p1 qbvconf_p1 = {0};
	struct netc_cmd_qbv_set_p2 qbvconf_p2 = {0};
	struct netc_cmd_qbv_gcl qbvconf_gcl = {0};
	uint8_t buffer[16];
	uint8_t offset;
	int rc;

	qbvconf_p1.port = port;
	qbvconf_p1.enabled = enable;
	qbvconf_p1.base_time = taprio->base_time;
	qbvconf_p1.cycle_time = taprio->cycle_time;
	qbvconf_p1.gcl_len = taprio->num_entries;
	if (enable)
		qbvconf_p1.gcl_len = taprio->num_entries;
	else
		qbvconf_p1.gcl_len = 0;

	if (qbvconf_p1.gcl_len > NETC_QBV_LIST_MAX_ENTRIES)
		return -EINVAL;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_QBV_SET_P1, &qbvconf_p1, sizeof(qbvconf_p1));
	if (rc < 0)
		goto err;

	qbvconf_p2.cycle_time_ext = taprio->cycle_time_extension;
	if (qbvconf_p1.gcl_len > 0) {
		qbvconf_p2.gcl.interval = taprio->entries[0].interval;
		qbvconf_p2.gcl.gate_mask = taprio->entries[0].gate_mask;
		qbvconf_p2.gcl.operation = taprio->entries[0].command;
	}
	rc = netc_xfer_set_cmd(priv, NETC_CMD_QBV_SET_P2, &qbvconf_p2, sizeof(qbvconf_p2));
	if (rc < 0)
		goto err;

	offset = 0;
	memset(buffer, 0, sizeof(buffer));
	for (int i = 1; i < qbvconf_p1.gcl_len; i++) {
		qbvconf_gcl.interval = taprio->entries[i].interval;
		qbvconf_gcl.gate_mask = taprio->entries[i].gate_mask;
		qbvconf_gcl.operation = taprio->entries[i].command;
		memcpy(&buffer[offset], &qbvconf_gcl, sizeof(qbvconf_gcl));
		if (offset) {
			rc = netc_xfer_set_cmd(priv, NETC_CMD_QBV_SET_GCL, buffer, sizeof(buffer));
			if (rc < 0)
				goto err;

			offset = 0;
			memset(buffer, 0, sizeof(buffer));
		} else {
			offset = sizeof(qbvconf_gcl);
		}
	}

	if (offset) {
		rc = netc_xfer_set_cmd(priv, NETC_CMD_QBV_SET_GCL, buffer, sizeof(buffer));
		if (rc < 0)
			goto err;
	}

	return 0;
err:
	dev_err(dev, "failed to set qbv on port: %d\n", port);

	return rc;
}

int netc_qci_set(struct netc_private *priv, struct netc_stream_filter *filter)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_qci_set qci_set = {0};
	int rc;

	qci_set.stream_handle = filter->stream_handle;
	qci_set.maxsdu = filter->qci.maxsdu;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_QCI_SET,
			&qci_set, sizeof(qci_set));
	if (rc < 0) {
		dev_err(dev, "failed to set Qci setting: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_qci_del(struct netc_private *priv, uint16_t handle,
		uint32_t port)
{
	struct device *dev = priv->ds->dev;
	int rc;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_QCI_DEL,
			       &handle, sizeof(handle));
	if (rc < 0) {
		dev_err(dev, "failed to delete Qci setting: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_frer_seqgen(struct netc_private *priv, struct netc_stream_filter *filter)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_frer_sg frer_sg = {0};
	int rc;

	frer_sg.stream_handle = filter->stream_handle;
	frer_sg.iport = filter->seqgen.iport;
	frer_sg.encap = filter->seqgen.enc;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_FRER_SG_SET,
			&frer_sg, sizeof(frer_sg));
	if (rc < 0) {
		dev_err(dev, "failed to set FRER sequence generation: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_frer_seqrec(struct netc_private *priv, struct netc_stream_filter *filter)
{
	struct device *dev = priv->ds->dev;
	struct netc_cmd_frer_sr frer_sr = {0};
	int rc;

	frer_sr.stream_handle = filter->stream_handle;
	frer_sr.eport = filter->seqrec.eport;
	frer_sr.encap = filter->seqrec.enc;
	frer_sr.alg = filter->seqrec.alg;
	frer_sr.his_len = filter->seqrec.his_len;
	frer_sr.reset_timeout = filter->seqrec.reset_timeout;
	frer_sr.rtag_pop_en = filter->seqrec.rtag_pop_en;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_FRER_SR_SET,
			&frer_sr, sizeof(frer_sr));
	if (rc < 0) {
		dev_err(dev, "failed to set FRER sequence recovery: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_frer_sg_del(struct netc_private *priv, uint16_t stream_handle, uint32_t port)
{
	struct device *dev = priv->ds->dev;
	int rc;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_FRER_SG_DEL,
			&stream_handle, sizeof(stream_handle));
	if (rc < 0) {
		dev_err(dev, "failed to delete FRER setting: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_frer_sr_del(struct netc_private *priv, uint16_t stream_handle, uint32_t port)
{
	struct device *dev = priv->ds->dev;
	int rc;

	rc = netc_xfer_set_cmd(priv, NETC_CMD_FRER_SR_DEL,
			       &stream_handle, sizeof(stream_handle));
	if (rc < 0) {
		dev_err(dev, "failed to delete FRER setting: %d\n", rc);
		return rc;
	}

	return 0;
}

int netc_config_setup(struct netc_config *config)
{
	if (config->vlan_max_count) {
		config->vlan = kcalloc(config->vlan_max_count,
					sizeof(*config->vlan),
					GFP_KERNEL);
		if (!config->vlan)
			return -ENOMEM;
	}

	return 0;
}

void netc_config_free(struct netc_config *config)
{
	kfree(config->vlan);
}
