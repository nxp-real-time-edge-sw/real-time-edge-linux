// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#include <linux/if_vlan.h>
#include <linux/dsa/netc.h>
#include <linux/packing.h>
#include "tag.h"
#include "tag_8021q.h"

#define NETC_8021Q_NAME		"netc-8021q"

/*
 * NETC HEADRER after Source MAC
 *
 * |     2B      |     2B      |   0 / 4B / 8B / 12B / 16B |
 * +------------ +-------------+---------------------------+
 * |    0xDADC   |   HEADRER   |            DATA           |
 * +------------ +------------ +---------------------------+
 */

#define NETC_HEADER_LEN			4
#define NETC_HEADER_DATA_TS_ID_LEN	4
#define NETC_HEADER_DATA_TIMESTAP_LEN	8
#define NETC_HEADER_DATA_CMD_LEN	16

#define NETC_HEADER_HOST_TO_SWITCH	BIT(15)

/* Binary structure of the NETC Header ETH_P_NETC_META:
 *
 * |   15      |  14  |     13    |   12  |  11   | 10 - 9 |   7 - 4   |  3 - 0  |
 * +-----------+------+-----------+-------+-------+--------+-----------+---------+
 * | TO HOST 0 | META | HOST Only | RX TS | TX TS |        | Switch ID | Port ID |
 * +-----------+------+-----------+-------+-------+--------+-----------+---------+
 */
#define NETC_RX_HEADER_IS_METADATA	BIT(14)
#define NETC_RX_HEADER_HOST_ONLY	BIT(13)
#define NETC_RX_HEADER_RX_TIMESTAP	BIT(12)
#define NETC_RX_HEADER_TX_TIMESTAP	BIT(11)

#define NETC_HEADER_PORT_MASK		0x0F
#define NETC_HEADER_PORT_OFFSET		0
#define NETC_HEADER_SWITCH_MASK		0xF0
#define NETC_HEADER_SWITCH_OFFSET	4
#define NETC_RX_HEADER_PORT_ID(x)	((x) & NETC_HEADER_PORT_MASK)
#define NETC_RX_HEADER_SWITCH_ID(x)	(((x) & NETC_HEADER_SWITCH_MASK) >> NETC_HEADER_SWITCH_OFFSET)

/*
 * RX RX_Timestamp:
 *
 * |    64 - 0   |
 * +------------ +
 * |  TimeStamp  |
 * +------------ +
 */
#define NETC_HEADER_TIMESTAMP_LEN	8

/*
 * RX TX_Timestamp:
 *
 * |    64 - 0   |    32 - 0   |
 * +------------ +------------ +
 * |  TimeStamp  |    TS_ID    |
 * +------------ +------------ +
 */
#define NETC_RX_HEADER_TS_ID_LEN	4

/* TX header */

/*
 * Binary structure of the NETC Header ETH_P_NETC_META:
 *
 * |   15      |  14  |   13   |   12  |  11     | 10 - 9 |  7 - 4    |  3 - 0  |
 * +-----------+------+--------+-------+---------+--------+-----------+---------+
 * |  To SW 1  | META |        |       | TAKE TS |        | SWITCH ID | PORT ID |
 * +-----------+------+--------+-------+------  -+--------+-----------+---------+
 */

#define NETC_TX_HEADER_IS_METADATA	BIT(14)
#define NETC_TX_HEADER_TAKE_TS		BIT(11)

#define NETC_TX_HEADER_TSTAMP_ID(x)	(x)
#define NETC_TX_HEADER_SWITCHID(x)	(((x) << NETC_HEADER_SWITCH_OFFSET) & NETC_HEADER_SWITCH_MASK)
#define NETC_TX_HEADER_DESTPORTID(x)	((x) & NETC_HEADER_PORT_MASK)

/*
 * TX Take TS:
 *
 * |    32 - 0   |
 * +------------ +
 * |    TS_ID    |
 * +------------ +
 */
#define NETC_TX_HEADER_TS_ID_LEN	4

void print_skb_data(struct sk_buff *skb)
{
    u8 *buf = skb->data - ETH_HLEN;
    int len = skb->len;
    int i = 0;

    if (!skb) {
        printk("Bad skb parameter");
        return;
    }
    printk("Packet length = 0x%x", len);

    for (i = 0; i < len; i += 8) {
        printk("0x%04x: %02x %02x %02x %02x %02x %02x %02x %02x\n", i,
		buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3],
		buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
    }
    printk("\n");
}

/* Similar to is_link_local_ether_addr(hdr->h_dest) but also covers PTP */
static inline bool netc_is_link_local(const struct sk_buff *skb)
{
	const struct ethhdr *hdr = eth_hdr(skb);
	u64 dmac = ether_addr_to_u64(hdr->h_dest);

	if (ntohs(hdr->h_proto) == ETH_P_NETC)
		return false;

	if ((dmac & NETC_LINKLOCAL_FILTER_A_MASK) ==
	     NETC_LINKLOCAL_FILTER_A)
		return true;

	if ((dmac & NETC_LINKLOCAL_FILTER_B_MASK) ==
	     NETC_LINKLOCAL_FILTER_B)
		return true;

	return false;
}

/* Send VLAN tags with a TPID that blends in with whatever VLAN protocol a
 * bridge spanning ports of this switch might have.
 */
static u16 netc_xmit_tpid(struct dsa_port *dp)
{
	struct dsa_switch *ds = dp->ds;
	struct dsa_port *other_dp;
	u16 proto;

	if (!dsa_port_is_vlan_filtering(dp))
		return ETH_P_NETC_8021Q;

	/* Port is VLAN-aware, so there is a bridge somewhere (a single one,
	 * we're sure about that). It may not be on this port though, so we
	 * need to find it.
	 */
	dsa_switch_for_each_port(other_dp, ds) {
		struct net_device *br = dsa_port_bridge_dev_get(other_dp);

		if (!br)
			continue;

		/* Error is returned only if CONFIG_BRIDGE_VLAN_FILTERING,
		 * which seems pointless to handle, as our port cannot become
		 * VLAN-aware in that case.
		 */
		br_vlan_get_proto(br, &proto);

		return proto;
	}

	WARN_ONCE(1, "Port is VLAN-aware but cannot find associated bridge!\n");

	return ETH_P_NETC_8021Q;
}

static struct sk_buff *netc_imprecise_xmit(struct sk_buff *skb,
					   struct net_device *netdev)
{
	struct dsa_port *dp = dsa_slave_to_port(netdev);
	unsigned int bridge_num = dsa_port_bridge_num_get(dp);
	struct net_device *br = dsa_port_bridge_dev_get(dp);
	u16 tx_vid;

	/* If the port is under a VLAN-aware bridge, just slide the
	 * VLAN-tagged packet into the FDB and hope for the best.
	 * This works because we support a single VLAN-aware bridge
	 * across the entire dst, and its VLANs cannot be shared with
	 * any standalone port.
	 */
	if (br_vlan_enabled(br))
		return skb;

	/* If the port is under a VLAN-unaware bridge, use an imprecise
	 * TX VLAN that targets the bridge's entire broadcast domain,
	 * instead of just the specific port.
	 */
	tx_vid = dsa_tag_8021q_bridge_vid(bridge_num);

	if (unlikely(skb_vlan_tag_present(skb))) {
		skb = __vlan_hwaccel_push_inside(skb);
		if (!skb) {
			WARN_ONCE(1, "Failed to push VLAN tag to payload!\n");
			return NULL;
		}
	}

	return dsa_8021q_xmit(skb, netdev, netc_xmit_tpid(dp), tx_vid);
}

static struct sk_buff *netc_meta_xmit(struct sk_buff *skb,
				      struct net_device *netdev)
{
	struct sk_buff *clone = NETC_SKB_CB(skb)->clone;
	struct dsa_port *dp = dsa_slave_to_port(netdev);
	int len = NETC_HEADER_LEN;
	__be16 *tx_header;
	__be32 *p_ts_id;

	if (clone)
		len = len + NETC_TX_HEADER_TS_ID_LEN;

	skb_push(skb, len);

	dsa_alloc_etype_header(skb, len);

	tx_header = dsa_etype_header_pos_tx(skb);

	tx_header[0] = htons(ETH_P_NETC_META);
	tx_header[1] = htons(NETC_HEADER_HOST_TO_SWITCH |
                             NETC_TX_HEADER_SWITCHID(dp->ds->index) |
                             NETC_TX_HEADER_DESTPORTID(dp->index));
	if(clone) {
		tx_header[1] |= htons(NETC_TX_HEADER_TAKE_TS);
		p_ts_id = dsa_etype_header_pos_tx(skb) + NETC_HEADER_LEN;
		p_ts_id[0] = cpu_to_be32(NETC_SKB_CB(clone)->ts_id);
	}

	return skb;
}

static struct sk_buff *netc_8021q_xmit(struct sk_buff *skb,
				       struct net_device *netdev)
{
	struct dsa_port *dp = dsa_slave_to_port(netdev);
	u16 queue_mapping = skb_get_queue_mapping(skb);
	u8 pcp = netdev_txq_to_tc(netdev, queue_mapping);
	u16 tx_vid = dsa_tag_8021q_standalone_vid(dp);

	return dsa_8021q_xmit(skb, netdev, netc_xmit_tpid(dp),
			      ((pcp << VLAN_PRIO_SHIFT) | tx_vid));
}

static struct sk_buff *netc_xmit(struct sk_buff *skb,
				 struct net_device *netdev)
{
	if (skb->offload_fwd_mark)
		return netc_imprecise_xmit(skb, netdev);

	if (unlikely(netc_is_link_local(skb)))
		return netc_meta_xmit(skb, netdev);

	return netc_8021q_xmit(skb, netdev);
}

static bool netc_skb_has_tag_8021q(const struct sk_buff *skb)
{
	u16 tpid = ntohs(eth_hdr(skb)->h_proto);

	return tpid == ETH_P_NETC || tpid == ETH_P_8021Q ||
	       skb_vlan_tag_present(skb);
}

static bool netc_skb_has_inband_control_extension(const struct sk_buff *skb)
{
	return ntohs(eth_hdr(skb)->h_proto) == ETH_P_NETC_META;
}

static struct sk_buff *netc_rcv_meta_cmd(struct sk_buff *skb, u16 rx_header)
{
	u8 *buf = dsa_etype_header_pos_rx(skb) + NETC_HEADER_LEN;
	int switch_id = NETC_RX_HEADER_SWITCH_ID(rx_header);
	int source_port = NETC_RX_HEADER_PORT_ID(rx_header);
	struct netc_tagger_data *tagger_data;
	struct net_device *master = skb->dev;
	struct dsa_port *cpu_dp;
	struct dsa_switch *ds;

	cpu_dp = master->dsa_ptr;
	ds = dsa_switch_find(cpu_dp->dst->index, switch_id);
	if (!ds) {
		net_err_ratelimited("%s: cannot find switch id %d\n",
				    master->name, switch_id);
		return NULL;
	}

	tagger_data = netc_tagger_data(ds);
	if (!tagger_data->meta_cmd_handler)
		return NULL;

	if (skb_is_nonlinear(skb))
		if(skb_linearize(skb))
			return NULL;

	tagger_data->meta_cmd_handler(ds, source_port, buf,
				skb->len - NETC_HEADER_LEN - 2 * ETH_ALEN);

	/* Discard the meta frame */
	return NULL;
}

static struct sk_buff *netc_rcv_tx_timestap(struct sk_buff *skb, u16 rx_header)
{
	u8 *buf = dsa_etype_header_pos_rx(skb) + NETC_HEADER_LEN;
	int switch_id = NETC_RX_HEADER_SWITCH_ID(rx_header);
	int source_port = NETC_RX_HEADER_PORT_ID(rx_header);
	struct netc_tagger_data *tagger_data;
	struct net_device *master = skb->dev;
	struct dsa_port *cpu_dp;
	struct dsa_switch *ds;
	u32 ts_id;
	u64 tstamp;

	cpu_dp = master->dsa_ptr;

	ds = dsa_switch_find(cpu_dp->dst->index, switch_id);
	if (!ds) {
		net_err_ratelimited("%s: cannot find switch id %d\n",
				    master->name, switch_id);
		return NULL;
	}

	tagger_data = netc_tagger_data(ds);
	if (!tagger_data->meta_tstamp_handler)
		return NULL;


	tstamp = be64_to_cpu(*(__be64 *)buf);
	ts_id = be32_to_cpu(*(__be32 *)(buf + NETC_HEADER_TIMESTAMP_LEN));

	tagger_data->meta_tstamp_handler(ds, source_port, ts_id, tstamp);

	/* Discard the meta frame, we've consumed the timestamps it contained */
	return NULL;
}

static struct sk_buff *netc_rcv_inband_control_extension(struct sk_buff *skb,
							 int *source_port,
							 int *switch_id,
							 bool *host_only)
{
	u16 rx_header;
	int len = 0;

	if (unlikely(!pskb_may_pull(skb,
				    NETC_HEADER_LEN +
				    NETC_HEADER_TIMESTAMP_LEN +
				    NETC_RX_HEADER_TS_ID_LEN)))
		return NULL;

	rx_header = ntohs(*(__be16 *)skb->data);

	if (rx_header & NETC_RX_HEADER_HOST_ONLY)
		*host_only = true;

	if (rx_header & NETC_RX_HEADER_IS_METADATA)
		return netc_rcv_meta_cmd(skb, rx_header);

	if (rx_header & NETC_RX_HEADER_TX_TIMESTAP)
		return netc_rcv_tx_timestap(skb, rx_header);

	/* RX Timestamp frame */
	if (rx_header & NETC_RX_HEADER_RX_TIMESTAP) {
		u64 *tstamp = &NETC_SKB_CB(skb)->tstamp;
		u8 *buf = dsa_etype_header_pos_rx(skb) + NETC_HEADER_LEN;

		*tstamp = be64_to_cpu(*(__be64 *)buf);

		len += NETC_HEADER_TIMESTAMP_LEN;
	}

	*source_port = NETC_RX_HEADER_PORT_ID(rx_header);
	*switch_id = NETC_RX_HEADER_SWITCH_ID(rx_header);

	len += NETC_HEADER_LEN;

	/* Advance skb->data past the DSA header */
	skb_pull_rcsum(skb, len);

	dsa_strip_etype_header(skb, len);

	/* With skb->data in its final place, update the MAC header
	 * so that eth_hdr() continues to works properly.
	 */
	skb_set_mac_header(skb, -ETH_HLEN);

	return skb;
}

/* If the VLAN in the packet is a tag_8021q one, set @source_port and
 * @switch_id and strip the header. Otherwise set @vid and keep it in the
 * packet.
 */
static void netc_vlan_rcv(struct sk_buff *skb, int *source_port,
			     int *switch_id, int *vbid, u16 *vid)
{
	struct vlan_ethhdr *hdr = vlan_eth_hdr(skb);
	u16 vlan_tci;

	if (skb_vlan_tag_present(skb))
		vlan_tci = skb_vlan_tag_get(skb);
	else
		vlan_tci = ntohs(hdr->h_vlan_TCI);

	if (vid_is_dsa_8021q(vlan_tci & VLAN_VID_MASK))
		return dsa_8021q_rcv(skb, source_port, switch_id, vbid);

	/* Try our best with imprecise RX */
	*vid = vlan_tci & VLAN_VID_MASK;
}

static struct sk_buff *netc_rcv(struct sk_buff *skb,
				struct net_device *netdev)
{
	int src_port = -1, switch_id = -1, vbid = -1;
	bool host_only = false;
	u16 vid = 0;

	if (netc_skb_has_inband_control_extension(skb)) {
		skb = netc_rcv_inband_control_extension(skb, &src_port,
							&switch_id,
							&host_only);
		if (!skb)
			return NULL;
	}

	/* Packets with in-band control extensions might still have RX VLANs */
	if (likely(netc_skb_has_tag_8021q(skb)))
		netc_vlan_rcv(skb, &src_port, &switch_id, &vbid, &vid);

	if (vbid >= 1)
		skb->dev = dsa_tag_8021q_find_port_by_vbid(netdev, vbid);
	else if (src_port == -1 || switch_id == -1)
		skb->dev = dsa_find_designated_bridge_port_by_vid(netdev, vid);
	else
		skb->dev = dsa_master_find_slave(netdev, switch_id, src_port);
	if (!skb->dev) {
		/* netdev_warn(netdev, "Couldn't decode source port\n"); */
		return NULL;
	}

	if (!host_only)
		dsa_default_offload_fwd_mark(skb);

	return skb;
}

static void netc_disconnect(struct dsa_switch *ds)
{
	struct netc_tagger_data *tagger_data = ds->tagger_data;

	kfree(tagger_data);
	ds->tagger_data = NULL;
}

static int netc_connect(struct dsa_switch *ds)
{
	struct netc_tagger_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ds->tagger_data = data;

	return 0;
}

static const struct dsa_device_ops netc_netdev_ops = {
	.name			= NETC_8021Q_NAME,
	.proto			= DSA_TAG_PROTO_NETC,
	.xmit			= netc_xmit,
	.rcv			= netc_rcv,
	.connect		= netc_connect,
	.disconnect		= netc_disconnect,
	.needed_headroom	= VLAN_HLEN,
	.promisc_on_master	= true,
};

MODULE_LICENSE("GPL v2");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_NETC, NETC_8021Q_NAME);

module_dsa_tag_driver(netc_netdev_ops);
