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

struct netc_tagger_private {
	struct netc_tagger_data data; /* Must be first */
	struct kthread_worker *xmit_worker;
};

/* Similar to is_link_local_ether_addr(hdr->h_dest) but also covers PTP */
static inline bool netc_is_link_local(const struct sk_buff *skb)
{
	const struct ethhdr *hdr = eth_hdr(skb);
	u64 dmac = ether_addr_to_u64(hdr->h_dest);

	if (ntohs(hdr->h_proto) == ETH_P_NETC_META)
		return false;

	if ((dmac & NETC_LINKLOCAL_FILTER_A_MASK) ==
		    NETC_LINKLOCAL_FILTER_A)
		return true;

	return false;
}

static struct sk_buff *netc_defer_xmit(struct dsa_port *dp,
				       struct sk_buff *skb)
{
	struct netc_tagger_private *priv = dp->ds->tagger_data;
	struct netc_tagger_data *data = &priv->data;
	void (*xmit_work_fn)(struct kthread_work *work);
	struct netc_deferred_xmit_work *xmit_work;
	struct kthread_worker *xmit_worker;

	xmit_work_fn = data->xmit_work_fn;
	xmit_worker = priv->xmit_worker;

	if (!xmit_work_fn || !xmit_worker)
		return NULL;

	/* PTP over IP packets need UDP checksumming. We may have inherited
	 * NETIF_F_HW_CSUM from the DSA master, but these packets are not sent
	 * through the DSA master, so calculate the checksum here.
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		return NULL;

	xmit_work = kzalloc(sizeof(*xmit_work), GFP_ATOMIC);
	if (!xmit_work)
		return NULL;

	/* Calls felix_port_deferred_xmit in felix.c */
	kthread_init_work(&xmit_work->work, xmit_work_fn);
	/* Increase refcount so the kfree_skb in dsa_slave_xmit
	 * won't really free the packet.
	 */
	xmit_work->dp = dp;
	xmit_work->skb = skb_get(skb);

	kthread_queue_work(xmit_worker, &xmit_work->work);

	return NULL;
}

static struct sk_buff *netc_xmit(struct sk_buff *skb,
				 struct net_device *netdev)
{
	struct dsa_port *dp = dsa_slave_to_port(netdev);
	u16 queue_mapping = skb_get_queue_mapping(skb);
	u8 pcp = netdev_txq_to_tc(netdev, queue_mapping);
	u16 tx_vid = dsa_tag_8021q_standalone_vid(dp);

	if (unlikely(netc_is_link_local(skb)))
		return netc_defer_xmit(dp, skb);

	return dsa_8021q_xmit(skb, netdev, ETH_P_8021Q,
			      ((pcp << VLAN_PRIO_SHIFT) | tx_vid));
}

static struct sk_buff *netc_rcv(struct sk_buff *skb,
				struct net_device *netdev)
{
	int src_port = -1, switch_id = -1, vid = -1;
	struct ethhdr *hdr;
	bool is_link_local;

	hdr = eth_hdr(skb);
	is_link_local = netc_is_link_local(skb);

	if (is_link_local) {
		/* Management traffic path. Switch embeds the switch ID and
		 * port ID into bytes of the destination MAC, courtesy of
		 * the incl_srcpt options.
		 */
		src_port = hdr->h_dest[3];
		switch_id = hdr->h_dest[4];
	}

	if (skb_vlan_tag_present(skb))
		/* Normal traffic path. */
		dsa_8021q_rcv(skb, &src_port, &switch_id, &vid);
	else
		return NULL;

	skb->dev = dsa_master_find_slave(netdev, switch_id, src_port);
	if (!skb->dev) {
		netdev_warn(netdev, "Couldn't decode source port switch-%d port- %d\n",
			    switch_id, src_port);
		return NULL;
	}

	if (!is_link_local)
		dsa_default_offload_fwd_mark(skb);

	return skb;
}

static void netc_disconnect(struct dsa_switch *ds)
{
	struct netc_tagger_private *priv = ds->tagger_data;

	kthread_destroy_worker(priv->xmit_worker);
	kfree(priv);
	ds->tagger_data = NULL;
}

static int netc_connect(struct dsa_switch *ds)
{
	struct netc_tagger_private *priv;
	int err;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->xmit_worker = kthread_create_worker(0, "netc_xmit");
	if (IS_ERR(priv->xmit_worker)) {
		err = PTR_ERR(priv->xmit_worker);
		kfree(priv);
		return err;
	}

	ds->tagger_data = priv;

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
