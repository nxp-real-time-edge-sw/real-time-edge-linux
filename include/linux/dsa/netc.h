// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#ifndef _NET_DSA_NETC_H
#define _NET_DSA_NETC_H

#include <linux/kthread.h>
#include <linux/skbuff.h>
#include <linux/dsa/8021q.h>
#include <net/dsa.h>

#define ETH_P_NETC		0x88A8
#define ETH_P_NETC_META		0xDADC
#define ETH_P_NETC_8021Q	ETH_P_8021Q

#define NETC_DEFAULT_VLAN	1

#define IFH_TAG_TYPE_C		0
#define IFH_TAG_TYPE_S		1

/* IEEE 802.3 Annex 57A: Slow Protocols PDUs (01:80:C2:xx:xx:xx) */
#define NETC_LINKLOCAL_FILTER_A		0x0180C2000000ull
#define NETC_LINKLOCAL_FILTER_A_MASK	0xFFFFFF000000ull
/* IEEE 1588 Annex F: Transport of PTP over Ethernet (01:1B:19:xx:xx:xx) */
#define NETC_LINKLOCAL_FILTER_B		0x011B19000000ull
#define NETC_LINKLOCAL_FILTER_B_MASK	0xFFFFFF000000ull

/* Source and Destination MAC of follow-up meta frames.
 * Whereas the choice of SMAC only affects the unique identification of the
 * switch as sender of meta frames, the DMAC must be an address that is present
 * in the DSA master port's multicast MAC filter.
 * 01-80-C2-00-00-0E is a good choice for this, as all profiles of IEEE 1588
 * over L2 use this address for some purpose already.
 */
#define NETC_META_SMAC			0x222222222222ull
#define NETC_META_DMAC			0x0180C200000Eull

struct netc_deferred_xmit_work {
	struct dsa_port *dp;
	struct sk_buff *skb;
	struct kthread_work work;
};

struct netc_skb_cb {
	struct sk_buff *clone;
	u64 tstamp;
	u32 ts_id;
};

#define NETC_SKB_CB(skb) \
	((struct netc_skb_cb *)((skb)->cb))

struct netc_tagger_data {
	void (*meta_tstamp_handler)(struct dsa_switch *ds, int port,
				    u32 ts_id, u64 tstamp);
	void (*meta_cmd_handler)(struct dsa_switch *ds, int port,
				 void *buf, size_t len);
};

static inline struct netc_tagger_data *
netc_tagger_data(struct dsa_switch *ds)
{
	WARN_ON_ONCE(ds->dst->tag_ops->proto != DSA_TAG_PROTO_NETC);
	return ds->tagger_data;
}

#endif /* _NET_DSA_NETC_H */
