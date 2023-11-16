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
#define ETH_P_NETC_META		0x0008

#define NETC_DEFAULT_VLAN	1

#define IFH_TAG_TYPE_C		0
#define IFH_TAG_TYPE_S		1

/* IEEE 802.3 Annex 57A: Slow Protocols PDUs (01:80:C2:xx:xx:xx) */
#define NETC_LINKLOCAL_FILTER_A		0x0180C2000000ull
#define NETC_LINKLOCAL_FILTER_A_MASK	0xFFFFFF000000ull

/* IEEE 1588 Annex F: Transport of PTP over Ethernet (01:1B:19:xx:xx:xx) */
#define NETC_LINKLOCAL_FILTER_B		0x011B19000000ull
#define NETC_LINKLOCAL_FILTER_B_MASK	0xFFFFFF000000ull

struct netc_deferred_xmit_work {
	struct dsa_port *dp;
	struct sk_buff *skb;
	struct kthread_work work;
};

struct netc_skb_cb {
	struct sk_buff *clone;
	u64 tstamp;
	u8 ts_id;
};

#define NETC_SKB_CB(skb) \
	((struct netc_skb_cb *)((skb)->cb))

struct netc_tagger_data {
	void (*xmit_work_fn)(struct kthread_work *work);
};

static inline struct netc_tagger_data *
netc_tagger_data(struct dsa_switch *ds)
{
	WARN_ON_ONCE(ds->dst->tag_ops->proto != DSA_TAG_PROTO_NETC);
	return ds->tagger_data;
}

#endif /* _NET_DSA_NETC_H */
