/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2019-2021 NXP
 */

#ifndef _NET_DSA_TAG_OCELOT_H
#define _NET_DSA_TAG_OCELOT_H

struct ocelot_skb_cb {
	u32 tstamp_lo;
};

#define OCELOT_SKB_CB(skb) \
	((struct ocelot_skb_cb *)DSA_SKB_CB_PRIV(skb))

#endif
