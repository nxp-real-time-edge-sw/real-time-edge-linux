// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2024 NXP
 */

#ifndef _NETC_PTP_H
#define _NETC_PTP_H

#include <linux/timer.h>

#if IS_ENABLED(CONFIG_NET_DSA_NETC_PTP)

struct netc_ptp_data {
	struct timer_list extts_timer;
	/* Used on NETC where meta frames are generated only for
	 * 2-step TX timestamps
	 */
	struct sk_buff_head skb_txtstamp_queue;
	struct ptp_clock *clock;
	struct ptp_clock_info caps;
	/* Serializes all operations on the PTP hardware clock */
	struct mutex lock;
	bool extts_enabled;
	u64 ptpsyncts;
};

int netc_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr);

int netc_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr);

void netc_process_meta_tstamp(struct dsa_switch *ds, int port,
			      u32 ts_id, u64 tstamp);

int netc_get_ts_info(struct dsa_switch *ds, int port,
			struct ethtool_ts_info *ts);

bool netc_port_rxtstamp(struct dsa_switch *ds, int port,
			   struct sk_buff *skb, unsigned int type);

void netc_port_txtstamp(struct dsa_switch *ds, int port,
			   struct sk_buff *skb);

int netc_ptp_clock_register(struct dsa_switch *ds);

void netc_ptp_clock_unregister(struct dsa_switch *ds);


#else

struct netc_ptp_data {
	struct mutex lock;
};

static inline int netc_ptp_clock_register(struct dsa_switch *ds)
{
	return 0;
}

static inline void netc_ptp_clock_unregister(struct dsa_switch *ds)
{
}

#define netc_get_ts_info NULL

#define netc_port_rxtstamp NULL

#define netc_port_txtstamp NULL

#define netc_hwtstamp_get NULL

#define netc_hwtstamp_set NULL

#define netc_process_meta_tstamp NULL

#endif /* IS_ENABLED(CONFIG_NET_DSA_NETC_PTP) */

#endif /* _NETC_PTP_H */
