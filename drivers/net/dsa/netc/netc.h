// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#ifndef _NETC_H
#define _NETC_H

#include <linux/ptp_clock_kernel.h>
#include <linux/timecounter.h>
#include <linux/dsa/8021q.h>
#include <net/dsa.h>
#include <linux/mutex.h>
#include "netc_config.h"

struct netc_private;

enum {
	NETC_SPEED_AUTO,
	NETC_SPEED_10MBPS,
	NETC_SPEED_100MBPS,
	NETC_SPEED_1000MBPS,
	NETC_SPEED_2500MBPS,
	NETC_SPEED_MAX,
};

enum netc_internal_phy_t {
	NETC_NO_PHY = 0,
};

struct netc_info {
	const char *name;
	int device_id;
	int num_ports;
	enum dsa_tag_protocol tag_proto;
	int ptp_ts_bits;
	bool multiple_cascade_ports;
	bool can_limit_mcast_flood;
};

struct netc_private {
	const struct netc_info *info;
	struct netc_config config;
	int cpu_port;
	phy_interface_t phy_mode[NETC_MAX_NUM_PORTS];
	bool fixed_link[NETC_MAX_NUM_PORTS];
	unsigned long ucast_egress_floods;
	unsigned long bcast_egress_floods;
	unsigned long hwts_tx_en;

	size_t max_xfer_len;
	struct spi_device *spidev;
	struct dsa_switch *ds;
	u16 bridge_pvid[NETC_MAX_NUM_PORTS];
	u16 tag_8021q_pvid[NETC_MAX_NUM_PORTS];
	/* Serializes transmission of management frames so that
	 * the switch doesn't confuse them with one another.
	 */
	struct mutex mgmt_lock;

	struct devlink_region **regions;
};

int netc_vlan_filtering(struct dsa_switch *ds, int port, bool enabled,
			struct netlink_ext_ack *extack);
void netc_frame_memory_partitioning(struct netc_private *priv);

/* From netc_devlink.c */
int netc_devlink_setup(struct dsa_switch *ds);
void netc_devlink_teardown(struct dsa_switch *ds);
int netc_devlink_info_get(struct dsa_switch *ds,
			  struct devlink_info_req *req,
			  struct netlink_ext_ack *extack);

/* From netc_spi.c */
int netc_xfer_cmd(const struct netc_private *priv,
		  enum netc_spi_rw_mode rw, enum netc_cmd cmd,
		  void *param, size_t param_len,
		  void *resp, size_t resp_len);
int netc_xfer_set_cmd(const struct netc_private *priv,
		      enum netc_cmd cmd,
		      void *param, size_t param_len);
int netc_xfer_get_cmd(const struct netc_private *priv,
		      enum netc_cmd cmd, uint32_t id,
		      void *resp, size_t resp_len);

int netc_xfer_write_reg(const struct netc_private *priv,
			uint32_t reg, uint32_t value);
int netc_xfer_read_reg(const struct netc_private *priv,
		       uint32_t reg, uint32_t *value);

/* From netc_ethtool.c */
void netc_get_ethtool_stats(struct dsa_switch *ds, int port, uint64_t *data);
void netc_get_strings(struct dsa_switch *ds, int port,
		      uint32_t stringset, uint8_t *data);
int netc_get_sset_count(struct dsa_switch *ds, int port, int sset);

/* From netc_ptp.c */
void netc_ptp_txtstamp_skb(struct dsa_switch *ds, int port,
			   struct sk_buff *skb);

#endif /* _NETC_H */
