// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#ifndef _NETC_CONFIG_H
#define _NETC_CONFIG_H

#include <linux/types.h>
#include <asm/types.h>

#define NETC_RT1180_DEVICE_ID		0xe001
#define NETC_NUM_PORTS			5
#define NETC_MAX_NUM_PORTS		NETC_NUM_PORTS
#define NETC_NUM_TC			8

#define NETC_ETHTOOL_STATS_NUM_MAX	120

#define NETC_SPI_WORD_BITS		8
#define NETC_SPI_MSG_WORD_BYTES		4
#define NETC_SPI_MSG_HEADER_SIZE	16
#define NETC_SPI_MSG_PARAM_SIZE		12
#define NETC_SPI_MSG_MAXLEN		4096
#define NETC_SPI_MSG_RESPONSE_TIME	1000 /* us */

#define NETC_CMD_DIR_SHIFT 31
#define NETC_CMD_LEN_SHIFT 16

enum  netc_spi_rw_mode {
	SPI_READ = 0,
	SPI_WRITE = 1,
};

struct netc_cmd_hdr {
	uint32_t cmd;
	uint8_t param[NETC_SPI_MSG_PARAM_SIZE];
};

/* Command */
enum netc_cmd {
	/* port related command */
	NETC_CMD_SYS_INFO_GET = 0x1,
	NETC_CMD_PORT_DSA_ADD,
	NETC_CMD_PORT_DSA_DEL,
	NETC_CMD_PORT_MTU_SET,
	NETC_CMD_PORT_MTU_GET,
	NETC_CMD_PORT_PHYLINK_MODE_SET,
	NETC_CMD_PORT_PHYLINK_STATUS_GET,
	NETC_CMD_PORT_ETHTOOL_STATS_GET,
	NETC_CMD_PORT_PVID_SET,
	NETC_CMD_PORT_LINK_SET,
	NETC_CMD_PORT_DROPUNTAG_SET,

	NETC_CMD_FDB_ADD = 0x1000,
	NETC_CMD_FDB_DEL,
	NETC_CMD_FDB_DUMP,
	NETC_CMD_VLAN_ADD,
	NETC_CMD_VLAN_DEL,
	NETC_CMD_VLAN_DUMP,
	NETC_CMD_FORWARD_MASK_SET,

	NETC_CMD_PTP_SYNC_SET = 0x2000,
	NETC_CMD_TIMER_CUR_SET,
	NETC_CMD_TIMER_CUR_GET,
	NETC_CMD_TIMER_RATE_SET,
	NETC_CMD_TIMER_RATE_GET,
	NETC_CMD_TIMER_ADJTIME_SET,
	NETC_CMD_TIMER_ADJFINE_SET,
	NETC_CMD_TIMER_PPS_START,
	NETC_CMD_TIMER_PPS_STOP,
	NETC_CMD_TIMER_EXTTS_START,
	NETC_CMD_TIMER_EXTTS_STOP,

	NETC_CMD_QBV_SET = 0x3000,
	NETC_CMD_QBV_GET,
	NETC_CMD_QBU_SET,
	NETC_CMD_QBU_GET,
	NETC_CMD_QCI_SET,
	NETC_CMD_QCI_GET,
	NETC_CMD_8021CB_SET,
	NETC_CMD_8021CB_GET,

	NETC_CMD_REG_SET = 0x4000,
	NETC_CMD_REG_GET,
	NETC_CMD_MAX_NUM,
};

struct netc_cmd_sysinfo {
	uint16_t device_id;
	uint16_t vendor_id;
	uint8_t  version_major;
	uint8_t  version_minor;
	uint8_t  version_revision;
	uint8_t  cpu_port;
};

/* command data for NETC_CMD_PORT_DSA_ADD */
struct netc_cmd_port_dsa_add {
	uint8_t cpu_port; /* switch port 0, 1, 2 or 3 */
	uint8_t slave_port; /* switch port 0, 1, 2 or 3 */
	uint8_t mac_addr[ETH_ALEN]; /* MAC address of master interface */
};

/* command data for NETC_CMD_PORT_DSA_DEL */
struct netc_cmd_port_dsa_del {
	uint8_t slave_port; /* switch port 0, 1, 2 or 3 */
	uint8_t reserved[3];
};

/* command data for NETC_CMD_PORT_MTU_SET */
struct netc_cmd_port_mtu {
	uint8_t port;  /* switch port 0, 1, 2 or 3 */
	uint8_t reserved;
	uint16_t mtu;
};

/* command data for NETC_CMD_PORT_PHYLINK_MODE_SET */
struct netc_cmd_port_phylink_mode {
	uint8_t port;  /* switch port 0, 1, 2 or 3 */
	bool duplex;   /* 0: half duplex; 1: full duplex */
	uint16_t speed;   /* 10: 10Mbps ; 100: 100Mbps ; 1000: 1000Mbps */
};

/* command data for NETC_CMD_PORT_PVID_SET */
struct netc_cmd_port_pvid {
	uint8_t port; /* switch port 0, 1, 2 or 3 */
	uint8_t reserved;
	uint16_t pvid;
};

/* command data for netc_cmd_port_link */
struct netc_cmd_port_link {
	uint8_t port; /* switch port 0, 1, 2 or 3 */
	bool link; /* 0: down; 1: up */
	uint8_t reserved[2];
};

/* command data for netc_cmd_port_dropuntag */
struct netc_cmd_port_dropuntag {
	uint8_t port; /* switch port 0, 1, 2 or 3 */
	uint8_t reserved;
	uint16_t drop;
};

/* command data for NETC_CMD_FDB_ADD */
struct netc_cmd_fdb {
	uint8_t mac_addr[ETH_ALEN];
	uint16_t vid;
	uint8_t port;  /* switch port 0, 1, 2 or 3 */
	uint8_t reserved[3];
};

/* command data for NETC_CMD_FDB_DEL */
struct netc_cmd_fdb_del {
	uint8_t mac_addr[ETH_ALEN];
	uint16_t vid;
};

/* command data for NETC_CMD_VLAN_ADD */
struct netc_cmd_vlan {
	uint16_t vid;
	uint8_t port;  /* switch port 0, 1, 2 or 3 */
	bool untagged;
};

/* data returned for NETC_CMD_PORT_PHYLINK_STATUS_GET */
struct netc_cmd_port_phylink_status {
	uint8_t port;  /* switch port 0, 1, 2 or 3 */
	bool link;
	uint16_t speed;
	bool duplex; /* 0: down; 1: up */
	uint8_t reserved[3];
};

/* command param */
struct netc_cmd_read_param {
	uint32_t id;
};

/* command data for NETC_CMD_REG_SET */
struct netc_cmd_reg_cmd {
	uint32_t reg;
	uint32_t value;
};

/* data returned for NETC_CMD_FDB_DUMP */
struct netc_cmd_fdb_dump {
	uint8_t mac_addr[ETH_ALEN];
	uint16_t vid;
	/* bit 0: switch port 0 etc. */
	uint32_t port_map;
	bool dynamic;
	uint8_t reserved[3];
	/* non-zero means there are remaining entries, 0 means no more entries */
	uint32_t resume_entry_id;
};

/* data returned for NETC_CMD_VLAN_DUMP */
struct netc_cmd_vlan_dump {
	uint16_t vid;
	bool untagged;
	uint8_t reserved;
	/* bit 0: switch port 0 etc. */
	uint32_t port_map;
	/* non-zero means there are remaining entries, 0 means no more entries */
	uint32_t resume_entry_id;
};

/* command param for NETC_CMD_TIMER_PPS_START */
struct netc_cmd_timer_pps {
	uint64_t pin_start;
	uint32_t pin_duration32;
};

struct netc_cmd_port_ethtool_stats {
	uint64_t values[NETC_ETHTOOL_STATS_NUM_MAX];
};

struct netc_mac_config {
	uint8_t port;
	uint16_t speed;
	uint16_t vlanid;
	bool link;
	bool egress;
	bool ingress;
	bool duplex;
	bool drptag;
	bool drpuntag;
	bool retag;
};

struct netc_fdb_entry {
	uint8_t mac_addr[ETH_ALEN];
	uint16_t vid;
	uint32_t port_map; /* bit 0: switch port 0 etc. */
	bool dynamic;
};

struct netc_vlan_entry {
	uint16_t vid;
	uint16_t port;
	uint32_t port_map;
	uint32_t tag_ports;
	uint32_t entry_id;
};

struct netc_config {
	uint16_t device_id;
	uint16_t vendor_id;
	uint8_t  version_major;
	uint8_t  version_minor;
	uint8_t  version_revision;
	uint8_t  cpu_port_mode;
	uint16_t tpid;
	uint16_t tpid2;
	struct netc_mac_config mac[NETC_MAX_NUM_PORTS];
	int cpu_port;
	int vlan_count;
	int vlan_max_count;
	struct netc_vlan_entry *vlan;
};

struct netc_private;

int netc_get_devinfo(struct netc_private *priv, struct netc_config *config);

int netc_port_phylink_mode_set(struct netc_private *priv,
			       struct netc_mac_config *mac);
int netc_port_phylink_stats_get(struct netc_private *priv,
				struct netc_mac_config *mac);
int netc_port_pvid_set(struct netc_private *priv, int port, uint16_t pvid);
int netc_port_link_set(struct netc_private *priv, int port, bool up);
int netc_port_dropuntag_set(struct netc_private *priv, int port, bool drop);

int netc_port_mtu_set(struct netc_private *priv, int port, int mtu);
int netc_port_mtu_get(struct netc_private *priv, int port, int *mtu);

int netc_port_pvid_set(struct netc_private *priv, int port, uint16_t pvid);

int netc_port_dsa_add(struct netc_private *priv, int cpu_port,
		      int slave_port, const unsigned char *mac_addr);
int netc_port_dsa_del(struct netc_private *priv, int slave_port);

int netc_fdb_entry_add(struct netc_private *priv,
		       const unsigned char *mac_addr,
		       uint16_t vid, int port);
int netc_fdb_entry_del(struct netc_private *priv,
		       const unsigned char *mac_addr,
		       uint16_t vid);
int netc_fdb_entry_get(struct netc_private *priv,
		       struct netc_fdb_entry *fdb,
		       uint32_t entry_id, uint32_t *next_id);

int netc_vlan_entry_add(struct netc_private *priv,
			uint16_t vid, int port, bool untagged);
int netc_vlan_entry_del(struct netc_private *priv, uint16_t vid, int port);
int netc_vlan_entry_get(struct netc_private *priv,
			struct netc_vlan_entry *vlan,
			uint32_t entry_id, uint32_t *next_id);

int netc_config_setup(struct netc_config *config);
void netc_config_free(struct netc_config *config);

#endif /* _NETC_CONFIG_H */
