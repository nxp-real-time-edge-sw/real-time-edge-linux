// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 */

#include "netc.h"

enum netc_stat_index {
	/* RX stats */
	NETC_STAT_RX_BYTES,
	NETC_STAT_RX_VALID_BYTES,
	NETC_STAT_RX_PAUSE_FRAMES,
	NETC_STAT_RX_VALID_FRAMES,
	NETC_STAT_RX_VLAN_FRAMES,
	NETC_STAT_RX_UC_FRAMES,
	NETC_STAT_RX_MC_FRAMES,
	NETC_STAT_RX_BC_FRAMES,
	NETC_STAT_RX_FRAMES,
	NETC_STAT_RX_MIN_FRAMES,
	NETC_STAT_RX_64_FRAMES,
	NETC_STAT_RX_65_127_FRAMES,
	NETC_STAT_RX_128_255_FRAMES,
	NETC_STAT_RX_256_511_FRAMES,
	NETC_STAT_RX_512_1023_FRAMES,
	NETC_STAT_RX_1024_1526_FRAMES,
	NETC_STAT_RX_1527_MAX_FRAMES,
	NETC_STAT_RX_CONTROL_FRAMES,

	/* TX stats */
	NETC_STAT_TX_BYTES,
	NETC_STAT_TX_VALID_BYTES,
	NETC_STAT_TX_PAUSE_FRAMES,
	NETC_STAT_TX_VALID_FRAMES,
	NETC_STAT_TX_VLAN_FRAMES,
	NETC_STAT_TX_UC_FRAMES,
	NETC_STAT_TX_MC_FRAMES,
	NETC_STAT_TX_BC_FRAMES,
	NETC_STAT_TX_FRAMES,
	NETC_STAT_TX_MIN_FRAMES,
	NETC_STAT_TX_64_FRAMES,
	NETC_STAT_TX_65_127_FRAMES,
	NETC_STAT_TX_128_255_FRAMES,
	NETC_STAT_TX_256_511_FRAMES,
	NETC_STAT_TX_512_1023_FRAMES,
	NETC_STAT_TX_1024_1526_FRAMES,
	NETC_STAT_TX_1527_MAX_FRAMES,
	NETC_STAT_TX_CONTROL_FRAMES,

	NETC_STAT_RX_VALID_REASSEMBLED_FRAMES,
	NETC_STAT_RX_ADDITIONAL_MPACKETS,
	NETC_STAT_RX_ERROR_FRAME_REASSEMBLY,
	NETC_STAT_RX_ERROR_FRAME_SMD,
	NETC_STAT_TX_ADDITIONAL_MPACKETS,
	NETC_STAT_TX_HOLD_TRANSITIONS,

	/* Error stats */
	NETC_STAT_RX_ERROR,
	NETC_STAT_RX_ERROR_UNDERSIZE,
	NETC_STAT_RX_ERROR_OVERSIZE,
	NETC_STAT_RX_ERROR_FCS,
	NETC_STAT_RX_ERROR_FRAGMENT,
	NETC_STAT_RX_ERROR_JABBER,
	NETC_STAT_RX_ERROR_DISCARD,
	NETC_STAT_RX_ERROR_NO_TRUNCATED,
	NETC_STAT_TX_ERROR_FCS,
	NETC_STAT_TX_ERROR_UNDERSIZE,

	/* Discard stats */
	NETC_STAT_RX_DISCARD_COUNT,
	NETC_STAT_RX_DISCARD_REASON0,
	NETC_STAT_RX_DISCARD_TABLE_ID,
	NETC_STAT_RX_DISCARD_ENTRY_ID,
	NETC_STAT_TX_DISCARD_COUNT,
	NETC_STAT_TX_DISCARD_REASON0,
	NETC_STAT_TX_DISCARD_TABLE_ID,
	NETC_STAT_TX_DISCARD_ENTRY_ID,
	NETC_STAT_BRIDGE_DISCARD_COUNT,
	NETC_STAT_BRIDGE_DISCARD_REASON0,
	NETC_STAT_BRIDGE_DISCARD_TABLE_ID,
	NETC_STAT_BRIDGE_DISCARD_ENTRY_ID,

	/* Q0 stats */
	NETC_STAT_Q0_REJECTED_BYTES,
	NETC_STAT_Q0_REJECTED_FRAMES,
	NETC_STAT_Q0_DEQUEUE_BYTES,
	NETC_STAT_Q0_DEQUEUE_FRAMES,
	NETC_STAT_Q0_DROPPED_BYTES,
	NETC_STAT_Q0_DROPPED_FRAMES,
	NETC_STAT_Q0_FRAMES,

	/* Q1 stats */
	NETC_STAT_Q1_REJECTED_BYTES,
	NETC_STAT_Q1_REJECTED_FRAMES,
	NETC_STAT_Q1_DEQUEUE_BYTES,
	NETC_STAT_Q1_DEQUEUE_FRAMES,
	NETC_STAT_Q1_DROPPED_BYTES,
	NETC_STAT_Q1_DROPPED_FRAMES,
	NETC_STAT_Q1_FRAMES,

	/* Q2 stats */
	NETC_STAT_Q2_REJECTED_BYTES,
	NETC_STAT_Q2_REJECTED_FRAMES,
	NETC_STAT_Q2_DEQUEUE_BYTES,
	NETC_STAT_Q2_DEQUEUE_FRAMES,
	NETC_STAT_Q2_DROPPED_BYTES,
	NETC_STAT_Q2_DROPPED_FRAMES,
	NETC_STAT_Q2_FRAMES,

	/* Q3 stats */
	NETC_STAT_Q3_REJECTED_BYTES,
	NETC_STAT_Q3_REJECTED_FRAMES,
	NETC_STAT_Q3_DEQUEUE_BYTES,
	NETC_STAT_Q3_DEQUEUE_FRAMES,
	NETC_STAT_Q3_DROPPED_BYTES,
	NETC_STAT_Q3_DROPPED_FRAMES,
	NETC_STAT_Q3_FRAMES,

	/* Q4 stats */
	NETC_STAT_Q4_REJECTED_BYTES,
	NETC_STAT_Q4_REJECTED_FRAMES,
	NETC_STAT_Q4_DEQUEUE_BYTES,
	NETC_STAT_Q4_DEQUEUE_FRAMES,
	NETC_STAT_Q4_DROPPED_BYTES,
	NETC_STAT_Q4_DROPPED_FRAMES,
	NETC_STAT_Q4_FRAMES,

	/* Q5 stats */
	NETC_STAT_Q5_REJECTED_BYTES,
	NETC_STAT_Q5_REJECTED_FRAMES,
	NETC_STAT_Q5_DEQUEUE_BYTES,
	NETC_STAT_Q5_DEQUEUE_FRAMES,
	NETC_STAT_Q5_DROPPED_BYTES,
	NETC_STAT_Q5_DROPPED_FRAMES,
	NETC_STAT_Q5_FRAMES,

	/* Q6 stats */
	NETC_STAT_Q6_REJECTED_BYTES,
	NETC_STAT_Q6_REJECTED_FRAMES,
	NETC_STAT_Q6_DEQUEUE_BYTES,
	NETC_STAT_Q6_DEQUEUE_FRAMES,
	NETC_STAT_Q6_DROPPED_BYTES,
	NETC_STAT_Q6_DROPPED_FRAMES,
	NETC_STAT_Q6_FRAMES,

	/* Q7 stats */
	NETC_STAT_Q7_REJECTED_BYTES,
	NETC_STAT_Q7_REJECTED_FRAMES,
	NETC_STAT_Q7_DEQUEUE_BYTES,
	NETC_STAT_Q7_DEQUEUE_FRAMES,
	NETC_STAT_Q7_DROPPED_BYTES,
	NETC_STAT_Q7_DROPPED_FRAMES,
	NETC_STAT_Q7_FRAMES,
	NETC_STAT_NUM,
};

char netc_stat_name[][ETH_GSTRING_LEN] = {
	/* RX stats */
	[NETC_STAT_RX_BYTES] = "in-bytes",
	[NETC_STAT_RX_VALID_BYTES] = "in-valid-bytes",
	[NETC_STAT_RX_PAUSE_FRAMES] = "in-pause-frames",
	[NETC_STAT_RX_VALID_FRAMES] = "in-vlan-frames",
	[NETC_STAT_RX_VLAN_FRAMES] = "in-vlan-frames",
	[NETC_STAT_RX_UC_FRAMES] = "in-uc-frames",
	[NETC_STAT_RX_MC_FRAMES] = "in-mc-frames",
	[NETC_STAT_RX_BC_FRAMES] = "in-bc-frames",
	[NETC_STAT_RX_FRAMES] = "in-frames",
	[NETC_STAT_RX_MIN_FRAMES] = "in-min-frames",
	[NETC_STAT_RX_64_FRAMES] = "in-64-frames",
	[NETC_STAT_RX_65_127_FRAMES] = "in-65-127-frames",
	[NETC_STAT_RX_128_255_FRAMES] = "in-128-255-frames",
	[NETC_STAT_RX_256_511_FRAMES] = "in-256-511-frames",
	[NETC_STAT_RX_512_1023_FRAMES] = "in-512-1023-frames",
	[NETC_STAT_RX_1024_1526_FRAMES] = "in-1024-1522-frames",
	[NETC_STAT_RX_1527_MAX_FRAMES] = "in-1523-max-frames",
	[NETC_STAT_RX_CONTROL_FRAMES] = "in-control-frames",

	/* TX stats */
	[NETC_STAT_TX_BYTES] = "out-bytes",
	[NETC_STAT_TX_VALID_BYTES] = "out-valid-bytes",
	[NETC_STAT_TX_PAUSE_FRAMES] = "out-pause-frames",
	[NETC_STAT_TX_VALID_FRAMES] = "out-valid-frames",
	[NETC_STAT_TX_VLAN_FRAMES] = "out-vlan-frames",
	[NETC_STAT_TX_UC_FRAMES] = "out-uc-frames",
	[NETC_STAT_TX_MC_FRAMES] = "out-mc-frames",
	[NETC_STAT_TX_BC_FRAMES] = "out-bc-frames",
	[NETC_STAT_TX_FRAMES] = "out-frames",
	[NETC_STAT_TX_MIN_FRAMES] = "out-min-frames",
	[NETC_STAT_TX_64_FRAMES] = "out-64-frames",
	[NETC_STAT_TX_65_127_FRAMES] = "out-65-127-frames",
	[NETC_STAT_TX_128_255_FRAMES] = "out-128-255-frames",
	[NETC_STAT_TX_256_511_FRAMES] = "out-256-511-frames",
	[NETC_STAT_TX_512_1023_FRAMES] = "out-512-1023-frames",
	[NETC_STAT_TX_1024_1526_FRAMES] = "out-1024-1522-frames",
	[NETC_STAT_TX_1527_MAX_FRAMES] = "out-1523-max-frames",
	[NETC_STAT_TX_CONTROL_FRAMES] = "out-control-frames",

	[NETC_STAT_RX_VALID_REASSEMBLED_FRAMES] = "in-valid-reassembled-frames",
	[NETC_STAT_RX_ADDITIONAL_MPACKETS] = "in-additional-mPackets",
	[NETC_STAT_RX_ERROR_FRAME_REASSEMBLY] = "in-error-frame-reassembly",
	[NETC_STAT_RX_ERROR_FRAME_SMD] = "in-error-frame-smd",
	[NETC_STAT_TX_ADDITIONAL_MPACKETS] = "out-additional-mPackets",
	[NETC_STAT_TX_HOLD_TRANSITIONS] = "out-hold-transitions",

	/* Error stats */
	[NETC_STAT_RX_ERROR] = "in-error",
	[NETC_STAT_RX_ERROR_UNDERSIZE] = "in-error-undersize",
	[NETC_STAT_RX_ERROR_OVERSIZE] = "in-error-oversize",
	[NETC_STAT_RX_ERROR_FCS] = "in-error-fcs",
	[NETC_STAT_RX_ERROR_FRAGMENT] = "in-error-fragment",
	[NETC_STAT_RX_ERROR_JABBER] = "in-error-jabber",
	[NETC_STAT_RX_ERROR_DISCARD] = "in-error-discard",
	[NETC_STAT_RX_ERROR_NO_TRUNCATED] = "in-error-dicard-no-truncated",
	[NETC_STAT_TX_ERROR_FCS] = "out-error-fcs",
	[NETC_STAT_TX_ERROR_UNDERSIZE] = "out-error-undersize",

	/* Discard stats */
	[NETC_STAT_RX_DISCARD_COUNT] = "in-discard-count",
	[NETC_STAT_RX_DISCARD_REASON0] = "in-discard-reason0",
	[NETC_STAT_RX_DISCARD_TABLE_ID] = "in-discard-table-id",
	[NETC_STAT_RX_DISCARD_ENTRY_ID] = "in-discard-entry-id",
	[NETC_STAT_TX_DISCARD_COUNT] = "out-discard-count",
	[NETC_STAT_TX_DISCARD_REASON0] = "out-discard-reason0",
	[NETC_STAT_TX_DISCARD_TABLE_ID] = "out-discard-table-id",
	[NETC_STAT_TX_DISCARD_ENTRY_ID] = "out-discard-entry-id",
	[NETC_STAT_BRIDGE_DISCARD_COUNT] = "bridge-discard-count",
	[NETC_STAT_BRIDGE_DISCARD_REASON0] = "bridge-discard-reason0",
	[NETC_STAT_BRIDGE_DISCARD_TABLE_ID] = "bridge-discard-table-id",
	[NETC_STAT_BRIDGE_DISCARD_ENTRY_ID] = "bridge-discard-entry-id",

	/* Q0 stats */
	[NETC_STAT_Q0_REJECTED_BYTES] = "q0-rejected-bytes",
	[NETC_STAT_Q0_REJECTED_FRAMES] = "q0-rejected-frames",
	[NETC_STAT_Q0_DEQUEUE_BYTES] = "q0-dequeue-bytes",
	[NETC_STAT_Q0_DEQUEUE_FRAMES] = "q0-dequeue-frames",
	[NETC_STAT_Q0_DROPPED_BYTES] = "q0-dropped-bytes",
	[NETC_STAT_Q0_DROPPED_FRAMES] = "q0-dropped-frames",
	[NETC_STAT_Q0_FRAMES] = "q0-frames",

	/* Q1 stats */
	[NETC_STAT_Q1_REJECTED_BYTES] = "q1-rejected-bytes",
	[NETC_STAT_Q1_REJECTED_FRAMES] = "q1-rejected-frames",
	[NETC_STAT_Q1_DEQUEUE_BYTES] = "q1-dequeue-bytes",
	[NETC_STAT_Q1_DEQUEUE_FRAMES] = "q1-dequeue-frames",
	[NETC_STAT_Q1_DROPPED_BYTES] = "q1-dropped-bytes",
	[NETC_STAT_Q1_DROPPED_FRAMES] = "q1-dropped-frames",
	[NETC_STAT_Q1_FRAMES] = "q1-frames",

	/* Q2 stats */
	[NETC_STAT_Q2_REJECTED_BYTES] = "q2-rejected-bytes",
	[NETC_STAT_Q2_REJECTED_FRAMES] = "q2-rejected-frames",
	[NETC_STAT_Q2_DEQUEUE_BYTES] = "q2-dequeue-bytes",
	[NETC_STAT_Q2_DEQUEUE_FRAMES] = "q2-dequeue-frames",
	[NETC_STAT_Q2_DROPPED_BYTES] = "q2-dropped-bytes",
	[NETC_STAT_Q2_DROPPED_FRAMES] = "q2-dropped-frames",
	[NETC_STAT_Q2_FRAMES] = "q2-frames",

	/* Q3 stats */
	[NETC_STAT_Q3_REJECTED_BYTES] = "q3-rejected-bytes",
	[NETC_STAT_Q3_REJECTED_FRAMES] = "q3-rejected-frames",
	[NETC_STAT_Q3_DEQUEUE_BYTES] = "q3-dequeue-bytes",
	[NETC_STAT_Q3_DEQUEUE_FRAMES] = "q3-dequeue-frames",
	[NETC_STAT_Q3_DROPPED_BYTES] = "q3-dropped-bytes",
	[NETC_STAT_Q3_DROPPED_FRAMES] = "q3-dropped-frames",
	[NETC_STAT_Q3_FRAMES] = "q3-frames",

	/* Q4 stats */
	[NETC_STAT_Q4_REJECTED_BYTES] = "q4-rejected-bytes",
	[NETC_STAT_Q4_REJECTED_FRAMES] = "q4-rejected-frames",
	[NETC_STAT_Q4_DEQUEUE_BYTES] = "q4-dequeue-bytes",
	[NETC_STAT_Q4_DEQUEUE_FRAMES] = "q4-dequeue-frames",
	[NETC_STAT_Q4_DROPPED_BYTES] = "q4-dropped-bytes",
	[NETC_STAT_Q4_DROPPED_FRAMES] = "q4-dropped-frames",
	[NETC_STAT_Q4_FRAMES] = "q4-frames",

	/* Q5 stats */
	[NETC_STAT_Q5_REJECTED_BYTES] = "q5-rejected-bytes",
	[NETC_STAT_Q5_REJECTED_FRAMES] = "q5-rejected-frames",
	[NETC_STAT_Q5_DEQUEUE_BYTES] = "q5-dequeue-bytes",
	[NETC_STAT_Q5_DEQUEUE_FRAMES] = "q5-dequeue-frames",
	[NETC_STAT_Q5_DROPPED_BYTES] = "q5-dropped-bytes",
	[NETC_STAT_Q5_DROPPED_FRAMES] = "q5-dropped-frames",
	[NETC_STAT_Q5_FRAMES] = "q5-frames",

	/* Q6 stats */
	[NETC_STAT_Q6_REJECTED_BYTES] = "q6-rejected-bytes",
	[NETC_STAT_Q6_REJECTED_FRAMES] = "q6-rejected-frames",
	[NETC_STAT_Q6_DEQUEUE_BYTES] = "q6-dequeue-bytes",
	[NETC_STAT_Q6_DEQUEUE_FRAMES] = "q6-dequeue-frames",
	[NETC_STAT_Q6_DROPPED_BYTES] = "q6-dropped-bytes",
	[NETC_STAT_Q6_DROPPED_FRAMES] = "q6-dropped-frames",
	[NETC_STAT_Q6_FRAMES] = "q6-frames",

	/* Q7 stats */
	[NETC_STAT_Q7_REJECTED_BYTES] = "q7-rejected-bytes",
	[NETC_STAT_Q7_REJECTED_FRAMES] = "q7-rejected-frames",
	[NETC_STAT_Q7_DEQUEUE_BYTES] = "q7-dequeue-bytes",
	[NETC_STAT_Q7_DEQUEUE_FRAMES] = "q7-dequeue-frames",
	[NETC_STAT_Q7_DROPPED_BYTES] = "q7-dropped-bytes",
	[NETC_STAT_Q7_DROPPED_FRAMES] = "q7-dropped-frames",
	[NETC_STAT_Q7_FRAMES] = "q7-frames",
};

void netc_get_ethtool_stats(struct dsa_switch *ds, int port, u64 *data)
{
	struct netc_private *priv = ds->priv;
	struct netc_cmd_port_ethtool_stats stats;
	int rc;
	enum netc_stat_index i;

	rc = netc_xfer_get_cmd(priv, NETC_CMD_PORT_ETHTOOL_STATS_GET,
			       port, &stats, sizeof(stats));

	if (rc) {
		dev_err(ds->dev,
			"Failed to get port %d stats\n", port);
		return;
	}

	for (i = 0; i < NETC_STAT_NUM; i++)
		data[i] = stats.values[i];
}

void netc_get_strings(struct dsa_switch *ds, int port,
		      u32 stringset, u8 *data)
{
	enum netc_stat_index i;
	char *p = data;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < NETC_STAT_NUM; i++) {
		strscpy(p, netc_stat_name[i], ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
	}
}

int netc_get_sset_count(struct dsa_switch *ds, int port, int sset)
{
	if (sset != ETH_SS_STATS)
		return -EOPNOTSUPP;

	return NETC_STAT_NUM;
}
