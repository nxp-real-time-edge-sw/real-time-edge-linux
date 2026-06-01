/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright 2025 NXP
 */

#ifndef __NETC_FM_H
#define __NETC_FM_H

#include <linux/bitops.h>
#include <linux/ioctl.h>

struct fm_filter {
	__u16 ethertype;
	__u16 rev1;
};

/* this is the structure of the argument of the IOCTL NETC_FM_CMD_CREATE command */
struct netc_fm_conf {
	__u32 fm_action;       /* specify what action the Frame Modification will do */
	__u32 flags;
	__u16 ingress_port;    /* the frames flow into the switch from this port */
	__u16 egress_port;     /* the frames leave the switch through this port */
	struct fm_filter filter;    /* the filter parameters */
	/* the offset of the Message Count field in UADP NetworkMessage */
	__u16 message_count_offset;
	__u16 rev1;
};

/* IOCTL command number */
#define NETC_FM_CMD_CREATE      _IOW(0xE2, 0xC0, struct netc_fm_conf)
#define NETC_FM_CMD_DESTROY     _IO(0xE2, 0xC1)

#endif
