// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 NXP
 *
 * author: Biwen Li (biwen.li@nxp.com)
 *         Hou Zhiqiang (Zhiqiang.Hou@nxp.com)
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/rpmsg.h>

#define RPMSG_PERF_AS_SENDER_IOCTL		_IO(0xb5, 0x5)
#define RPMSG_PERF_AS_RECEIVER_IOCTL		_IO(0xb5, 0x6)
#define RPMSG_PERF_AS_RECEIVER_END_ACK_IOCTL	_IO(0xb5, 0x7)
#define RPMSG_PERF_GET_RUNNING_STA_IOCTL	_IO(0xb5, 0x8)

enum {
	RPMSG_DEV_IDLE,
	RPMSG_DEV_SENDING,
	RPMSG_DEV_RECEIVING,
};

static void usage(char *name)
{
	printf("usage: %s <dev> <as_sender> <no_copy> <packet_size> <test_time>\n", name);
	printf("\tdev: specify rpmsg device, see /dev/rpmsg-perf<x>\n");
	printf("\tas_sender: true for as_sender, false for as_receiver\n");
	printf("\tno_copy: specify if use no_copy version API in remote side\n");
	printf("\tpacket_size: specify the packet size, the MAX value is 496\n");
	printf("\ttest_time: specify the test period\n");
	printf("\tsuch as: %s /dev/rpmsg-perf0 true true 64 60\n", name);
}

struct packet_header
{
	uint32_t preamble;
	bool no_copy;
	uint32_t packet_size;
	uint32_t packet_cnt;
	uint32_t test_time; /* unit: second */
	uint32_t poll_times; /* when linux as receiver, FreeRTOS poll times when get one tx buffer */
};

int main(int argc, char* argv[]) {
	int ep_fd;
	ssize_t ret;
	struct packet_header hdr;
	bool as_sender = false;
	uint32_t status;

	if (argc != 6) {
		usage(argv[0]);
		return 1;
	}

	ep_fd = open(argv[1], O_RDWR);
	if (ep_fd == -1) {
		perror("Can't open rpmsg-perf endpoint device");
		return 1;
	}

	if (!strcmp(argv[2], "true"))
		as_sender = true;

	if (!strcmp(argv[3], "true"))
		hdr.no_copy = true;
	else
		hdr.no_copy = false;

	hdr.packet_size = atoi(argv[4]);
	if ((hdr.packet_size > 496) || (hdr.packet_size <= 0)) {
		usage(argv[0]);
		return 1;
	}

	hdr.test_time = atoi(argv[5]);
	if (hdr.test_time <= 0)
		hdr.test_time = 60;

	if (as_sender) {
		if (ioctl(ep_fd, RPMSG_PERF_AS_SENDER_IOCTL, &hdr))
			perror("Failed to run as sender");
	} else {
		if (ioctl(ep_fd, RPMSG_PERF_AS_RECEIVER_IOCTL, &hdr))
			perror("Failed to run as receiver");

		usleep((hdr.test_time) * 1000 * 1000);
		if (ioctl(ep_fd, RPMSG_PERF_AS_RECEIVER_END_ACK_IOCTL, &hdr))
			perror("Failed to send RECEIVER_END_ACK packet");

	}

	do {
		ioctl(ep_fd, RPMSG_PERF_GET_RUNNING_STA_IOCTL, &status);
		if (status == RPMSG_DEV_IDLE)
			break;
		usleep(100000);
	} while (1);

	close(ep_fd);
	return 0;
}
