# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_NET_DSA_NETC) += netcdsa.o

netcdsa-objs := \
    netc_spi.o \
    netc_config.o \
    netc_ethtool.o \
    netc_devlink.o \
    netc_main.o

ifdef CONFIG_NET_DSA_NETC_PTP
netcdsa-objs += netc_ptp.o
endif