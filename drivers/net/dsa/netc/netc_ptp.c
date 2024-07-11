// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023-2024 NXP
 */

#include "netc.h"

#define extts_to_data(t) \
		container_of((t), struct netc_ptp_data, extts_timer)
#define ptp_caps_to_data(d) \
		container_of((d), struct netc_ptp_data, caps)
#define ptp_data_to_netc(d) \
		container_of((d), struct netc_private, ptp_data)

int netc_hwtstamp_set(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct netc_private *priv = ds->priv;
	struct hwtstamp_config config;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	switch (config.tx_type) {
	case HWTSTAMP_TX_OFF:
		priv->hwts_tx_en &= ~BIT(port);
		break;
	case HWTSTAMP_TX_ON:
		priv->hwts_tx_en |= BIT(port);
		break;
	default:
		return -ERANGE;
	}

	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		priv->hwts_rx_en &= ~BIT(port);
		break;
	default:
		priv->hwts_rx_en |= BIT(port);
		break;
	}

	if (copy_to_user(ifr->ifr_data, &config, sizeof(config)))
		return -EFAULT;
	return 0;
}

int netc_hwtstamp_get(struct dsa_switch *ds, int port, struct ifreq *ifr)
{
	struct netc_private *priv = ds->priv;
	struct hwtstamp_config config;

	config.flags = 0;
	if (priv->hwts_tx_en & BIT(port))
		config.tx_type = HWTSTAMP_TX_ON;
	else
		config.tx_type = HWTSTAMP_TX_OFF;
	if (priv->hwts_rx_en & BIT(port))
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;
	else
		config.rx_filter = HWTSTAMP_FILTER_NONE;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
		-EFAULT : 0;
}

int netc_get_ts_info(struct dsa_switch *ds, int port,
		     struct ethtool_ts_info *info)
{
	struct netc_private *priv = ds->priv;
	struct netc_ptp_data *ptp_data = &priv->ptp_data;

	/* Called during cleanup */
	if (!ptp_data->clock)
		return -ENODEV;

	info->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;
	info->tx_types = (1 << HWTSTAMP_TX_OFF) |
			 (1 << HWTSTAMP_TX_ON);
	info->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
			   (1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT);
	info->phc_index = ptp_clock_index(ptp_data->clock);

	return 0;
}

/* Called from dsa_skb_defer_rx_timestamp */
bool netc_port_rxtstamp(struct dsa_switch *ds, int port,
			   struct sk_buff *skb, unsigned int type)
{
	struct skb_shared_hwtstamps *shwt = skb_hwtstamps(skb);
	u64 ts = NETC_SKB_CB(skb)->tstamp;

	*shwt = (struct skb_shared_hwtstamps) {0};

	shwt->hwtstamp = ns_to_ktime(ts);

	/* Don't defer */
	return false;
}

void netc_process_meta_tstamp(struct dsa_switch *ds, int port,
			      u32 ts_id, u64 tstamp)
{
	struct netc_private *priv = ds->priv;
	struct netc_ptp_data *ptp_data = &priv->ptp_data;
	struct sk_buff *skb, *skb_tmp, *skb_match = NULL;
	struct skb_shared_hwtstamps shwt = {0};

	spin_lock(&ptp_data->skb_txtstamp_queue.lock);

	skb_queue_walk_safe(&ptp_data->skb_txtstamp_queue, skb, skb_tmp) {
		if (NETC_SKB_CB(skb)->ts_id != ts_id)
			continue;

		__skb_unlink(skb, &ptp_data->skb_txtstamp_queue);
		skb_match = skb;

		break;
	}

	spin_unlock(&ptp_data->skb_txtstamp_queue.lock);

	if (WARN_ON(!skb_match))
		return;

	shwt.hwtstamp = ns_to_ktime(tstamp);
	skb_complete_tx_timestamp(skb_match, &shwt);
}

/* Called from dsa_skb_tx_timestamp. This callback is just to clone
 * the skb and have it available in NETC_SKB_CB in the .port_deferred_xmit
 * callback, where we will timestamp it synchronously.
 */
void netc_port_txtstamp(struct dsa_switch *ds, int port, struct sk_buff *skb)
{
	struct netc_private *priv = ds->priv;
	struct sk_buff *clone;
	struct netc_ptp_data *ptp_data = &priv->ptp_data;
	u32 ts_id;

	if (!(priv->hwts_tx_en & BIT(port)))
		return;

	clone = skb_clone_sk(skb);
	if (!clone)
		return;

	NETC_SKB_CB(skb)->clone = clone;

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	spin_lock(&priv->ts_id_lock);

	ts_id = priv->ts_id;
	/* Deal automatically with 8-bit wraparound */
	priv->ts_id++;

	NETC_SKB_CB(clone)->ts_id = ts_id;

	spin_unlock(&priv->ts_id_lock);

	skb_queue_tail(&ptp_data->skb_txtstamp_queue, clone);
}

static int netc_ptp_reset(struct dsa_switch *ds)
{
	struct netc_private *priv = ds->priv;
	struct netc_ptp_data *ptp_data = &priv->ptp_data;
	int rc;
	u64 data = 1;

	dev_dbg(ds->dev, "Resetting PTP clock\n");

	mutex_lock(&ptp_data->lock);

	rc = netc_xfer_set_cmd(priv, NETC_CMD_PTP_SYNC_SET,
			       &data, sizeof(data));

	mutex_unlock(&ptp_data->lock);

	return rc;
}

static int netc_ptp_gettimex(struct ptp_clock_info *ptp,
			     struct timespec64 *ts,
			     struct ptp_system_timestamp *ptp_sts)
{
	struct netc_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct netc_private *priv = ptp_data_to_netc(ptp_data);
	u64 now = 0;
	int rc;

	mutex_lock(&ptp_data->lock);

	rc = netc_xfer_read_u64(priv, NETC_CMD_TIMER_CUR_GET, &now, ptp_sts);

	mutex_unlock(&ptp_data->lock);

	*ts = ns_to_timespec64(now);

	if (rc < 0)
		dev_err(priv->ds->dev, "Failed to read PTP clock: %d\n", rc);

	return rc;
}

static int netc_ptp_settime(struct ptp_clock_info *ptp,
			    const struct timespec64 *ts)
{
	struct netc_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct netc_private *priv = ptp_data_to_netc(ptp_data);
	struct netc_ptp_ctl_param param;
	int rc;

	param.ns = timespec64_to_ns(ts);
	param.clock_id = 0;

	mutex_lock(&ptp_data->lock);

	rc = netc_xfer_set_cmd(priv, NETC_CMD_TIMER_CUR_SET,
			       &param, sizeof(param));

	mutex_unlock(&ptp_data->lock);

	return rc;
}

static int netc_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct netc_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct netc_private *priv = ptp_data_to_netc(ptp_data);
	struct netc_ptp_ctl_param param;
	int rc;

	param.ppb = scaled_ppm_to_ppb(scaled_ppm);;
	param.clock_id = 0;

	mutex_lock(&ptp_data->lock);

	rc = netc_xfer_set_cmd(priv, NETC_CMD_TIMER_ADJFINE_SET,
			       &param, sizeof(param));

	mutex_unlock(&ptp_data->lock);

	return rc;
}

static int netc_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct netc_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct netc_private *priv = ptp_data_to_netc(ptp_data);
	struct netc_ptp_ctl_param param;
	int rc;

	param.offset = delta;
	param.clock_id = 0;

	mutex_lock(&ptp_data->lock);

	rc = netc_xfer_set_cmd(priv, NETC_CMD_TIMER_ADJTIME_SET,
			       &param, sizeof(param));

	mutex_unlock(&ptp_data->lock);

	return rc;
}

static int netc_per_out_enable(struct netc_private *priv,
			       struct ptp_perout_request *perout,
			       bool on)
{
	struct netc_ptp_data *ptp_data = &priv->ptp_data;
	struct netc_cmd_timer_pps param;
	int rc;

	/* We only support one channel */
	if (perout->index != 0)
		return -EOPNOTSUPP;

	/* Reject requests with unsupported flags */
	if (perout->flags)
		return -EOPNOTSUPP;

	mutex_lock(&ptp_data->lock);

	if (on) {
		struct timespec64 pin_duration_ts = {
			.tv_sec = perout->period.sec,
			.tv_nsec = perout->period.nsec,
		};
		struct timespec64 pin_start_ts = {
			.tv_sec = perout->start.sec,
			.tv_nsec = perout->start.nsec,
		};
		u64 pin_duration = timespec64_to_ns(&pin_duration_ts);
		if (pin_duration > U32_MAX) {
			rc = -ERANGE;
			goto _out;
		}
		param.pin_duration32 = (u32) pin_duration;
		param.pin_start = timespec64_to_ns(&pin_start_ts);

		rc = netc_xfer_set_cmd(priv, NETC_CMD_TIMER_PPS_START,
				       &param, sizeof(param));
	} else
		rc = netc_xfer_set_cmd(priv, NETC_CMD_TIMER_PPS_STOP,
				       NULL, 0);

_out:
	mutex_unlock(&ptp_data->lock);

	return rc;
}

static int netc_ptp_enable(struct ptp_clock_info *ptp,
			   struct ptp_clock_request *req, int on)
{
	struct netc_ptp_data *ptp_data = ptp_caps_to_data(ptp);
	struct netc_private *priv = ptp_data_to_netc(ptp_data);
	int rc = -EOPNOTSUPP;

	if (req->type == PTP_CLK_REQ_PEROUT)
		rc = netc_per_out_enable(priv, &req->perout, on);

	return rc;
}

struct ptp_clock_info netc_clock_caps = {
	.owner		= THIS_MODULE,
	.name		= "NETC PHC",
	.max_adj	= 1000000,
	.n_alarm	= 2,
	.n_ext_ts	= 2,
	.n_per_out	= 3,
	.n_pins		= 0,
	.pps		= 1,
	.adjfine	= netc_ptp_adjfine,
	.adjtime	= netc_ptp_adjtime,
	.gettimex64	= netc_ptp_gettimex,
	.settime64	= netc_ptp_settime,
	.enable		= netc_ptp_enable,
};

int netc_ptp_clock_register(struct dsa_switch *ds)
{
	struct netc_private *priv = ds->priv;
	struct netc_ptp_data *ptp_data = &priv->ptp_data;

	skb_queue_head_init(&ptp_data->skb_txtstamp_queue);

	ptp_data->caps = netc_clock_caps;
	ptp_data->clock = ptp_clock_register(&ptp_data->caps, ds->dev);
	if (IS_ERR_OR_NULL(ptp_data->clock))
		return PTR_ERR(ptp_data->clock);

	return netc_ptp_reset(ds);
}

void netc_ptp_clock_unregister(struct dsa_switch *ds)
{
	struct netc_private *priv = ds->priv;
	struct netc_ptp_data *ptp_data = &priv->ptp_data;

	if (IS_ERR_OR_NULL(ptp_data->clock))
		return;

	del_timer_sync(&ptp_data->extts_timer);
	ptp_cancel_worker_sync(ptp_data->clock);
	skb_queue_purge(&ptp_data->skb_txtstamp_queue);
	ptp_clock_unregister(ptp_data->clock);
	ptp_data->clock = NULL;
}
