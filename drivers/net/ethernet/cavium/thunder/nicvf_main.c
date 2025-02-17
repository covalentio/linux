/*
 * Copyright (C) 2015 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/log2.h>
#include <linux/prefetch.h>
#include <linux/irq.h>

#include "nic_reg.h"
#include "nic.h"
#include "nicvf_queues.h"
#include "thunder_bgx.h"

#define DRV_NAME	"thunder-nicvf"
#define DRV_VERSION	"1.0"

/* Supported devices */
static const struct pci_device_id nicvf_id_table[] = {
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVICE_ID_THUNDER_NIC_VF,
			 PCI_VENDOR_ID_CAVIUM, 0xA11E) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVICE_ID_THUNDER_PASS1_NIC_VF,
			 PCI_VENDOR_ID_CAVIUM, 0xA11E) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Sunil Goutham");
MODULE_DESCRIPTION("Cavium Thunder NIC Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, nicvf_id_table);

static int debug = 0x00;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug message level bitmap");

static int cpi_alg = CPI_ALG_NONE;
module_param(cpi_alg, int, S_IRUGO);
MODULE_PARM_DESC(cpi_alg,
		 "PFC algorithm (0=none, 1=VLAN, 2=VLAN16, 3=IP Diffserv)");

static int nicvf_enable_msix(struct nicvf *nic);
static netdev_tx_t nicvf_xmit(struct sk_buff *skb, struct net_device *netdev);
static void nicvf_read_bgx_stats(struct nicvf *nic, struct bgx_stats_msg *bgx);

static inline void nicvf_set_rx_frame_cnt(struct nicvf *nic,
					  struct sk_buff *skb)
{
	if (skb->len <= 64)
		nic->drv_stats.rx_frames_64++;
	else if (skb->len <= 127)
		nic->drv_stats.rx_frames_127++;
	else if (skb->len <= 255)
		nic->drv_stats.rx_frames_255++;
	else if (skb->len <= 511)
		nic->drv_stats.rx_frames_511++;
	else if (skb->len <= 1023)
		nic->drv_stats.rx_frames_1023++;
	else if (skb->len <= 1518)
		nic->drv_stats.rx_frames_1518++;
	else
		nic->drv_stats.rx_frames_jumbo++;
}

/* The Cavium ThunderX network controller can *only* be found in SoCs
 * containing the ThunderX ARM64 CPU implementation.  All accesses to the device
 * registers on this platform are implicitly strongly ordered with respect
 * to memory accesses. So writeq_relaxed() and readq_relaxed() are safe to use
 * with no memory barriers in this driver.  The readq()/writeq() functions add
 * explicit ordering operation which in this case are redundant, and only
 * add overhead.
 */

/* Register read/write APIs */
void nicvf_reg_write(struct nicvf *nic, u64 offset, u64 val)
{
	writeq_relaxed(val, nic->reg_base + offset);
}

u64 nicvf_reg_read(struct nicvf *nic, u64 offset)
{
	return readq_relaxed(nic->reg_base + offset);
}

void nicvf_queue_reg_write(struct nicvf *nic, u64 offset,
			   u64 qidx, u64 val)
{
	void __iomem *addr = nic->reg_base + offset;

	writeq_relaxed(val, addr + (qidx << NIC_Q_NUM_SHIFT));
}

u64 nicvf_queue_reg_read(struct nicvf *nic, u64 offset, u64 qidx)
{
	void __iomem *addr = nic->reg_base + offset;

	return readq_relaxed(addr + (qidx << NIC_Q_NUM_SHIFT));
}

/* VF -> PF mailbox communication */

int nicvf_send_msg_to_pf(struct nicvf *nic, union nic_mbx *mbx)
{
	int timeout = NIC_MBOX_MSG_TIMEOUT;
	int sleep = 10;
	u64 *msg = (u64 *)mbx;

	nic->pf_acked = false;
	nic->pf_nacked = false;

	nicvf_reg_write(nic, NIC_VF_PF_MAILBOX_0_1 + 0, msg[0]);
	nicvf_reg_write(nic, NIC_VF_PF_MAILBOX_0_1 + 8, msg[1]);

	/* Wait for previous message to be acked, timeout 2sec */
	while (!nic->pf_acked) {
		if (nic->pf_nacked)
			return -EINVAL;
		msleep(sleep);
		if (nic->pf_acked)
			break;
		timeout -= sleep;
		if (!timeout) {
			netdev_err(nic->netdev,
				   "PF didn't ack to mbox msg %d from VF%d\n",
				   (mbx->msg.msg & 0xFF), nic->vf_id);
			return -EBUSY;
		}
	}
	return 0;
}

/* Checks if VF is able to comminicate with PF
* and also gets the VNIC number this VF is associated to.
*/
static int nicvf_check_pf_ready(struct nicvf *nic)
{
	int timeout = 5000, sleep = 20;

	nic->pf_ready_to_rcv_msg = false;

	nicvf_reg_write(nic, NIC_VF_PF_MAILBOX_0_1 + 0,
			le64_to_cpu(NIC_MBOX_MSG_READY));
	nicvf_reg_write(nic, NIC_VF_PF_MAILBOX_0_1 + 8, 1ULL);

	while (!nic->pf_ready_to_rcv_msg) {
		msleep(sleep);
		if (nic->pf_ready_to_rcv_msg)
			break;
		timeout -= sleep;
		if (!timeout) {
			netdev_err(nic->netdev,
				   "PF didn't respond to READY msg\n");
			return 0;
		}
	}
	return 1;
}

static void  nicvf_handle_mbx_intr(struct nicvf *nic)
{
	union nic_mbx mbx = {};
	u64 *mbx_data;
	u64 mbx_addr;
	int i;

	mbx_addr = NIC_VF_PF_MAILBOX_0_1;
	mbx_data = (u64 *)&mbx;

	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_data = nicvf_reg_read(nic, mbx_addr);
		mbx_data++;
		mbx_addr += sizeof(u64);
	}

	netdev_dbg(nic->netdev, "Mbox message: msg: 0x%x\n", mbx.msg.msg);
	switch (mbx.msg.msg) {
	case NIC_MBOX_MSG_READY:
		nic->pf_ready_to_rcv_msg = true;
		nic->vf_id = mbx.nic_cfg.vf_id & 0x7F;
		nic->tns_mode = mbx.nic_cfg.tns_mode & 0x7F;
		nic->node = mbx.nic_cfg.node_id;
		ether_addr_copy(nic->netdev->dev_addr,
				(u8 *)&mbx.nic_cfg.mac_addr);
		nic->link_up = false;
		nic->duplex = 0;
		nic->speed = 0;
		break;
	case NIC_MBOX_MSG_ACK:
		nic->pf_acked = true;
		break;
	case NIC_MBOX_MSG_NACK:
		nic->pf_nacked = true;
		break;
	case NIC_MBOX_MSG_RSS_SIZE:
		nic->rss_info.rss_size = mbx.rss_size.ind_tbl_size;
		nic->pf_acked = true;
		break;
	case NIC_MBOX_MSG_BGX_STATS:
		nicvf_read_bgx_stats(nic, &mbx.bgx_stats);
		nic->pf_acked = true;
		nic->bgx_stats_acked = true;
		break;
	case NIC_MBOX_MSG_BGX_LINK_CHANGE:
		nic->pf_acked = true;
		nic->link_up = mbx.link_status.link_up;
		nic->duplex = mbx.link_status.duplex;
		nic->speed = mbx.link_status.speed;
		if (nic->link_up) {
			netdev_info(nic->netdev, "%s: Link is Up %d Mbps %s\n",
				    nic->netdev->name, nic->speed,
				    nic->duplex == DUPLEX_FULL ?
				"Full duplex" : "Half duplex");
			netif_carrier_on(nic->netdev);
			netif_tx_wake_all_queues(nic->netdev);
		} else {
			netdev_info(nic->netdev, "%s: Link is Down\n",
				    nic->netdev->name);
			netif_carrier_off(nic->netdev);
			netif_tx_stop_all_queues(nic->netdev);
		}
		break;
	default:
		netdev_err(nic->netdev,
			   "Invalid message from PF, msg 0x%x\n", mbx.msg.msg);
		break;
	}
	nicvf_clear_intr(nic, NICVF_INTR_MBOX, 0);
}

static int nicvf_hw_set_mac_addr(struct nicvf *nic, struct net_device *netdev)
{
	union nic_mbx mbx = {};
	int i;

	mbx.mac.msg = NIC_MBOX_MSG_SET_MAC;
	mbx.mac.vf_id = nic->vf_id;
	for (i = 0; i < ETH_ALEN; i++)
		mbx.mac.addr = (mbx.mac.addr << 8) |
				     netdev->dev_addr[i];

	return nicvf_send_msg_to_pf(nic, &mbx);
}

void nicvf_config_cpi(struct nicvf *nic)
{
	union nic_mbx mbx = {};

	mbx.cpi_cfg.msg = NIC_MBOX_MSG_CPI_CFG;
	mbx.cpi_cfg.vf_id = nic->vf_id;
	mbx.cpi_cfg.cpi_alg = nic->cpi_alg;
	mbx.cpi_cfg.rq_cnt = nic->qs->rq_cnt;

	nicvf_send_msg_to_pf(nic, &mbx);
}

void nicvf_get_rss_size(struct nicvf *nic)
{
	union nic_mbx mbx = {};

	mbx.rss_size.msg = NIC_MBOX_MSG_RSS_SIZE;
	mbx.rss_size.vf_id = nic->vf_id;
	nicvf_send_msg_to_pf(nic, &mbx);
}

void nicvf_config_rss(struct nicvf *nic)
{
	union nic_mbx mbx = {};
	struct nicvf_rss_info *rss = &nic->rss_info;
	int ind_tbl_len = rss->rss_size;
	int i, nextq = 0;

	mbx.rss_cfg.vf_id = nic->vf_id;
	mbx.rss_cfg.hash_bits = rss->hash_bits;
	while (ind_tbl_len) {
		mbx.rss_cfg.tbl_offset = nextq;
		mbx.rss_cfg.tbl_len = min(ind_tbl_len,
					       RSS_IND_TBL_LEN_PER_MBX_MSG);
		mbx.rss_cfg.msg = mbx.rss_cfg.tbl_offset ?
			  NIC_MBOX_MSG_RSS_CFG_CONT : NIC_MBOX_MSG_RSS_CFG;

		for (i = 0; i < mbx.rss_cfg.tbl_len; i++)
			mbx.rss_cfg.ind_tbl[i] = rss->ind_tbl[nextq++];

		nicvf_send_msg_to_pf(nic, &mbx);

		ind_tbl_len -= mbx.rss_cfg.tbl_len;
	}
}

void nicvf_set_rss_key(struct nicvf *nic)
{
	struct nicvf_rss_info *rss = &nic->rss_info;
	u64 key_addr = NIC_VNIC_RSS_KEY_0_4;
	int idx;

	for (idx = 0; idx < RSS_HASH_KEY_SIZE; idx++) {
		nicvf_reg_write(nic, key_addr, rss->key[idx]);
		key_addr += sizeof(u64);
	}
}

static int nicvf_rss_init(struct nicvf *nic)
{
	struct nicvf_rss_info *rss = &nic->rss_info;
	int idx;

	nicvf_get_rss_size(nic);

	if ((nic->qs->rq_cnt <= 1) || (cpi_alg != CPI_ALG_NONE)) {
		rss->enable = false;
		rss->hash_bits = 0;
		return 0;
	}

	rss->enable = true;

	/* Using the HW reset value for now */
	rss->key[0] = 0xFEED0BADFEED0BAD;
	rss->key[1] = 0xFEED0BADFEED0BAD;
	rss->key[2] = 0xFEED0BADFEED0BAD;
	rss->key[3] = 0xFEED0BADFEED0BAD;
	rss->key[4] = 0xFEED0BADFEED0BAD;

	nicvf_set_rss_key(nic);

	rss->cfg = RSS_IP_HASH_ENA | RSS_TCP_HASH_ENA | RSS_UDP_HASH_ENA;
	nicvf_reg_write(nic, NIC_VNIC_RSS_CFG, rss->cfg);

	rss->hash_bits =  ilog2(rounddown_pow_of_two(rss->rss_size));

	for (idx = 0; idx < rss->rss_size; idx++)
		rss->ind_tbl[idx] = ethtool_rxfh_indir_default(idx,
							       nic->qs->rq_cnt);
	nicvf_config_rss(nic);
	return 1;
}

int nicvf_set_real_num_queues(struct net_device *netdev,
			      int tx_queues, int rx_queues)
{
	int err = 0;

	err = netif_set_real_num_tx_queues(netdev, tx_queues);
	if (err) {
		netdev_err(netdev,
			   "Failed to set no of Tx queues: %d\n", tx_queues);
		return err;
	}

	err = netif_set_real_num_rx_queues(netdev, rx_queues);
	if (err)
		netdev_err(netdev,
			   "Failed to set no of Rx queues: %d\n", rx_queues);
	return err;
}

static int nicvf_init_resources(struct nicvf *nic)
{
	int err;
	u64 mbx_addr = NIC_VF_PF_MAILBOX_0_1;

	/* Enable Qset */
	nicvf_qset_config(nic, true);

	/* Initialize queues and HW for data transfer */
	err = nicvf_config_data_transfer(nic, true);
	if (err) {
		netdev_err(nic->netdev,
			   "Failed to alloc/config VF's QSet resources\n");
		return err;
	}

	/* Send VF config done msg to PF */
	nicvf_reg_write(nic, mbx_addr, le64_to_cpu(NIC_MBOX_MSG_CFG_DONE));
	mbx_addr += (NIC_PF_VF_MAILBOX_SIZE - 1) * 8;
	nicvf_reg_write(nic, mbx_addr, 1ULL);

	return 0;
}

static void nicvf_snd_pkt_handler(struct net_device *netdev,
				  struct cmp_queue *cq,
				  struct cqe_send_t *cqe_tx, int cqe_type)
{
	struct sk_buff *skb = NULL;
	struct nicvf *nic = netdev_priv(netdev);
	struct snd_queue *sq;
	struct sq_hdr_subdesc *hdr;

	sq = &nic->qs->sq[cqe_tx->sq_idx];

	hdr = (struct sq_hdr_subdesc *)GET_SQ_DESC(sq, cqe_tx->sqe_ptr);
	if (hdr->subdesc_type != SQ_DESC_TYPE_HEADER)
		return;

	netdev_dbg(nic->netdev,
		   "%s Qset #%d SQ #%d SQ ptr #%d subdesc count %d\n",
		   __func__, cqe_tx->sq_qs, cqe_tx->sq_idx,
		   cqe_tx->sqe_ptr, hdr->subdesc_cnt);

	nicvf_put_sq_desc(sq, hdr->subdesc_cnt + 1);
	nicvf_check_cqe_tx_errs(nic, cq, cqe_tx);
	skb = (struct sk_buff *)sq->skbuff[cqe_tx->sqe_ptr];
	/* For TSO offloaded packets only one head SKB needs to be freed */
	if (skb) {
		prefetch(skb);
		dev_consume_skb_any(skb);
	}
}

static void nicvf_rcv_pkt_handler(struct net_device *netdev,
				  struct napi_struct *napi,
				  struct cmp_queue *cq,
				  struct cqe_rx_t *cqe_rx, int cqe_type)
{
	struct sk_buff *skb;
	struct nicvf *nic = netdev_priv(netdev);
	int err = 0;

	/* Check for errors */
	err = nicvf_check_cqe_rx_errs(nic, cq, cqe_rx);
	if (err && !cqe_rx->rb_cnt)
		return;

	skb = nicvf_get_rcv_skb(nic, cqe_rx);
	if (!skb) {
		netdev_dbg(nic->netdev, "Packet not received\n");
		return;
	}

	if (netif_msg_pktdata(nic)) {
		netdev_info(nic->netdev, "%s: skb 0x%p, len=%d\n", netdev->name,
			    skb, skb->len);
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1,
			       skb->data, skb->len, true);
	}

	nicvf_set_rx_frame_cnt(nic, skb);

	skb_record_rx_queue(skb, cqe_rx->rq_idx);
	if (netdev->hw_features & NETIF_F_RXCSUM) {
		/* HW by default verifies TCP/UDP/SCTP checksums */
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {
		skb_checksum_none_assert(skb);
	}

	skb->protocol = eth_type_trans(skb, netdev);

	if (napi && (netdev->features & NETIF_F_GRO))
		napi_gro_receive(napi, skb);
	else
		netif_receive_skb(skb);
}

static int nicvf_cq_intr_handler(struct net_device *netdev, u8 cq_idx,
				 struct napi_struct *napi, int budget)
{
	int processed_cqe, work_done = 0;
	int cqe_count, cqe_head;
	struct nicvf *nic = netdev_priv(netdev);
	struct queue_set *qs = nic->qs;
	struct cmp_queue *cq = &qs->cq[cq_idx];
	struct cqe_rx_t *cq_desc;

	spin_lock_bh(&cq->lock);
loop:
	processed_cqe = 0;
	/* Get no of valid CQ entries to process */
	cqe_count = nicvf_queue_reg_read(nic, NIC_QSET_CQ_0_7_STATUS, cq_idx);
	cqe_count &= CQ_CQE_COUNT;
	if (!cqe_count)
		goto done;

	/* Get head of the valid CQ entries */
	cqe_head = nicvf_queue_reg_read(nic, NIC_QSET_CQ_0_7_HEAD, cq_idx) >> 9;
	cqe_head &= 0xFFFF;

	netdev_dbg(nic->netdev, "%s cqe_count %d cqe_head %d\n",
		   __func__, cqe_count, cqe_head);
	while (processed_cqe < cqe_count) {
		/* Get the CQ descriptor */
		cq_desc = (struct cqe_rx_t *)GET_CQ_DESC(cq, cqe_head);
		cqe_head++;
		cqe_head &= (cq->dmem.q_len - 1);
		/* Initiate prefetch for next descriptor */
		prefetch((struct cqe_rx_t *)GET_CQ_DESC(cq, cqe_head));

		if ((work_done >= budget) && napi &&
		    (cq_desc->cqe_type != CQE_TYPE_SEND)) {
			break;
		}

		netdev_dbg(nic->netdev, "cq_desc->cqe_type %d\n",
			   cq_desc->cqe_type);
		switch (cq_desc->cqe_type) {
		case CQE_TYPE_RX:
			nicvf_rcv_pkt_handler(netdev, napi, cq,
					      cq_desc, CQE_TYPE_RX);
			work_done++;
		break;
		case CQE_TYPE_SEND:
			nicvf_snd_pkt_handler(netdev, cq,
					      (void *)cq_desc, CQE_TYPE_SEND);
		break;
		case CQE_TYPE_INVALID:
		case CQE_TYPE_RX_SPLIT:
		case CQE_TYPE_RX_TCP:
		case CQE_TYPE_SEND_PTP:
			/* Ignore for now */
		break;
		}
		processed_cqe++;
	}
	netdev_dbg(nic->netdev, "%s processed_cqe %d work_done %d budget %d\n",
		   __func__, processed_cqe, work_done, budget);

	/* Ring doorbell to inform H/W to reuse processed CQEs */
	nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_DOOR,
			      cq_idx, processed_cqe);

	if ((work_done < budget) && napi)
		goto loop;

done:
	spin_unlock_bh(&cq->lock);
	return work_done;
}

static int nicvf_poll(struct napi_struct *napi, int budget)
{
	u64  cq_head;
	int  work_done = 0;
	struct net_device *netdev = napi->dev;
	struct nicvf *nic = netdev_priv(netdev);
	struct nicvf_cq_poll *cq;
	struct netdev_queue *txq;

	cq = container_of(napi, struct nicvf_cq_poll, napi);
	work_done = nicvf_cq_intr_handler(netdev, cq->cq_idx, napi, budget);

	txq = netdev_get_tx_queue(netdev, cq->cq_idx);
	if (netif_tx_queue_stopped(txq))
		netif_tx_wake_queue(txq);

	if (work_done < budget) {
		/* Slow packet rate, exit polling */
		napi_complete(napi);
		/* Re-enable interrupts */
		cq_head = nicvf_queue_reg_read(nic, NIC_QSET_CQ_0_7_HEAD,
					       cq->cq_idx);
		nicvf_clear_intr(nic, NICVF_INTR_CQ, cq->cq_idx);
		nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_HEAD,
				      cq->cq_idx, cq_head);
		nicvf_enable_intr(nic, NICVF_INTR_CQ, cq->cq_idx);
	}
	return work_done;
}

/* Qset error interrupt handler
 *
 * As of now only CQ errors are handled
 */
void nicvf_handle_qs_err(unsigned long data)
{
	struct nicvf *nic = (struct nicvf *)data;
	struct queue_set *qs = nic->qs;
	int qidx;
	u64 status;

	netif_tx_disable(nic->netdev);

	/* Check if it is CQ err */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		status = nicvf_queue_reg_read(nic, NIC_QSET_CQ_0_7_STATUS,
					      qidx);
		if (!(status & CQ_ERR_MASK))
			continue;
		/* Process already queued CQEs and reconfig CQ */
		nicvf_disable_intr(nic, NICVF_INTR_CQ, qidx);
		nicvf_sq_disable(nic, qidx);
		nicvf_cq_intr_handler(nic->netdev, qidx, NULL, 0);
		nicvf_cmp_queue_config(nic, qs, qidx, true);
		nicvf_sq_free_used_descs(nic->netdev, &qs->sq[qidx], qidx);
		nicvf_sq_enable(nic, &qs->sq[qidx], qidx);

		nicvf_enable_intr(nic, NICVF_INTR_CQ, qidx);
	}

	netif_tx_start_all_queues(nic->netdev);
	/* Re-enable Qset error interrupt */
	nicvf_enable_intr(nic, NICVF_INTR_QS_ERR, 0);
}

static irqreturn_t nicvf_misc_intr_handler(int irq, void *nicvf_irq)
{
	struct nicvf *nic = (struct nicvf *)nicvf_irq;
	u64 intr;

	intr = nicvf_reg_read(nic, NIC_VF_INT);
	/* Check for spurious interrupt */
	if (!(intr & NICVF_INTR_MBOX_MASK))
		return IRQ_HANDLED;

	nicvf_handle_mbx_intr(nic);

	return IRQ_HANDLED;
}

static irqreturn_t nicvf_intr_handler(int irq, void *nicvf_irq)
{
	u64 qidx, intr, clear_intr = 0;
	u64 cq_intr, rbdr_intr, qs_err_intr;
	struct nicvf *nic = (struct nicvf *)nicvf_irq;
	struct queue_set *qs = nic->qs;
	struct nicvf_cq_poll *cq_poll = NULL;

	intr = nicvf_reg_read(nic, NIC_VF_INT);
	if (netif_msg_intr(nic))
		netdev_info(nic->netdev, "%s: interrupt status 0x%llx\n",
			    nic->netdev->name, intr);

	qs_err_intr = intr & NICVF_INTR_QS_ERR_MASK;
	if (qs_err_intr) {
		/* Disable Qset err interrupt and schedule softirq */
		nicvf_disable_intr(nic, NICVF_INTR_QS_ERR, 0);
		tasklet_hi_schedule(&nic->qs_err_task);
		clear_intr |= qs_err_intr;
	}

	/* Disable interrupts and start polling */
	cq_intr = (intr & NICVF_INTR_CQ_MASK) >> NICVF_INTR_CQ_SHIFT;
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		if (!(cq_intr & (1 << qidx)))
			continue;
		if (!nicvf_is_intr_enabled(nic, NICVF_INTR_CQ, qidx))
			continue;

		nicvf_disable_intr(nic, NICVF_INTR_CQ, qidx);
		clear_intr |= ((1 << qidx) << NICVF_INTR_CQ_SHIFT);

		cq_poll = nic->napi[qidx];
		/* Schedule NAPI */
		if (cq_poll)
			napi_schedule(&cq_poll->napi);
	}

	/* Handle RBDR interrupts */
	rbdr_intr = (intr & NICVF_INTR_RBDR_MASK) >> NICVF_INTR_RBDR_SHIFT;
	if (rbdr_intr) {
		/* Disable RBDR interrupt and schedule softirq */
		for (qidx = 0; qidx < qs->rbdr_cnt; qidx++) {
			if (!nicvf_is_intr_enabled(nic, NICVF_INTR_RBDR, qidx))
				continue;
			nicvf_disable_intr(nic, NICVF_INTR_RBDR, qidx);
			tasklet_hi_schedule(&nic->rbdr_task);
			clear_intr |= ((1 << qidx) << NICVF_INTR_RBDR_SHIFT);
		}
	}

	/* Clear interrupts */
	nicvf_reg_write(nic, NIC_VF_INT, clear_intr);
	return IRQ_HANDLED;
}

static int nicvf_enable_msix(struct nicvf *nic)
{
	int ret, vec;

	nic->num_vec = NIC_VF_MSIX_VECTORS;

	for (vec = 0; vec < nic->num_vec; vec++)
		nic->msix_entries[vec].entry = vec;

	ret = pci_enable_msix(nic->pdev, nic->msix_entries, nic->num_vec);
	if (ret) {
		netdev_err(nic->netdev,
			   "Req for #%d msix vectors failed\n", nic->num_vec);
		return 0;
	}
	nic->msix_enabled = 1;
	return 1;
}

static void nicvf_disable_msix(struct nicvf *nic)
{
	if (nic->msix_enabled) {
		pci_disable_msix(nic->pdev);
		nic->msix_enabled = 0;
		nic->num_vec = 0;
	}
}

static int nicvf_register_interrupts(struct nicvf *nic)
{
	int irq, free, ret = 0;
	int vector;

	for_each_cq_irq(irq)
		sprintf(nic->irq_name[irq], "NICVF%d CQ%d",
			nic->vf_id, irq);

	for_each_sq_irq(irq)
		sprintf(nic->irq_name[irq], "NICVF%d SQ%d",
			nic->vf_id, irq - NICVF_INTR_ID_SQ);

	for_each_rbdr_irq(irq)
		sprintf(nic->irq_name[irq], "NICVF%d RBDR%d",
			nic->vf_id, irq - NICVF_INTR_ID_RBDR);

	/* Register all interrupts except mailbox */
	for (irq = 0; irq < NICVF_INTR_ID_SQ; irq++) {
		vector = nic->msix_entries[irq].vector;
		ret = request_irq(vector, nicvf_intr_handler,
				  0, nic->irq_name[irq], nic);
		if (ret)
			break;
		nic->irq_allocated[irq] = true;
	}

	for (irq = NICVF_INTR_ID_SQ; irq < NICVF_INTR_ID_MISC; irq++) {
		vector = nic->msix_entries[irq].vector;
		ret = request_irq(vector, nicvf_intr_handler,
				  0, nic->irq_name[irq], nic);
		if (ret)
			break;
		nic->irq_allocated[irq] = true;
	}

	sprintf(nic->irq_name[NICVF_INTR_ID_QS_ERR],
		"NICVF%d Qset error", nic->vf_id);
	if (!ret) {
		vector = nic->msix_entries[NICVF_INTR_ID_QS_ERR].vector;
		irq = NICVF_INTR_ID_QS_ERR;
		ret = request_irq(vector, nicvf_intr_handler,
				  0, nic->irq_name[irq], nic);
		if (!ret)
			nic->irq_allocated[irq] = true;
	}

	if (ret) {
		netdev_err(nic->netdev, "Request irq failed\n");
		for (free = 0; free < irq; free++)
			free_irq(nic->msix_entries[free].vector, nic);
		return ret;
	}

	return 0;
}

static void nicvf_unregister_interrupts(struct nicvf *nic)
{
	int irq;

	/* Free registered interrupts */
	for (irq = 0; irq < nic->num_vec; irq++) {
		if (nic->irq_allocated[irq])
			free_irq(nic->msix_entries[irq].vector, nic);
		nic->irq_allocated[irq] = false;
	}

	/* Disable MSI-X */
	nicvf_disable_msix(nic);
}

/* Initialize MSIX vectors and register MISC interrupt.
 * Send READY message to PF to check if its alive
 */
static int nicvf_register_misc_interrupt(struct nicvf *nic)
{
	int ret = 0;
	int irq = NICVF_INTR_ID_MISC;

	/* Return if mailbox interrupt is already registered */
	if (nic->msix_enabled)
		return 0;

	/* Enable MSI-X */
	if (!nicvf_enable_msix(nic))
		return 1;

	sprintf(nic->irq_name[irq], "%s Mbox", "NICVF");
	/* Register Misc interrupt */
	ret = request_irq(nic->msix_entries[irq].vector,
			  nicvf_misc_intr_handler, 0, nic->irq_name[irq], nic);

	if (ret)
		return ret;
	nic->irq_allocated[irq] = true;

	/* Enable mailbox interrupt */
	nicvf_enable_intr(nic, NICVF_INTR_MBOX, 0);

	/* Check if VF is able to communicate with PF */
	if (!nicvf_check_pf_ready(nic)) {
		nicvf_disable_intr(nic, NICVF_INTR_MBOX, 0);
		nicvf_unregister_interrupts(nic);
		return 1;
	}

	return 0;
}

static netdev_tx_t nicvf_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nicvf *nic = netdev_priv(netdev);
	int qid = skb_get_queue_mapping(skb);
	struct netdev_queue *txq = netdev_get_tx_queue(netdev, qid);

	/* Check for minimum packet length */
	if (skb->len <= ETH_HLEN) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (!nicvf_sq_append_skb(nic, skb) && !netif_tx_queue_stopped(txq)) {
		netif_tx_stop_queue(txq);
		nic->drv_stats.tx_busy++;
		if (netif_msg_tx_err(nic))
			netdev_warn(netdev,
				    "%s: Transmit ring full, stopping SQ%d\n",
				    netdev->name, qid);

		return NETDEV_TX_BUSY;
	}

	return NETDEV_TX_OK;
}

int nicvf_stop(struct net_device *netdev)
{
	int irq, qidx;
	struct nicvf *nic = netdev_priv(netdev);
	struct queue_set *qs = nic->qs;
	struct nicvf_cq_poll *cq_poll = NULL;
	union nic_mbx mbx = {};

	mbx.msg.msg = NIC_MBOX_MSG_SHUTDOWN;
	nicvf_send_msg_to_pf(nic, &mbx);

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	/* Disable RBDR & QS error interrupts */
	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++) {
		nicvf_disable_intr(nic, NICVF_INTR_RBDR, qidx);
		nicvf_clear_intr(nic, NICVF_INTR_RBDR, qidx);
	}
	nicvf_disable_intr(nic, NICVF_INTR_QS_ERR, 0);
	nicvf_clear_intr(nic, NICVF_INTR_QS_ERR, 0);

	/* Wait for pending IRQ handlers to finish */
	for (irq = 0; irq < nic->num_vec; irq++)
		synchronize_irq(nic->msix_entries[irq].vector);

	tasklet_kill(&nic->rbdr_task);
	tasklet_kill(&nic->qs_err_task);
	if (nic->rb_work_scheduled)
		cancel_delayed_work_sync(&nic->rbdr_work);

	for (qidx = 0; qidx < nic->qs->cq_cnt; qidx++) {
		cq_poll = nic->napi[qidx];
		if (!cq_poll)
			continue;
		nic->napi[qidx] = NULL;
		napi_synchronize(&cq_poll->napi);
		/* CQ intr is enabled while napi_complete,
		 * so disable it now
		 */
		nicvf_disable_intr(nic, NICVF_INTR_CQ, qidx);
		nicvf_clear_intr(nic, NICVF_INTR_CQ, qidx);
		napi_disable(&cq_poll->napi);
		netif_napi_del(&cq_poll->napi);
		kfree(cq_poll);
	}

	/* Free resources */
	nicvf_config_data_transfer(nic, false);

	/* Disable HW Qset */
	nicvf_qset_config(nic, false);

	/* disable mailbox interrupt */
	nicvf_disable_intr(nic, NICVF_INTR_MBOX, 0);

	nicvf_unregister_interrupts(nic);

	return 0;
}

int nicvf_open(struct net_device *netdev)
{
	int err, qidx;
	struct nicvf *nic = netdev_priv(netdev);
	struct queue_set *qs = nic->qs;
	struct nicvf_cq_poll *cq_poll = NULL;

	nic->mtu = netdev->mtu;

	netif_carrier_off(netdev);

	err = nicvf_register_misc_interrupt(nic);
	if (err)
		return err;

	/* Register NAPI handler for processing CQEs */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		cq_poll = kzalloc(sizeof(*cq_poll), GFP_KERNEL);
		if (!cq_poll) {
			err = -ENOMEM;
			goto napi_del;
		}
		cq_poll->cq_idx = qidx;
		netif_napi_add(netdev, &cq_poll->napi, nicvf_poll,
			       NAPI_POLL_WEIGHT);
		napi_enable(&cq_poll->napi);
		nic->napi[qidx] = cq_poll;
	}

	/* Check if we got MAC address from PF or else generate a radom MAC */
	if (is_zero_ether_addr(netdev->dev_addr)) {
		eth_hw_addr_random(netdev);
		nicvf_hw_set_mac_addr(nic, netdev);
	}

	/* Init tasklet for handling Qset err interrupt */
	tasklet_init(&nic->qs_err_task, nicvf_handle_qs_err,
		     (unsigned long)nic);

	/* Init RBDR tasklet which will refill RBDR */
	tasklet_init(&nic->rbdr_task, nicvf_rbdr_task,
		     (unsigned long)nic);
	INIT_DELAYED_WORK(&nic->rbdr_work, nicvf_rbdr_work);

	/* Configure CPI alorithm */
	nic->cpi_alg = cpi_alg;
	nicvf_config_cpi(nic);

	/* Configure receive side scaling */
	nicvf_rss_init(nic);

	err = nicvf_register_interrupts(nic);
	if (err)
		goto cleanup;

	/* Initialize the queues */
	err = nicvf_init_resources(nic);
	if (err)
		goto cleanup;

	/* Make sure queue initialization is written */
	wmb();

	nicvf_reg_write(nic, NIC_VF_INT, -1);
	/* Enable Qset err interrupt */
	nicvf_enable_intr(nic, NICVF_INTR_QS_ERR, 0);

	/* Enable completion queue interrupt */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++)
		nicvf_enable_intr(nic, NICVF_INTR_CQ, qidx);

	/* Enable RBDR threshold interrupt */
	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
		nicvf_enable_intr(nic, NICVF_INTR_RBDR, qidx);

	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);

	return 0;
cleanup:
	nicvf_disable_intr(nic, NICVF_INTR_MBOX, 0);
	nicvf_unregister_interrupts(nic);
napi_del:
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		cq_poll = nic->napi[qidx];
		if (!cq_poll)
			continue;
		napi_disable(&cq_poll->napi);
		netif_napi_del(&cq_poll->napi);
		kfree(cq_poll);
		nic->napi[qidx] = NULL;
	}
	return err;
}

static int nicvf_update_hw_max_frs(struct nicvf *nic, int mtu)
{
	union nic_mbx mbx = {};

	mbx.frs.msg = NIC_MBOX_MSG_SET_MAX_FRS;
	mbx.frs.max_frs = mtu;
	mbx.frs.vf_id = nic->vf_id;

	return nicvf_send_msg_to_pf(nic, &mbx);
}

static int nicvf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nicvf *nic = netdev_priv(netdev);

	if (new_mtu > NIC_HW_MAX_FRS)
		return -EINVAL;

	if (new_mtu < NIC_HW_MIN_FRS)
		return -EINVAL;

	if (nicvf_update_hw_max_frs(nic, new_mtu))
		return -EINVAL;
	netdev->mtu = new_mtu;
	nic->mtu = new_mtu;

	return 0;
}

static int nicvf_set_mac_address(struct net_device *netdev, void *p)
{
	struct sockaddr *addr = p;
	struct nicvf *nic = netdev_priv(netdev);

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);

	if (nic->msix_enabled)
		if (nicvf_hw_set_mac_addr(nic, netdev))
			return -EBUSY;

	return 0;
}

static void nicvf_read_bgx_stats(struct nicvf *nic, struct bgx_stats_msg *bgx)
{
	if (bgx->rx)
		nic->bgx_stats.rx_stats[bgx->idx] = bgx->stats;
	else
		nic->bgx_stats.tx_stats[bgx->idx] = bgx->stats;
}

void nicvf_update_lmac_stats(struct nicvf *nic)
{
	int stat = 0;
	union nic_mbx mbx = {};
	int timeout;

	if (!netif_running(nic->netdev))
		return;

	mbx.bgx_stats.msg = NIC_MBOX_MSG_BGX_STATS;
	mbx.bgx_stats.vf_id = nic->vf_id;
	/* Rx stats */
	mbx.bgx_stats.rx = 1;
	while (stat < BGX_RX_STATS_COUNT) {
		nic->bgx_stats_acked = 0;
		mbx.bgx_stats.idx = stat;
		nicvf_send_msg_to_pf(nic, &mbx);
		timeout = 0;
		while ((!nic->bgx_stats_acked) && (timeout < 10)) {
			msleep(2);
			timeout++;
		}
		stat++;
	}

	stat = 0;

	/* Tx stats */
	mbx.bgx_stats.rx = 0;
	while (stat < BGX_TX_STATS_COUNT) {
		nic->bgx_stats_acked = 0;
		mbx.bgx_stats.idx = stat;
		nicvf_send_msg_to_pf(nic, &mbx);
		timeout = 0;
		while ((!nic->bgx_stats_acked) && (timeout < 10)) {
			msleep(2);
			timeout++;
		}
		stat++;
	}
}

void nicvf_update_stats(struct nicvf *nic)
{
	int qidx;
	struct nicvf_hw_stats *stats = &nic->stats;
	struct nicvf_drv_stats *drv_stats = &nic->drv_stats;
	struct queue_set *qs = nic->qs;

#define GET_RX_STATS(reg) \
	nicvf_reg_read(nic, NIC_VNIC_RX_STAT_0_13 | (reg << 3))
#define GET_TX_STATS(reg) \
	nicvf_reg_read(nic, NIC_VNIC_TX_STAT_0_4 | (reg << 3))

	stats->rx_bytes_ok = GET_RX_STATS(RX_OCTS);
	stats->rx_ucast_frames_ok = GET_RX_STATS(RX_UCAST);
	stats->rx_bcast_frames_ok = GET_RX_STATS(RX_BCAST);
	stats->rx_mcast_frames_ok = GET_RX_STATS(RX_MCAST);
	stats->rx_fcs_errors = GET_RX_STATS(RX_FCS);
	stats->rx_l2_errors = GET_RX_STATS(RX_L2ERR);
	stats->rx_drop_red = GET_RX_STATS(RX_RED);
	stats->rx_drop_overrun = GET_RX_STATS(RX_ORUN);
	stats->rx_drop_bcast = GET_RX_STATS(RX_DRP_BCAST);
	stats->rx_drop_mcast = GET_RX_STATS(RX_DRP_MCAST);
	stats->rx_drop_l3_bcast = GET_RX_STATS(RX_DRP_L3BCAST);
	stats->rx_drop_l3_mcast = GET_RX_STATS(RX_DRP_L3MCAST);

	stats->tx_bytes_ok = GET_TX_STATS(TX_OCTS);
	stats->tx_ucast_frames_ok = GET_TX_STATS(TX_UCAST);
	stats->tx_bcast_frames_ok = GET_TX_STATS(TX_BCAST);
	stats->tx_mcast_frames_ok = GET_TX_STATS(TX_MCAST);
	stats->tx_drops = GET_TX_STATS(TX_DROP);

	drv_stats->rx_frames_ok = stats->rx_ucast_frames_ok +
				  stats->rx_bcast_frames_ok +
				  stats->rx_mcast_frames_ok;
	drv_stats->tx_frames_ok = stats->tx_ucast_frames_ok +
				  stats->tx_bcast_frames_ok +
				  stats->tx_mcast_frames_ok;
	drv_stats->rx_drops = stats->rx_drop_red +
			      stats->rx_drop_overrun;
	drv_stats->tx_drops = stats->tx_drops;

	/* Update RQ and SQ stats */
	for (qidx = 0; qidx < qs->rq_cnt; qidx++)
		nicvf_update_rq_stats(nic, qidx);
	for (qidx = 0; qidx < qs->sq_cnt; qidx++)
		nicvf_update_sq_stats(nic, qidx);
}

struct rtnl_link_stats64 *nicvf_get_stats64(struct net_device *netdev,
					    struct rtnl_link_stats64 *stats)
{
	struct nicvf *nic = netdev_priv(netdev);
	struct nicvf_hw_stats *hw_stats = &nic->stats;
	struct nicvf_drv_stats *drv_stats = &nic->drv_stats;

	nicvf_update_stats(nic);

	stats->rx_bytes = hw_stats->rx_bytes_ok;
	stats->rx_packets = drv_stats->rx_frames_ok;
	stats->rx_dropped = drv_stats->rx_drops;

	stats->tx_bytes = hw_stats->tx_bytes_ok;
	stats->tx_packets = drv_stats->tx_frames_ok;
	stats->tx_dropped = drv_stats->tx_drops;

	return stats;
}

static void nicvf_tx_timeout(struct net_device *dev)
{
	struct nicvf *nic = netdev_priv(dev);

	if (netif_msg_tx_err(nic))
		netdev_warn(dev, "%s: Transmit timed out, resetting\n",
			    dev->name);

	schedule_work(&nic->reset_task);
}

static void nicvf_reset_task(struct work_struct *work)
{
	struct nicvf *nic;

	nic = container_of(work, struct nicvf, reset_task);

	if (!netif_running(nic->netdev))
		return;

	nicvf_stop(nic->netdev);
	nicvf_open(nic->netdev);
	nic->netdev->trans_start = jiffies;
}

static const struct net_device_ops nicvf_netdev_ops = {
	.ndo_open		= nicvf_open,
	.ndo_stop		= nicvf_stop,
	.ndo_start_xmit		= nicvf_xmit,
	.ndo_change_mtu		= nicvf_change_mtu,
	.ndo_set_mac_address	= nicvf_set_mac_address,
	.ndo_get_stats64	= nicvf_get_stats64,
	.ndo_tx_timeout         = nicvf_tx_timeout,
};

static int nicvf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct nicvf *nic;
	struct queue_set *qs;
	int    err;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto err_release_regions;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "unable to get 48-bit DMA for consistent allocations\n");
		goto err_release_regions;
	}

	netdev = alloc_etherdev_mqs(sizeof(struct nicvf),
				    MAX_RCV_QUEUES_PER_QS,
				    MAX_SND_QUEUES_PER_QS);
	if (!netdev) {
		err = -ENOMEM;
		goto err_release_regions;
	}

	pci_set_drvdata(pdev, netdev);

	SET_NETDEV_DEV(netdev, &pdev->dev);

	nic = netdev_priv(netdev);
	nic->netdev = netdev;
	nic->pdev = pdev;

	/* MAP VF's configuration registers */
	nic->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!nic->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto err_free_netdev;
	}

	err = nicvf_set_qset_resources(nic);
	if (err)
		goto err_free_netdev;

	qs = nic->qs;

	err = nicvf_set_real_num_queues(netdev, qs->sq_cnt, qs->rq_cnt);
	if (err)
		goto err_free_netdev;

	/* Check if PF is alive and get MAC address for this VF */
	err = nicvf_register_misc_interrupt(nic);
	if (err)
		goto err_free_netdev;

	netdev->features |= (NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_SG |
			     NETIF_F_TSO | NETIF_F_GRO);
	netdev->hw_features = netdev->features;

	netdev->netdev_ops = &nicvf_netdev_ops;

	INIT_WORK(&nic->reset_task, nicvf_reset_task);

	err = register_netdev(netdev);
	if (err) {
		dev_err(dev, "Failed to register netdevice\n");
		goto err_unregister_interrupts;
	}

	nic->msg_enable = debug;

	nicvf_set_ethtool_ops(netdev);

	return 0;

err_unregister_interrupts:
	nicvf_unregister_interrupts(nic);
err_free_netdev:
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	return err;
}

static void nicvf_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nicvf *nic = netdev_priv(netdev);

	unregister_netdev(netdev);
	nicvf_unregister_interrupts(nic);
	pci_set_drvdata(pdev, NULL);
	free_netdev(netdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver nicvf_driver = {
	.name = DRV_NAME,
	.id_table = nicvf_id_table,
	.probe = nicvf_probe,
	.remove = nicvf_remove,
};

static int __init nicvf_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&nicvf_driver);
}

static void __exit nicvf_cleanup_module(void)
{
	pci_unregister_driver(&nicvf_driver);
}

module_init(nicvf_init_module);
module_exit(nicvf_cleanup_module);
