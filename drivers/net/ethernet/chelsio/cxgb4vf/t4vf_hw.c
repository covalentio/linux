/*
 * This file is part of the Chelsio T4 PCI-E SR-IOV Virtual Function Ethernet
 * driver for Linux.
 *
 * Copyright (c) 2009-2010 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/pci.h>

#include "t4vf_common.h"
#include "t4vf_defs.h"

#include "../cxgb4/t4_regs.h"
#include "../cxgb4/t4_values.h"
#include "../cxgb4/t4fw_api.h"

/*
 * Wait for the device to become ready (signified by our "who am I" register
 * returning a value other than all 1's).  Return an error if it doesn't
 * become ready ...
 */
int t4vf_wait_dev_ready(struct adapter *adapter)
{
	const u32 whoami = T4VF_PL_BASE_ADDR + PL_VF_WHOAMI;
	const u32 notready1 = 0xffffffff;
	const u32 notready2 = 0xeeeeeeee;
	u32 val;

	val = t4_read_reg(adapter, whoami);
	if (val != notready1 && val != notready2)
		return 0;
	msleep(500);
	val = t4_read_reg(adapter, whoami);
	if (val != notready1 && val != notready2)
		return 0;
	else
		return -EIO;
}

/*
 * Get the reply to a mailbox command and store it in @rpl in big-endian order
 * (since the firmware data structures are specified in a big-endian layout).
 */
static void get_mbox_rpl(struct adapter *adapter, __be64 *rpl, int size,
			 u32 mbox_data)
{
	for ( ; size; size -= 8, mbox_data += 8)
		*rpl++ = cpu_to_be64(t4_read_reg64(adapter, mbox_data));
}

/*
 * Dump contents of mailbox with a leading tag.
 */
static void dump_mbox(struct adapter *adapter, const char *tag, u32 mbox_data)
{
	dev_err(adapter->pdev_dev,
		"mbox %s: %llx %llx %llx %llx %llx %llx %llx %llx\n", tag,
		(unsigned long long)t4_read_reg64(adapter, mbox_data +  0),
		(unsigned long long)t4_read_reg64(adapter, mbox_data +  8),
		(unsigned long long)t4_read_reg64(adapter, mbox_data + 16),
		(unsigned long long)t4_read_reg64(adapter, mbox_data + 24),
		(unsigned long long)t4_read_reg64(adapter, mbox_data + 32),
		(unsigned long long)t4_read_reg64(adapter, mbox_data + 40),
		(unsigned long long)t4_read_reg64(adapter, mbox_data + 48),
		(unsigned long long)t4_read_reg64(adapter, mbox_data + 56));
}

/**
 *	t4vf_wr_mbox_core - send a command to FW through the mailbox
 *	@adapter: the adapter
 *	@cmd: the command to write
 *	@size: command length in bytes
 *	@rpl: where to optionally store the reply
 *	@sleep_ok: if true we may sleep while awaiting command completion
 *
 *	Sends the given command to FW through the mailbox and waits for the
 *	FW to execute the command.  If @rpl is not %NULL it is used to store
 *	the FW's reply to the command.  The command and its optional reply
 *	are of the same length.  FW can take up to 500 ms to respond.
 *	@sleep_ok determines whether we may sleep while awaiting the response.
 *	If sleeping is allowed we use progressive backoff otherwise we spin.
 *
 *	The return value is 0 on success or a negative errno on failure.  A
 *	failure can happen either because we are not able to execute the
 *	command or FW executes it but signals an error.  In the latter case
 *	the return value is the error code indicated by FW (negated).
 */
int t4vf_wr_mbox_core(struct adapter *adapter, const void *cmd, int size,
		      void *rpl, bool sleep_ok)
{
	static const int delay[] = {
		1, 1, 3, 5, 10, 10, 20, 50, 100
	};

	u32 v;
	int i, ms, delay_idx;
	const __be64 *p;
	u32 mbox_data = T4VF_MBDATA_BASE_ADDR;
	u32 mbox_ctl = T4VF_CIM_BASE_ADDR + CIM_VF_EXT_MAILBOX_CTRL;

	/*
	 * Commands must be multiples of 16 bytes in length and may not be
	 * larger than the size of the Mailbox Data register array.
	 */
	if ((size % 16) != 0 ||
	    size > NUM_CIM_VF_MAILBOX_DATA_INSTANCES * 4)
		return -EINVAL;

	/*
	 * Loop trying to get ownership of the mailbox.  Return an error
	 * if we can't gain ownership.
	 */
	v = MBOWNER_G(t4_read_reg(adapter, mbox_ctl));
	for (i = 0; v == MBOX_OWNER_NONE && i < 3; i++)
		v = MBOWNER_G(t4_read_reg(adapter, mbox_ctl));
	if (v != MBOX_OWNER_DRV)
		return v == MBOX_OWNER_FW ? -EBUSY : -ETIMEDOUT;

	/*
	 * Write the command array into the Mailbox Data register array and
	 * transfer ownership of the mailbox to the firmware.
	 *
	 * For the VFs, the Mailbox Data "registers" are actually backed by
	 * T4's "MA" interface rather than PL Registers (as is the case for
	 * the PFs).  Because these are in different coherency domains, the
	 * write to the VF's PL-register-backed Mailbox Control can race in
	 * front of the writes to the MA-backed VF Mailbox Data "registers".
	 * So we need to do a read-back on at least one byte of the VF Mailbox
	 * Data registers before doing the write to the VF Mailbox Control
	 * register.
	 */
	for (i = 0, p = cmd; i < size; i += 8)
		t4_write_reg64(adapter, mbox_data + i, be64_to_cpu(*p++));
	t4_read_reg(adapter, mbox_data);         /* flush write */

	t4_write_reg(adapter, mbox_ctl,
		     MBMSGVALID_F | MBOWNER_V(MBOX_OWNER_FW));
	t4_read_reg(adapter, mbox_ctl);          /* flush write */

	/*
	 * Spin waiting for firmware to acknowledge processing our command.
	 */
	delay_idx = 0;
	ms = delay[0];

	for (i = 0; i < FW_CMD_MAX_TIMEOUT; i += ms) {
		if (sleep_ok) {
			ms = delay[delay_idx];
			if (delay_idx < ARRAY_SIZE(delay) - 1)
				delay_idx++;
			msleep(ms);
		} else
			mdelay(ms);

		/*
		 * If we're the owner, see if this is the reply we wanted.
		 */
		v = t4_read_reg(adapter, mbox_ctl);
		if (MBOWNER_G(v) == MBOX_OWNER_DRV) {
			/*
			 * If the Message Valid bit isn't on, revoke ownership
			 * of the mailbox and continue waiting for our reply.
			 */
			if ((v & MBMSGVALID_F) == 0) {
				t4_write_reg(adapter, mbox_ctl,
					     MBOWNER_V(MBOX_OWNER_NONE));
				continue;
			}

			/*
			 * We now have our reply.  Extract the command return
			 * value, copy the reply back to our caller's buffer
			 * (if specified) and revoke ownership of the mailbox.
			 * We return the (negated) firmware command return
			 * code (this depends on FW_SUCCESS == 0).
			 */

			/* return value in low-order little-endian word */
			v = t4_read_reg(adapter, mbox_data);
			if (FW_CMD_RETVAL_G(v))
				dump_mbox(adapter, "FW Error", mbox_data);

			if (rpl) {
				/* request bit in high-order BE word */
				WARN_ON((be32_to_cpu(*(const __be32 *)cmd)
					 & FW_CMD_REQUEST_F) == 0);
				get_mbox_rpl(adapter, rpl, size, mbox_data);
				WARN_ON((be32_to_cpu(*(__be32 *)rpl)
					 & FW_CMD_REQUEST_F) != 0);
			}
			t4_write_reg(adapter, mbox_ctl,
				     MBOWNER_V(MBOX_OWNER_NONE));
			return -FW_CMD_RETVAL_G(v);
		}
	}

	/*
	 * We timed out.  Return the error ...
	 */
	dump_mbox(adapter, "FW Timeout", mbox_data);
	return -ETIMEDOUT;
}

/**
 *	hash_mac_addr - return the hash value of a MAC address
 *	@addr: the 48-bit Ethernet MAC address
 *
 *	Hashes a MAC address according to the hash function used by hardware
 *	inexact (hash) address matching.
 */
static int hash_mac_addr(const u8 *addr)
{
	u32 a = ((u32)addr[0] << 16) | ((u32)addr[1] << 8) | addr[2];
	u32 b = ((u32)addr[3] << 16) | ((u32)addr[4] << 8) | addr[5];
	a ^= b;
	a ^= (a >> 12);
	a ^= (a >> 6);
	return a & 0x3f;
}

#define ADVERT_MASK (FW_PORT_CAP_SPEED_100M | FW_PORT_CAP_SPEED_1G |\
		     FW_PORT_CAP_SPEED_10G | FW_PORT_CAP_SPEED_40G | \
		     FW_PORT_CAP_SPEED_100G | FW_PORT_CAP_ANEG)

/**
 *	init_link_config - initialize a link's SW state
 *	@lc: structure holding the link state
 *	@caps: link capabilities
 *
 *	Initializes the SW state maintained for each link, including the link's
 *	capabilities and default speed/flow-control/autonegotiation settings.
 */
static void init_link_config(struct link_config *lc, unsigned int caps)
{
	lc->supported = caps;
	lc->requested_speed = 0;
	lc->speed = 0;
	lc->requested_fc = lc->fc = PAUSE_RX | PAUSE_TX;
	if (lc->supported & FW_PORT_CAP_ANEG) {
		lc->advertising = lc->supported & ADVERT_MASK;
		lc->autoneg = AUTONEG_ENABLE;
		lc->requested_fc |= PAUSE_AUTONEG;
	} else {
		lc->advertising = 0;
		lc->autoneg = AUTONEG_DISABLE;
	}
}

/**
 *	t4vf_port_init - initialize port hardware/software state
 *	@adapter: the adapter
 *	@pidx: the adapter port index
 */
int t4vf_port_init(struct adapter *adapter, int pidx)
{
	struct port_info *pi = adap2pinfo(adapter, pidx);
	struct fw_vi_cmd vi_cmd, vi_rpl;
	struct fw_port_cmd port_cmd, port_rpl;
	int v;

	/*
	 * Execute a VI Read command to get our Virtual Interface information
	 * like MAC address, etc.
	 */
	memset(&vi_cmd, 0, sizeof(vi_cmd));
	vi_cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_VI_CMD) |
				       FW_CMD_REQUEST_F |
				       FW_CMD_READ_F);
	vi_cmd.alloc_to_len16 = cpu_to_be32(FW_LEN16(vi_cmd));
	vi_cmd.type_viid = cpu_to_be16(FW_VI_CMD_VIID_V(pi->viid));
	v = t4vf_wr_mbox(adapter, &vi_cmd, sizeof(vi_cmd), &vi_rpl);
	if (v)
		return v;

	BUG_ON(pi->port_id != FW_VI_CMD_PORTID_G(vi_rpl.portid_pkd));
	pi->rss_size = FW_VI_CMD_RSSSIZE_G(be16_to_cpu(vi_rpl.rsssize_pkd));
	t4_os_set_hw_addr(adapter, pidx, vi_rpl.mac);

	/*
	 * If we don't have read access to our port information, we're done
	 * now.  Otherwise, execute a PORT Read command to get it ...
	 */
	if (!(adapter->params.vfres.r_caps & FW_CMD_CAP_PORT))
		return 0;

	memset(&port_cmd, 0, sizeof(port_cmd));
	port_cmd.op_to_portid = cpu_to_be32(FW_CMD_OP_V(FW_PORT_CMD) |
					    FW_CMD_REQUEST_F |
					    FW_CMD_READ_F |
					    FW_PORT_CMD_PORTID_V(pi->port_id));
	port_cmd.action_to_len16 =
		cpu_to_be32(FW_PORT_CMD_ACTION_V(FW_PORT_ACTION_GET_PORT_INFO) |
			    FW_LEN16(port_cmd));
	v = t4vf_wr_mbox(adapter, &port_cmd, sizeof(port_cmd), &port_rpl);
	if (v)
		return v;

	v = be32_to_cpu(port_rpl.u.info.lstatus_to_modtype);
	pi->mdio_addr = (v & FW_PORT_CMD_MDIOCAP_F) ?
			FW_PORT_CMD_MDIOADDR_G(v) : -1;
	pi->port_type = FW_PORT_CMD_PTYPE_G(v);
	pi->mod_type = FW_PORT_MOD_TYPE_NA;

	init_link_config(&pi->link_cfg, be16_to_cpu(port_rpl.u.info.pcap));

	return 0;
}

/**
 *      t4vf_fw_reset - issue a reset to FW
 *      @adapter: the adapter
 *
 *	Issues a reset command to FW.  For a Physical Function this would
 *	result in the Firmware resetting all of its state.  For a Virtual
 *	Function this just resets the state associated with the VF.
 */
int t4vf_fw_reset(struct adapter *adapter)
{
	struct fw_reset_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_write = cpu_to_be32(FW_CMD_OP_V(FW_RESET_CMD) |
				      FW_CMD_WRITE_F);
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));
	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_query_params - query FW or device parameters
 *	@adapter: the adapter
 *	@nparams: the number of parameters
 *	@params: the parameter names
 *	@vals: the parameter values
 *
 *	Reads the values of firmware or device parameters.  Up to 7 parameters
 *	can be queried at once.
 */
static int t4vf_query_params(struct adapter *adapter, unsigned int nparams,
			     const u32 *params, u32 *vals)
{
	int i, ret;
	struct fw_params_cmd cmd, rpl;
	struct fw_params_param *p;
	size_t len16;

	if (nparams > 7)
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_PARAMS_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_READ_F);
	len16 = DIV_ROUND_UP(offsetof(struct fw_params_cmd,
				      param[nparams].mnem), 16);
	cmd.retval_len16 = cpu_to_be32(FW_CMD_LEN16_V(len16));
	for (i = 0, p = &cmd.param[0]; i < nparams; i++, p++)
		p->mnem = htonl(*params++);

	ret = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
	if (ret == 0)
		for (i = 0, p = &rpl.param[0]; i < nparams; i++, p++)
			*vals++ = be32_to_cpu(p->val);
	return ret;
}

/**
 *	t4vf_set_params - sets FW or device parameters
 *	@adapter: the adapter
 *	@nparams: the number of parameters
 *	@params: the parameter names
 *	@vals: the parameter values
 *
 *	Sets the values of firmware or device parameters.  Up to 7 parameters
 *	can be specified at once.
 */
int t4vf_set_params(struct adapter *adapter, unsigned int nparams,
		    const u32 *params, const u32 *vals)
{
	int i;
	struct fw_params_cmd cmd;
	struct fw_params_param *p;
	size_t len16;

	if (nparams > 7)
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_PARAMS_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_WRITE_F);
	len16 = DIV_ROUND_UP(offsetof(struct fw_params_cmd,
				      param[nparams]), 16);
	cmd.retval_len16 = cpu_to_be32(FW_CMD_LEN16_V(len16));
	for (i = 0, p = &cmd.param[0]; i < nparams; i++, p++) {
		p->mnem = cpu_to_be32(*params++);
		p->val = cpu_to_be32(*vals++);
	}

	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_bar2_sge_qregs - return BAR2 SGE Queue register information
 *	@adapter: the adapter
 *	@qid: the Queue ID
 *	@qtype: the Ingress or Egress type for @qid
 *	@pbar2_qoffset: BAR2 Queue Offset
 *	@pbar2_qid: BAR2 Queue ID or 0 for Queue ID inferred SGE Queues
 *
 *	Returns the BAR2 SGE Queue Registers information associated with the
 *	indicated Absolute Queue ID.  These are passed back in return value
 *	pointers.  @qtype should be T4_BAR2_QTYPE_EGRESS for Egress Queue
 *	and T4_BAR2_QTYPE_INGRESS for Ingress Queues.
 *
 *	This may return an error which indicates that BAR2 SGE Queue
 *	registers aren't available.  If an error is not returned, then the
 *	following values are returned:
 *
 *	  *@pbar2_qoffset: the BAR2 Offset of the @qid Registers
 *	  *@pbar2_qid: the BAR2 SGE Queue ID or 0 of @qid
 *
 *	If the returned BAR2 Queue ID is 0, then BAR2 SGE registers which
 *	require the "Inferred Queue ID" ability may be used.  E.g. the
 *	Write Combining Doorbell Buffer. If the BAR2 Queue ID is not 0,
 *	then these "Inferred Queue ID" register may not be used.
 */
int t4vf_bar2_sge_qregs(struct adapter *adapter,
			unsigned int qid,
			enum t4_bar2_qtype qtype,
			u64 *pbar2_qoffset,
			unsigned int *pbar2_qid)
{
	unsigned int page_shift, page_size, qpp_shift, qpp_mask;
	u64 bar2_page_offset, bar2_qoffset;
	unsigned int bar2_qid, bar2_qid_offset, bar2_qinferred;

	/* T4 doesn't support BAR2 SGE Queue registers.
	 */
	if (is_t4(adapter->params.chip))
		return -EINVAL;

	/* Get our SGE Page Size parameters.
	 */
	page_shift = adapter->params.sge.sge_vf_hps + 10;
	page_size = 1 << page_shift;

	/* Get the right Queues per Page parameters for our Queue.
	 */
	qpp_shift = (qtype == T4_BAR2_QTYPE_EGRESS
		     ? adapter->params.sge.sge_vf_eq_qpp
		     : adapter->params.sge.sge_vf_iq_qpp);
	qpp_mask = (1 << qpp_shift) - 1;

	/* Calculate the basics of the BAR2 SGE Queue register area:
	 *  o The BAR2 page the Queue registers will be in.
	 *  o The BAR2 Queue ID.
	 *  o The BAR2 Queue ID Offset into the BAR2 page.
	 */
	bar2_page_offset = ((u64)(qid >> qpp_shift) << page_shift);
	bar2_qid = qid & qpp_mask;
	bar2_qid_offset = bar2_qid * SGE_UDB_SIZE;

	/* If the BAR2 Queue ID Offset is less than the Page Size, then the
	 * hardware will infer the Absolute Queue ID simply from the writes to
	 * the BAR2 Queue ID Offset within the BAR2 Page (and we need to use a
	 * BAR2 Queue ID of 0 for those writes).  Otherwise, we'll simply
	 * write to the first BAR2 SGE Queue Area within the BAR2 Page with
	 * the BAR2 Queue ID and the hardware will infer the Absolute Queue ID
	 * from the BAR2 Page and BAR2 Queue ID.
	 *
	 * One important censequence of this is that some BAR2 SGE registers
	 * have a "Queue ID" field and we can write the BAR2 SGE Queue ID
	 * there.  But other registers synthesize the SGE Queue ID purely
	 * from the writes to the registers -- the Write Combined Doorbell
	 * Buffer is a good example.  These BAR2 SGE Registers are only
	 * available for those BAR2 SGE Register areas where the SGE Absolute
	 * Queue ID can be inferred from simple writes.
	 */
	bar2_qoffset = bar2_page_offset;
	bar2_qinferred = (bar2_qid_offset < page_size);
	if (bar2_qinferred) {
		bar2_qoffset += bar2_qid_offset;
		bar2_qid = 0;
	}

	*pbar2_qoffset = bar2_qoffset;
	*pbar2_qid = bar2_qid;
	return 0;
}

/**
 *	t4vf_get_sge_params - retrieve adapter Scatter gather Engine parameters
 *	@adapter: the adapter
 *
 *	Retrieves various core SGE parameters in the form of hardware SGE
 *	register values.  The caller is responsible for decoding these as
 *	needed.  The SGE parameters are stored in @adapter->params.sge.
 */
int t4vf_get_sge_params(struct adapter *adapter)
{
	struct sge_params *sge_params = &adapter->params.sge;
	u32 params[7], vals[7];
	int v;

	params[0] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_CONTROL_A));
	params[1] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_HOST_PAGE_SIZE_A));
	params[2] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_FL_BUFFER_SIZE0_A));
	params[3] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_FL_BUFFER_SIZE1_A));
	params[4] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_TIMER_VALUE_0_AND_1_A));
	params[5] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_TIMER_VALUE_2_AND_3_A));
	params[6] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_TIMER_VALUE_4_AND_5_A));
	v = t4vf_query_params(adapter, 7, params, vals);
	if (v)
		return v;
	sge_params->sge_control = vals[0];
	sge_params->sge_host_page_size = vals[1];
	sge_params->sge_fl_buffer_size[0] = vals[2];
	sge_params->sge_fl_buffer_size[1] = vals[3];
	sge_params->sge_timer_value_0_and_1 = vals[4];
	sge_params->sge_timer_value_2_and_3 = vals[5];
	sge_params->sge_timer_value_4_and_5 = vals[6];

	/* T4 uses a single control field to specify both the PCIe Padding and
	 * Packing Boundary.  T5 introduced the ability to specify these
	 * separately with the Padding Boundary in SGE_CONTROL and and Packing
	 * Boundary in SGE_CONTROL2.  So for T5 and later we need to grab
	 * SGE_CONTROL in order to determine how ingress packet data will be
	 * laid out in Packed Buffer Mode.  Unfortunately, older versions of
	 * the firmware won't let us retrieve SGE_CONTROL2 so if we get a
	 * failure grabbing it we throw an error since we can't figure out the
	 * right value.
	 */
	if (!is_t4(adapter->params.chip)) {
		params[0] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
			     FW_PARAMS_PARAM_XYZ_V(SGE_CONTROL2_A));
		v = t4vf_query_params(adapter, 1, params, vals);
		if (v != FW_SUCCESS) {
			dev_err(adapter->pdev_dev,
				"Unable to get SGE Control2; "
				"probably old firmware.\n");
			return v;
		}
		sge_params->sge_control2 = vals[0];
	}

	params[0] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_INGRESS_RX_THRESHOLD_A));
	params[1] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
		     FW_PARAMS_PARAM_XYZ_V(SGE_CONM_CTRL_A));
	v = t4vf_query_params(adapter, 2, params, vals);
	if (v)
		return v;
	sge_params->sge_ingress_rx_threshold = vals[0];
	sge_params->sge_congestion_control = vals[1];

	/* For T5 and later we want to use the new BAR2 Doorbells.
	 * Unfortunately, older firmware didn't allow the this register to be
	 * read.
	 */
	if (!is_t4(adapter->params.chip)) {
		u32 whoami;
		unsigned int pf, s_hps, s_qpp;

		params[0] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
			     FW_PARAMS_PARAM_XYZ_V(
				     SGE_EGRESS_QUEUES_PER_PAGE_VF_A));
		params[1] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_REG) |
			     FW_PARAMS_PARAM_XYZ_V(
				     SGE_INGRESS_QUEUES_PER_PAGE_VF_A));
		v = t4vf_query_params(adapter, 2, params, vals);
		if (v != FW_SUCCESS) {
			dev_warn(adapter->pdev_dev,
				 "Unable to get VF SGE Queues/Page; "
				 "probably old firmware.\n");
			return v;
		}
		sge_params->sge_egress_queues_per_page = vals[0];
		sge_params->sge_ingress_queues_per_page = vals[1];

		/* We need the Queues/Page for our VF.  This is based on the
		 * PF from which we're instantiated and is indexed in the
		 * register we just read. Do it once here so other code in
		 * the driver can just use it.
		 */
		whoami = t4_read_reg(adapter,
				     T4VF_PL_BASE_ADDR + PL_VF_WHOAMI_A);
		pf = SOURCEPF_G(whoami);

		s_hps = (HOSTPAGESIZEPF0_S +
			 (HOSTPAGESIZEPF1_S - HOSTPAGESIZEPF0_S) * pf);
		sge_params->sge_vf_hps =
			((sge_params->sge_host_page_size >> s_hps)
			 & HOSTPAGESIZEPF0_M);

		s_qpp = (QUEUESPERPAGEPF0_S +
			 (QUEUESPERPAGEPF1_S - QUEUESPERPAGEPF0_S) * pf);
		sge_params->sge_vf_eq_qpp =
			((sge_params->sge_egress_queues_per_page >> s_qpp)
			 & QUEUESPERPAGEPF0_M);
		sge_params->sge_vf_iq_qpp =
			((sge_params->sge_ingress_queues_per_page >> s_qpp)
			 & QUEUESPERPAGEPF0_M);
	}

	return 0;
}

/**
 *	t4vf_get_vpd_params - retrieve device VPD paremeters
 *	@adapter: the adapter
 *
 *	Retrives various device Vital Product Data parameters.  The parameters
 *	are stored in @adapter->params.vpd.
 */
int t4vf_get_vpd_params(struct adapter *adapter)
{
	struct vpd_params *vpd_params = &adapter->params.vpd;
	u32 params[7], vals[7];
	int v;

	params[0] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_DEV) |
		     FW_PARAMS_PARAM_X_V(FW_PARAMS_PARAM_DEV_CCLK));
	v = t4vf_query_params(adapter, 1, params, vals);
	if (v)
		return v;
	vpd_params->cclk = vals[0];

	return 0;
}

/**
 *	t4vf_get_dev_params - retrieve device paremeters
 *	@adapter: the adapter
 *
 *	Retrives various device parameters.  The parameters are stored in
 *	@adapter->params.dev.
 */
int t4vf_get_dev_params(struct adapter *adapter)
{
	struct dev_params *dev_params = &adapter->params.dev;
	u32 params[7], vals[7];
	int v;

	params[0] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_DEV) |
		     FW_PARAMS_PARAM_X_V(FW_PARAMS_PARAM_DEV_FWREV));
	params[1] = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_DEV) |
		     FW_PARAMS_PARAM_X_V(FW_PARAMS_PARAM_DEV_TPREV));
	v = t4vf_query_params(adapter, 2, params, vals);
	if (v)
		return v;
	dev_params->fwrev = vals[0];
	dev_params->tprev = vals[1];

	return 0;
}

/**
 *	t4vf_get_rss_glb_config - retrieve adapter RSS Global Configuration
 *	@adapter: the adapter
 *
 *	Retrieves global RSS mode and parameters with which we have to live
 *	and stores them in the @adapter's RSS parameters.
 */
int t4vf_get_rss_glb_config(struct adapter *adapter)
{
	struct rss_params *rss = &adapter->params.rss;
	struct fw_rss_glb_config_cmd cmd, rpl;
	int v;

	/*
	 * Execute an RSS Global Configuration read command to retrieve
	 * our RSS configuration.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_write = cpu_to_be32(FW_CMD_OP_V(FW_RSS_GLB_CONFIG_CMD) |
				      FW_CMD_REQUEST_F |
				      FW_CMD_READ_F);
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));
	v = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
	if (v)
		return v;

	/*
	 * Transate the big-endian RSS Global Configuration into our
	 * cpu-endian format based on the RSS mode.  We also do first level
	 * filtering at this point to weed out modes which don't support
	 * VF Drivers ...
	 */
	rss->mode = FW_RSS_GLB_CONFIG_CMD_MODE_G(
			be32_to_cpu(rpl.u.manual.mode_pkd));
	switch (rss->mode) {
	case FW_RSS_GLB_CONFIG_CMD_MODE_BASICVIRTUAL: {
		u32 word = be32_to_cpu(
				rpl.u.basicvirtual.synmapen_to_hashtoeplitz);

		rss->u.basicvirtual.synmapen =
			((word & FW_RSS_GLB_CONFIG_CMD_SYNMAPEN_F) != 0);
		rss->u.basicvirtual.syn4tupenipv6 =
			((word & FW_RSS_GLB_CONFIG_CMD_SYN4TUPENIPV6_F) != 0);
		rss->u.basicvirtual.syn2tupenipv6 =
			((word & FW_RSS_GLB_CONFIG_CMD_SYN2TUPENIPV6_F) != 0);
		rss->u.basicvirtual.syn4tupenipv4 =
			((word & FW_RSS_GLB_CONFIG_CMD_SYN4TUPENIPV4_F) != 0);
		rss->u.basicvirtual.syn2tupenipv4 =
			((word & FW_RSS_GLB_CONFIG_CMD_SYN2TUPENIPV4_F) != 0);

		rss->u.basicvirtual.ofdmapen =
			((word & FW_RSS_GLB_CONFIG_CMD_OFDMAPEN_F) != 0);

		rss->u.basicvirtual.tnlmapen =
			((word & FW_RSS_GLB_CONFIG_CMD_TNLMAPEN_F) != 0);
		rss->u.basicvirtual.tnlalllookup =
			((word  & FW_RSS_GLB_CONFIG_CMD_TNLALLLKP_F) != 0);

		rss->u.basicvirtual.hashtoeplitz =
			((word & FW_RSS_GLB_CONFIG_CMD_HASHTOEPLITZ_F) != 0);

		/* we need at least Tunnel Map Enable to be set */
		if (!rss->u.basicvirtual.tnlmapen)
			return -EINVAL;
		break;
	}

	default:
		/* all unknown/unsupported RSS modes result in an error */
		return -EINVAL;
	}

	return 0;
}

/**
 *	t4vf_get_vfres - retrieve VF resource limits
 *	@adapter: the adapter
 *
 *	Retrieves configured resource limits and capabilities for a virtual
 *	function.  The results are stored in @adapter->vfres.
 */
int t4vf_get_vfres(struct adapter *adapter)
{
	struct vf_resources *vfres = &adapter->params.vfres;
	struct fw_pfvf_cmd cmd, rpl;
	int v;
	u32 word;

	/*
	 * Execute PFVF Read command to get VF resource limits; bail out early
	 * with error on command failure.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_PFVF_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_READ_F);
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));
	v = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
	if (v)
		return v;

	/*
	 * Extract VF resource limits and return success.
	 */
	word = be32_to_cpu(rpl.niqflint_niq);
	vfres->niqflint = FW_PFVF_CMD_NIQFLINT_G(word);
	vfres->niq = FW_PFVF_CMD_NIQ_G(word);

	word = be32_to_cpu(rpl.type_to_neq);
	vfres->neq = FW_PFVF_CMD_NEQ_G(word);
	vfres->pmask = FW_PFVF_CMD_PMASK_G(word);

	word = be32_to_cpu(rpl.tc_to_nexactf);
	vfres->tc = FW_PFVF_CMD_TC_G(word);
	vfres->nvi = FW_PFVF_CMD_NVI_G(word);
	vfres->nexactf = FW_PFVF_CMD_NEXACTF_G(word);

	word = be32_to_cpu(rpl.r_caps_to_nethctrl);
	vfres->r_caps = FW_PFVF_CMD_R_CAPS_G(word);
	vfres->wx_caps = FW_PFVF_CMD_WX_CAPS_G(word);
	vfres->nethctrl = FW_PFVF_CMD_NETHCTRL_G(word);

	return 0;
}

/**
 *	t4vf_read_rss_vi_config - read a VI's RSS configuration
 *	@adapter: the adapter
 *	@viid: Virtual Interface ID
 *	@config: pointer to host-native VI RSS Configuration buffer
 *
 *	Reads the Virtual Interface's RSS configuration information and
 *	translates it into CPU-native format.
 */
int t4vf_read_rss_vi_config(struct adapter *adapter, unsigned int viid,
			    union rss_vi_config *config)
{
	struct fw_rss_vi_config_cmd cmd, rpl;
	int v;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_RSS_VI_CONFIG_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_READ_F |
				     FW_RSS_VI_CONFIG_CMD_VIID(viid));
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));
	v = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
	if (v)
		return v;

	switch (adapter->params.rss.mode) {
	case FW_RSS_GLB_CONFIG_CMD_MODE_BASICVIRTUAL: {
		u32 word = be32_to_cpu(rpl.u.basicvirtual.defaultq_to_udpen);

		config->basicvirtual.ip6fourtupen =
			((word & FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN_F) != 0);
		config->basicvirtual.ip6twotupen =
			((word & FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN_F) != 0);
		config->basicvirtual.ip4fourtupen =
			((word & FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN_F) != 0);
		config->basicvirtual.ip4twotupen =
			((word & FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN_F) != 0);
		config->basicvirtual.udpen =
			((word & FW_RSS_VI_CONFIG_CMD_UDPEN_F) != 0);
		config->basicvirtual.defaultq =
			FW_RSS_VI_CONFIG_CMD_DEFAULTQ_G(word);
		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 *	t4vf_write_rss_vi_config - write a VI's RSS configuration
 *	@adapter: the adapter
 *	@viid: Virtual Interface ID
 *	@config: pointer to host-native VI RSS Configuration buffer
 *
 *	Write the Virtual Interface's RSS configuration information
 *	(translating it into firmware-native format before writing).
 */
int t4vf_write_rss_vi_config(struct adapter *adapter, unsigned int viid,
			     union rss_vi_config *config)
{
	struct fw_rss_vi_config_cmd cmd, rpl;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_RSS_VI_CONFIG_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_WRITE_F |
				     FW_RSS_VI_CONFIG_CMD_VIID(viid));
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));
	switch (adapter->params.rss.mode) {
	case FW_RSS_GLB_CONFIG_CMD_MODE_BASICVIRTUAL: {
		u32 word = 0;

		if (config->basicvirtual.ip6fourtupen)
			word |= FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN_F;
		if (config->basicvirtual.ip6twotupen)
			word |= FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN_F;
		if (config->basicvirtual.ip4fourtupen)
			word |= FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN_F;
		if (config->basicvirtual.ip4twotupen)
			word |= FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN_F;
		if (config->basicvirtual.udpen)
			word |= FW_RSS_VI_CONFIG_CMD_UDPEN_F;
		word |= FW_RSS_VI_CONFIG_CMD_DEFAULTQ_V(
				config->basicvirtual.defaultq);
		cmd.u.basicvirtual.defaultq_to_udpen = cpu_to_be32(word);
		break;
	}

	default:
		return -EINVAL;
	}

	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
}

/**
 *	t4vf_config_rss_range - configure a portion of the RSS mapping table
 *	@adapter: the adapter
 *	@viid: Virtual Interface of RSS Table Slice
 *	@start: starting entry in the table to write
 *	@n: how many table entries to write
 *	@rspq: values for the "Response Queue" (Ingress Queue) lookup table
 *	@nrspq: number of values in @rspq
 *
 *	Programs the selected part of the VI's RSS mapping table with the
 *	provided values.  If @nrspq < @n the supplied values are used repeatedly
 *	until the full table range is populated.
 *
 *	The caller must ensure the values in @rspq are in the range 0..1023.
 */
int t4vf_config_rss_range(struct adapter *adapter, unsigned int viid,
			  int start, int n, const u16 *rspq, int nrspq)
{
	const u16 *rsp = rspq;
	const u16 *rsp_end = rspq+nrspq;
	struct fw_rss_ind_tbl_cmd cmd;

	/*
	 * Initialize firmware command template to write the RSS table.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_RSS_IND_TBL_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_WRITE_F |
				     FW_RSS_IND_TBL_CMD_VIID_V(viid));
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));

	/*
	 * Each firmware RSS command can accommodate up to 32 RSS Ingress
	 * Queue Identifiers.  These Ingress Queue IDs are packed three to
	 * a 32-bit word as 10-bit values with the upper remaining 2 bits
	 * reserved.
	 */
	while (n > 0) {
		__be32 *qp = &cmd.iq0_to_iq2;
		int nq = min(n, 32);
		int ret;

		/*
		 * Set up the firmware RSS command header to send the next
		 * "nq" Ingress Queue IDs to the firmware.
		 */
		cmd.niqid = cpu_to_be16(nq);
		cmd.startidx = cpu_to_be16(start);

		/*
		 * "nq" more done for the start of the next loop.
		 */
		start += nq;
		n -= nq;

		/*
		 * While there are still Ingress Queue IDs to stuff into the
		 * current firmware RSS command, retrieve them from the
		 * Ingress Queue ID array and insert them into the command.
		 */
		while (nq > 0) {
			/*
			 * Grab up to the next 3 Ingress Queue IDs (wrapping
			 * around the Ingress Queue ID array if necessary) and
			 * insert them into the firmware RSS command at the
			 * current 3-tuple position within the commad.
			 */
			u16 qbuf[3];
			u16 *qbp = qbuf;
			int nqbuf = min(3, nq);

			nq -= nqbuf;
			qbuf[0] = qbuf[1] = qbuf[2] = 0;
			while (nqbuf) {
				nqbuf--;
				*qbp++ = *rsp++;
				if (rsp >= rsp_end)
					rsp = rspq;
			}
			*qp++ = cpu_to_be32(FW_RSS_IND_TBL_CMD_IQ0_V(qbuf[0]) |
					    FW_RSS_IND_TBL_CMD_IQ1_V(qbuf[1]) |
					    FW_RSS_IND_TBL_CMD_IQ2_V(qbuf[2]));
		}

		/*
		 * Send this portion of the RRS table update to the firmware;
		 * bail out on any errors.
		 */
		ret = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
		if (ret)
			return ret;
	}
	return 0;
}

/**
 *	t4vf_alloc_vi - allocate a virtual interface on a port
 *	@adapter: the adapter
 *	@port_id: physical port associated with the VI
 *
 *	Allocate a new Virtual Interface and bind it to the indicated
 *	physical port.  Return the new Virtual Interface Identifier on
 *	success, or a [negative] error number on failure.
 */
int t4vf_alloc_vi(struct adapter *adapter, int port_id)
{
	struct fw_vi_cmd cmd, rpl;
	int v;

	/*
	 * Execute a VI command to allocate Virtual Interface and return its
	 * VIID.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_VI_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_WRITE_F |
				    FW_CMD_EXEC_F);
	cmd.alloc_to_len16 = cpu_to_be32(FW_LEN16(cmd) |
					 FW_VI_CMD_ALLOC_F);
	cmd.portid_pkd = FW_VI_CMD_PORTID_V(port_id);
	v = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
	if (v)
		return v;

	return FW_VI_CMD_VIID_G(be16_to_cpu(rpl.type_viid));
}

/**
 *	t4vf_free_vi -- free a virtual interface
 *	@adapter: the adapter
 *	@viid: the virtual interface identifier
 *
 *	Free a previously allocated Virtual Interface.  Return an error on
 *	failure.
 */
int t4vf_free_vi(struct adapter *adapter, int viid)
{
	struct fw_vi_cmd cmd;

	/*
	 * Execute a VI command to free the Virtual Interface.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_VI_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_EXEC_F);
	cmd.alloc_to_len16 = cpu_to_be32(FW_LEN16(cmd) |
					 FW_VI_CMD_FREE_F);
	cmd.type_viid = cpu_to_be16(FW_VI_CMD_VIID_V(viid));
	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_enable_vi - enable/disable a virtual interface
 *	@adapter: the adapter
 *	@viid: the Virtual Interface ID
 *	@rx_en: 1=enable Rx, 0=disable Rx
 *	@tx_en: 1=enable Tx, 0=disable Tx
 *
 *	Enables/disables a virtual interface.
 */
int t4vf_enable_vi(struct adapter *adapter, unsigned int viid,
		   bool rx_en, bool tx_en)
{
	struct fw_vi_enable_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_ENABLE_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_EXEC_F |
				     FW_VI_ENABLE_CMD_VIID_V(viid));
	cmd.ien_to_len16 = cpu_to_be32(FW_VI_ENABLE_CMD_IEN_V(rx_en) |
				       FW_VI_ENABLE_CMD_EEN_V(tx_en) |
				       FW_LEN16(cmd));
	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_identify_port - identify a VI's port by blinking its LED
 *	@adapter: the adapter
 *	@viid: the Virtual Interface ID
 *	@nblinks: how many times to blink LED at 2.5 Hz
 *
 *	Identifies a VI's port by blinking its LED.
 */
int t4vf_identify_port(struct adapter *adapter, unsigned int viid,
		       unsigned int nblinks)
{
	struct fw_vi_enable_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_ENABLE_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_EXEC_F |
				     FW_VI_ENABLE_CMD_VIID_V(viid));
	cmd.ien_to_len16 = cpu_to_be32(FW_VI_ENABLE_CMD_LED_F |
				       FW_LEN16(cmd));
	cmd.blinkdur = cpu_to_be16(nblinks);
	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_set_rxmode - set Rx properties of a virtual interface
 *	@adapter: the adapter
 *	@viid: the VI id
 *	@mtu: the new MTU or -1 for no change
 *	@promisc: 1 to enable promiscuous mode, 0 to disable it, -1 no change
 *	@all_multi: 1 to enable all-multi mode, 0 to disable it, -1 no change
 *	@bcast: 1 to enable broadcast Rx, 0 to disable it, -1 no change
 *	@vlanex: 1 to enable hardware VLAN Tag extraction, 0 to disable it,
 *		-1 no change
 *
 *	Sets Rx properties of a virtual interface.
 */
int t4vf_set_rxmode(struct adapter *adapter, unsigned int viid,
		    int mtu, int promisc, int all_multi, int bcast, int vlanex,
		    bool sleep_ok)
{
	struct fw_vi_rxmode_cmd cmd;

	/* convert to FW values */
	if (mtu < 0)
		mtu = FW_VI_RXMODE_CMD_MTU_M;
	if (promisc < 0)
		promisc = FW_VI_RXMODE_CMD_PROMISCEN_M;
	if (all_multi < 0)
		all_multi = FW_VI_RXMODE_CMD_ALLMULTIEN_M;
	if (bcast < 0)
		bcast = FW_VI_RXMODE_CMD_BROADCASTEN_M;
	if (vlanex < 0)
		vlanex = FW_VI_RXMODE_CMD_VLANEXEN_M;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_RXMODE_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_WRITE_F |
				     FW_VI_RXMODE_CMD_VIID_V(viid));
	cmd.retval_len16 = cpu_to_be32(FW_LEN16(cmd));
	cmd.mtu_to_vlanexen =
		cpu_to_be32(FW_VI_RXMODE_CMD_MTU_V(mtu) |
			    FW_VI_RXMODE_CMD_PROMISCEN_V(promisc) |
			    FW_VI_RXMODE_CMD_ALLMULTIEN_V(all_multi) |
			    FW_VI_RXMODE_CMD_BROADCASTEN_V(bcast) |
			    FW_VI_RXMODE_CMD_VLANEXEN_V(vlanex));
	return t4vf_wr_mbox_core(adapter, &cmd, sizeof(cmd), NULL, sleep_ok);
}

/**
 *	t4vf_alloc_mac_filt - allocates exact-match filters for MAC addresses
 *	@adapter: the adapter
 *	@viid: the Virtual Interface Identifier
 *	@free: if true any existing filters for this VI id are first removed
 *	@naddr: the number of MAC addresses to allocate filters for (up to 7)
 *	@addr: the MAC address(es)
 *	@idx: where to store the index of each allocated filter
 *	@hash: pointer to hash address filter bitmap
 *	@sleep_ok: call is allowed to sleep
 *
 *	Allocates an exact-match filter for each of the supplied addresses and
 *	sets it to the corresponding address.  If @idx is not %NULL it should
 *	have at least @naddr entries, each of which will be set to the index of
 *	the filter allocated for the corresponding MAC address.  If a filter
 *	could not be allocated for an address its index is set to 0xffff.
 *	If @hash is not %NULL addresses that fail to allocate an exact filter
 *	are hashed and update the hash filter bitmap pointed at by @hash.
 *
 *	Returns a negative error number or the number of filters allocated.
 */
int t4vf_alloc_mac_filt(struct adapter *adapter, unsigned int viid, bool free,
			unsigned int naddr, const u8 **addr, u16 *idx,
			u64 *hash, bool sleep_ok)
{
	int offset, ret = 0;
	unsigned nfilters = 0;
	unsigned int rem = naddr;
	struct fw_vi_mac_cmd cmd, rpl;
	unsigned int max_naddr = is_t4(adapter->params.chip) ?
				 NUM_MPS_CLS_SRAM_L_INSTANCES :
				 NUM_MPS_T5_CLS_SRAM_L_INSTANCES;

	if (naddr > max_naddr)
		return -EINVAL;

	for (offset = 0; offset < naddr; /**/) {
		unsigned int fw_naddr = (rem < ARRAY_SIZE(cmd.u.exact)
					 ? rem
					 : ARRAY_SIZE(cmd.u.exact));
		size_t len16 = DIV_ROUND_UP(offsetof(struct fw_vi_mac_cmd,
						     u.exact[fw_naddr]), 16);
		struct fw_vi_mac_exact *p;
		int i;

		memset(&cmd, 0, sizeof(cmd));
		cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_MAC_CMD) |
					     FW_CMD_REQUEST_F |
					     FW_CMD_WRITE_F |
					     (free ? FW_CMD_EXEC_F : 0) |
					     FW_VI_MAC_CMD_VIID_V(viid));
		cmd.freemacs_to_len16 =
			cpu_to_be32(FW_VI_MAC_CMD_FREEMACS_V(free) |
				    FW_CMD_LEN16_V(len16));

		for (i = 0, p = cmd.u.exact; i < fw_naddr; i++, p++) {
			p->valid_to_idx = cpu_to_be16(
				FW_VI_MAC_CMD_VALID_F |
				FW_VI_MAC_CMD_IDX_V(FW_VI_MAC_ADD_MAC));
			memcpy(p->macaddr, addr[offset+i], sizeof(p->macaddr));
		}


		ret = t4vf_wr_mbox_core(adapter, &cmd, sizeof(cmd), &rpl,
					sleep_ok);
		if (ret && ret != -ENOMEM)
			break;

		for (i = 0, p = rpl.u.exact; i < fw_naddr; i++, p++) {
			u16 index = FW_VI_MAC_CMD_IDX_G(
				be16_to_cpu(p->valid_to_idx));

			if (idx)
				idx[offset+i] =
					(index >= max_naddr
					 ? 0xffff
					 : index);
			if (index < max_naddr)
				nfilters++;
			else if (hash)
				*hash |= (1ULL << hash_mac_addr(addr[offset+i]));
		}

		free = false;
		offset += fw_naddr;
		rem -= fw_naddr;
	}

	/*
	 * If there were no errors or we merely ran out of room in our MAC
	 * address arena, return the number of filters actually written.
	 */
	if (ret == 0 || ret == -ENOMEM)
		ret = nfilters;
	return ret;
}

/**
 *	t4vf_change_mac - modifies the exact-match filter for a MAC address
 *	@adapter: the adapter
 *	@viid: the Virtual Interface ID
 *	@idx: index of existing filter for old value of MAC address, or -1
 *	@addr: the new MAC address value
 *	@persist: if idx < 0, the new MAC allocation should be persistent
 *
 *	Modifies an exact-match filter and sets it to the new MAC address.
 *	Note that in general it is not possible to modify the value of a given
 *	filter so the generic way to modify an address filter is to free the
 *	one being used by the old address value and allocate a new filter for
 *	the new address value.  @idx can be -1 if the address is a new
 *	addition.
 *
 *	Returns a negative error number or the index of the filter with the new
 *	MAC value.
 */
int t4vf_change_mac(struct adapter *adapter, unsigned int viid,
		    int idx, const u8 *addr, bool persist)
{
	int ret;
	struct fw_vi_mac_cmd cmd, rpl;
	struct fw_vi_mac_exact *p = &cmd.u.exact[0];
	size_t len16 = DIV_ROUND_UP(offsetof(struct fw_vi_mac_cmd,
					     u.exact[1]), 16);
	unsigned int max_naddr = is_t4(adapter->params.chip) ?
				 NUM_MPS_CLS_SRAM_L_INSTANCES :
				 NUM_MPS_T5_CLS_SRAM_L_INSTANCES;

	/*
	 * If this is a new allocation, determine whether it should be
	 * persistent (across a "freemacs" operation) or not.
	 */
	if (idx < 0)
		idx = persist ? FW_VI_MAC_ADD_PERSIST_MAC : FW_VI_MAC_ADD_MAC;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_MAC_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_WRITE_F |
				     FW_VI_MAC_CMD_VIID_V(viid));
	cmd.freemacs_to_len16 = cpu_to_be32(FW_CMD_LEN16_V(len16));
	p->valid_to_idx = cpu_to_be16(FW_VI_MAC_CMD_VALID_F |
				      FW_VI_MAC_CMD_IDX_V(idx));
	memcpy(p->macaddr, addr, sizeof(p->macaddr));

	ret = t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), &rpl);
	if (ret == 0) {
		p = &rpl.u.exact[0];
		ret = FW_VI_MAC_CMD_IDX_G(be16_to_cpu(p->valid_to_idx));
		if (ret >= max_naddr)
			ret = -ENOMEM;
	}
	return ret;
}

/**
 *	t4vf_set_addr_hash - program the MAC inexact-match hash filter
 *	@adapter: the adapter
 *	@viid: the Virtual Interface Identifier
 *	@ucast: whether the hash filter should also match unicast addresses
 *	@vec: the value to be written to the hash filter
 *	@sleep_ok: call is allowed to sleep
 *
 *	Sets the 64-bit inexact-match hash filter for a virtual interface.
 */
int t4vf_set_addr_hash(struct adapter *adapter, unsigned int viid,
		       bool ucast, u64 vec, bool sleep_ok)
{
	struct fw_vi_mac_cmd cmd;
	size_t len16 = DIV_ROUND_UP(offsetof(struct fw_vi_mac_cmd,
					     u.exact[0]), 16);

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_MAC_CMD) |
				     FW_CMD_REQUEST_F |
				     FW_CMD_WRITE_F |
				     FW_VI_ENABLE_CMD_VIID_V(viid));
	cmd.freemacs_to_len16 = cpu_to_be32(FW_VI_MAC_CMD_HASHVECEN_F |
					    FW_VI_MAC_CMD_HASHUNIEN_V(ucast) |
					    FW_CMD_LEN16_V(len16));
	cmd.u.hash.hashvec = cpu_to_be64(vec);
	return t4vf_wr_mbox_core(adapter, &cmd, sizeof(cmd), NULL, sleep_ok);
}

/**
 *	t4vf_get_port_stats - collect "port" statistics
 *	@adapter: the adapter
 *	@pidx: the port index
 *	@s: the stats structure to fill
 *
 *	Collect statistics for the "port"'s Virtual Interface.
 */
int t4vf_get_port_stats(struct adapter *adapter, int pidx,
			struct t4vf_port_stats *s)
{
	struct port_info *pi = adap2pinfo(adapter, pidx);
	struct fw_vi_stats_vf fwstats;
	unsigned int rem = VI_VF_NUM_STATS;
	__be64 *fwsp = (__be64 *)&fwstats;

	/*
	 * Grab the Virtual Interface statistics a chunk at a time via mailbox
	 * commands.  We could use a Work Request and get all of them at once
	 * but that's an asynchronous interface which is awkward to use.
	 */
	while (rem) {
		unsigned int ix = VI_VF_NUM_STATS - rem;
		unsigned int nstats = min(6U, rem);
		struct fw_vi_stats_cmd cmd, rpl;
		size_t len = (offsetof(struct fw_vi_stats_cmd, u) +
			      sizeof(struct fw_vi_stats_ctl));
		size_t len16 = DIV_ROUND_UP(len, 16);
		int ret;

		memset(&cmd, 0, sizeof(cmd));
		cmd.op_to_viid = cpu_to_be32(FW_CMD_OP_V(FW_VI_STATS_CMD) |
					     FW_VI_STATS_CMD_VIID_V(pi->viid) |
					     FW_CMD_REQUEST_F |
					     FW_CMD_READ_F);
		cmd.retval_len16 = cpu_to_be32(FW_CMD_LEN16_V(len16));
		cmd.u.ctl.nstats_ix =
			cpu_to_be16(FW_VI_STATS_CMD_IX_V(ix) |
				    FW_VI_STATS_CMD_NSTATS_V(nstats));
		ret = t4vf_wr_mbox_ns(adapter, &cmd, len, &rpl);
		if (ret)
			return ret;

		memcpy(fwsp, &rpl.u.ctl.stat0, sizeof(__be64) * nstats);

		rem -= nstats;
		fwsp += nstats;
	}

	/*
	 * Translate firmware statistics into host native statistics.
	 */
	s->tx_bcast_bytes = be64_to_cpu(fwstats.tx_bcast_bytes);
	s->tx_bcast_frames = be64_to_cpu(fwstats.tx_bcast_frames);
	s->tx_mcast_bytes = be64_to_cpu(fwstats.tx_mcast_bytes);
	s->tx_mcast_frames = be64_to_cpu(fwstats.tx_mcast_frames);
	s->tx_ucast_bytes = be64_to_cpu(fwstats.tx_ucast_bytes);
	s->tx_ucast_frames = be64_to_cpu(fwstats.tx_ucast_frames);
	s->tx_drop_frames = be64_to_cpu(fwstats.tx_drop_frames);
	s->tx_offload_bytes = be64_to_cpu(fwstats.tx_offload_bytes);
	s->tx_offload_frames = be64_to_cpu(fwstats.tx_offload_frames);

	s->rx_bcast_bytes = be64_to_cpu(fwstats.rx_bcast_bytes);
	s->rx_bcast_frames = be64_to_cpu(fwstats.rx_bcast_frames);
	s->rx_mcast_bytes = be64_to_cpu(fwstats.rx_mcast_bytes);
	s->rx_mcast_frames = be64_to_cpu(fwstats.rx_mcast_frames);
	s->rx_ucast_bytes = be64_to_cpu(fwstats.rx_ucast_bytes);
	s->rx_ucast_frames = be64_to_cpu(fwstats.rx_ucast_frames);

	s->rx_err_frames = be64_to_cpu(fwstats.rx_err_frames);

	return 0;
}

/**
 *	t4vf_iq_free - free an ingress queue and its free lists
 *	@adapter: the adapter
 *	@iqtype: the ingress queue type (FW_IQ_TYPE_FL_INT_CAP, etc.)
 *	@iqid: ingress queue ID
 *	@fl0id: FL0 queue ID or 0xffff if no attached FL0
 *	@fl1id: FL1 queue ID or 0xffff if no attached FL1
 *
 *	Frees an ingress queue and its associated free lists, if any.
 */
int t4vf_iq_free(struct adapter *adapter, unsigned int iqtype,
		 unsigned int iqid, unsigned int fl0id, unsigned int fl1id)
{
	struct fw_iq_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_IQ_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_EXEC_F);
	cmd.alloc_to_len16 = cpu_to_be32(FW_IQ_CMD_FREE_F |
					 FW_LEN16(cmd));
	cmd.type_to_iqandstindex =
		cpu_to_be32(FW_IQ_CMD_TYPE_V(iqtype));

	cmd.iqid = cpu_to_be16(iqid);
	cmd.fl0id = cpu_to_be16(fl0id);
	cmd.fl1id = cpu_to_be16(fl1id);
	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_eth_eq_free - free an Ethernet egress queue
 *	@adapter: the adapter
 *	@eqid: egress queue ID
 *
 *	Frees an Ethernet egress queue.
 */
int t4vf_eth_eq_free(struct adapter *adapter, unsigned int eqid)
{
	struct fw_eq_eth_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_vfn = cpu_to_be32(FW_CMD_OP_V(FW_EQ_ETH_CMD) |
				    FW_CMD_REQUEST_F |
				    FW_CMD_EXEC_F);
	cmd.alloc_to_len16 = cpu_to_be32(FW_EQ_ETH_CMD_FREE_F |
					 FW_LEN16(cmd));
	cmd.eqid_pkd = cpu_to_be32(FW_EQ_ETH_CMD_EQID_V(eqid));
	return t4vf_wr_mbox(adapter, &cmd, sizeof(cmd), NULL);
}

/**
 *	t4vf_handle_fw_rpl - process a firmware reply message
 *	@adapter: the adapter
 *	@rpl: start of the firmware message
 *
 *	Processes a firmware message, such as link state change messages.
 */
int t4vf_handle_fw_rpl(struct adapter *adapter, const __be64 *rpl)
{
	const struct fw_cmd_hdr *cmd_hdr = (const struct fw_cmd_hdr *)rpl;
	u8 opcode = FW_CMD_OP_G(be32_to_cpu(cmd_hdr->hi));

	switch (opcode) {
	case FW_PORT_CMD: {
		/*
		 * Link/module state change message.
		 */
		const struct fw_port_cmd *port_cmd =
			(const struct fw_port_cmd *)rpl;
		u32 stat, mod;
		int action, port_id, link_ok, speed, fc, pidx;

		/*
		 * Extract various fields from port status change message.
		 */
		action = FW_PORT_CMD_ACTION_G(
			be32_to_cpu(port_cmd->action_to_len16));
		if (action != FW_PORT_ACTION_GET_PORT_INFO) {
			dev_err(adapter->pdev_dev,
				"Unknown firmware PORT reply action %x\n",
				action);
			break;
		}

		port_id = FW_PORT_CMD_PORTID_G(
			be32_to_cpu(port_cmd->op_to_portid));

		stat = be32_to_cpu(port_cmd->u.info.lstatus_to_modtype);
		link_ok = (stat & FW_PORT_CMD_LSTATUS_F) != 0;
		speed = 0;
		fc = 0;
		if (stat & FW_PORT_CMD_RXPAUSE_F)
			fc |= PAUSE_RX;
		if (stat & FW_PORT_CMD_TXPAUSE_F)
			fc |= PAUSE_TX;
		if (stat & FW_PORT_CMD_LSPEED_V(FW_PORT_CAP_SPEED_100M))
			speed = 100;
		else if (stat & FW_PORT_CMD_LSPEED_V(FW_PORT_CAP_SPEED_1G))
			speed = 1000;
		else if (stat & FW_PORT_CMD_LSPEED_V(FW_PORT_CAP_SPEED_10G))
			speed = 10000;
		else if (stat & FW_PORT_CMD_LSPEED_V(FW_PORT_CAP_SPEED_40G))
			speed = 40000;

		/*
		 * Scan all of our "ports" (Virtual Interfaces) looking for
		 * those bound to the physical port which has changed.  If
		 * our recorded state doesn't match the current state,
		 * signal that change to the OS code.
		 */
		for_each_port(adapter, pidx) {
			struct port_info *pi = adap2pinfo(adapter, pidx);
			struct link_config *lc;

			if (pi->port_id != port_id)
				continue;

			lc = &pi->link_cfg;

			mod = FW_PORT_CMD_MODTYPE_G(stat);
			if (mod != pi->mod_type) {
				pi->mod_type = mod;
				t4vf_os_portmod_changed(adapter, pidx);
			}

			if (link_ok != lc->link_ok || speed != lc->speed ||
			    fc != lc->fc) {
				/* something changed */
				lc->link_ok = link_ok;
				lc->speed = speed;
				lc->fc = fc;
				lc->supported =
					be16_to_cpu(port_cmd->u.info.pcap);
				t4vf_os_link_changed(adapter, pidx, link_ok);
			}
		}
		break;
	}

	default:
		dev_err(adapter->pdev_dev, "Unknown firmware reply %X\n",
			opcode);
	}
	return 0;
}

/**
 */
int t4vf_prep_adapter(struct adapter *adapter)
{
	int err;
	unsigned int chipid;

	/* Wait for the device to become ready before proceeding ...
	 */
	err = t4vf_wait_dev_ready(adapter);
	if (err)
		return err;

	/* Default port and clock for debugging in case we can't reach
	 * firmware.
	 */
	adapter->params.nports = 1;
	adapter->params.vfres.pmask = 1;
	adapter->params.vpd.cclk = 50000;

	adapter->params.chip = 0;
	switch (CHELSIO_PCI_ID_VER(adapter->pdev->device)) {
	case CHELSIO_T4:
		adapter->params.chip |= CHELSIO_CHIP_CODE(CHELSIO_T4, 0);
		break;

	case CHELSIO_T5:
		chipid = REV_G(t4_read_reg(adapter, PL_VF_REV_A));
		adapter->params.chip |= CHELSIO_CHIP_CODE(CHELSIO_T5, chipid);
		break;
	}

	return 0;
}
