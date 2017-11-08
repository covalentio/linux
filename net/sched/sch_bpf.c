/*
 * Lightweight BPF based pseudo qdisc for ingress and egress.
 *
 * Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct bpf_sch_miniq {
	struct mini_Qdisc_pair miniqp;
	bool offloaded;
};

struct bpf_sch_data {
	struct bpf_sch_miniq ingress;
	struct bpf_sch_miniq egress;
};

static __always_inline struct bpf_prog *
tcf_to_prog(const struct tcf_proto *tp)
{
	return (void *)tp;
}

static __always_inline struct tcf_proto *
prog_to_tcf(struct bpf_prog *prog)
{
	return (void *)prog;
}

static __always_inline int bpf_sch_ret_code(int code)
{
	switch (code) {
	case TC_ACT_OK:
	case TC_ACT_SHOT:
	case TC_ACT_STOLEN:
	case TC_ACT_TRAP:
	case TC_ACT_REDIRECT:
	case TC_ACT_UNSPEC:
		return code;
	default:
		return TC_ACT_SHOT;
	}
}

static int bpf_sch_ingress(struct sk_buff *skb, const struct tcf_proto *tp,
			   struct tcf_result *res, bool unused)
{
	const struct bpf_prog *prog = tcf_to_prog(tp);
	int ret;

	bpf_compute_data_pointers(skb);
	qdisc_skb_cb(skb)->tc_classid = 0;

	__skb_push(skb, skb->mac_len);
	rcu_read_lock();
	ret = BPF_PROG_RUN(prog, skb);
	rcu_read_unlock();
	__skb_pull(skb, skb->mac_len);

	res->classid = qdisc_skb_cb(skb)->tc_classid;
	return bpf_sch_ret_code(ret);
}

static int bpf_sch_egress(struct sk_buff *skb, const struct tcf_proto *tp,
			  struct tcf_result *res, bool unused)
{
	const struct bpf_prog *prog = tcf_to_prog(tp);
	int ret;

	bpf_compute_data_pointers(skb);
	qdisc_skb_cb(skb)->tc_classid = 0;

	rcu_read_lock();
	ret = BPF_PROG_RUN(prog, skb);
	rcu_read_unlock();

	res->classid = qdisc_skb_cb(skb)->tc_classid;
	return bpf_sch_ret_code(ret);
}

static void bpf_sch_rcu_cb(struct mini_Qdisc *miniq)
{
	bpf_prog_put(tcf_to_prog(miniq->tp));
}

static void bpf_sch_select_run_fn(struct Qdisc *qdisc,
				  struct mini_Qdisc_pair *miniqp)
{
	struct bpf_sch_data *q = qdisc_priv(qdisc);

	if (miniqp == &q->ingress.miniqp)
		mini_qdisc_pair_set_cbs(miniqp, bpf_sch_ingress, bpf_sch_rcu_cb);
	else if (miniqp == &q->egress.miniqp)
		mini_qdisc_pair_set_cbs(miniqp, bpf_sch_egress, bpf_sch_rcu_cb);
	else
		WARN_ONCE(1, "Invalid mini_Qdisc_pair selected!\n");
}

static int bpf_sch_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct nlattr *nest, *nest_inner;
	const struct bpf_prog *prog;
	struct mini_Qdisc *miniq;
	u64 flags = 0;

	ASSERT_RTNL();

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	miniq = mini_qdisc_get_active(&q->ingress.miniqp);
	if (miniq) {
		nest_inner = nla_nest_start(skb, TCA_BPF_PARMS_INGRESS);
		if (nest_inner == NULL)
			goto nla_put_failure;
		prog = tcf_to_prog(miniq->tp);
		if (nla_put_u32(skb, TCA_BPF_PARMS_PROG, prog->aux->id))
			goto nla_put_failure;
		if (q->ingress.offloaded)
			flags |= TCA_BPF_SCH_OFFLOAD;
		if (flags && nla_put_u32(skb, TCA_BPF_PARMS_FLAGS, flags))
			goto nla_put_failure;
		nla_nest_end(skb, nest_inner);
	}

	miniq = mini_qdisc_get_active(&q->egress.miniqp);
	if (miniq) {
		nest_inner = nla_nest_start(skb, TCA_BPF_PARMS_EGRESS);
		if (nest_inner == NULL)
			goto nla_put_failure;
		prog = tcf_to_prog(miniq->tp);
		if (nla_put_u32(skb, TCA_BPF_PARMS_PROG, prog->aux->id))
			goto nla_put_failure;
		nla_nest_end(skb, nest_inner);
	}

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct nla_policy bpf_parms_policy[TCA_BPF_PARMS_MAX + 1] = {
	[TCA_BPF_PARMS_PROG]	= { .type = NLA_U32 },
	[TCA_BPF_PARMS_FLAGS]	= { .type = NLA_U32 },
};

static const struct nla_policy bpf_policy[TCA_BPF_SCH_MAX + 1] = {
	[TCA_BPF_PARMS_INGRESS]	= { .type = NLA_NESTED },
	[TCA_BPF_PARMS_EGRESS]	= { .type = NLA_NESTED },
};

struct bpf_sch_swap_req {
	enum tc_sch_bpf_type type;
	struct bpf_prog *prog;
	bool offload;
};

static int bpf_sch_get_prog(struct net_device *dev, struct nlattr *opt,
			    struct bpf_sch_swap_req *req)
{
	struct nlattr *tb[TCA_BPF_PARMS_MAX + 1];
	int ret, prog_fd;
	u64 flags;

	ret = nla_parse_nested(tb, TCA_BPF_PARMS_MAX, opt, bpf_parms_policy,
			       NULL);
	if (ret < 0)
		return ret;
	if (!tb[TCA_BPF_PARMS_PROG] ||
	    (tb[TCA_BPF_PARMS_FLAGS] &&
	     req->type != TC_SETUP_SCHBPF_INGRESS))
		return -EINVAL;
	if (tb[TCA_BPF_PARMS_FLAGS]) {
		flags = nla_get_u32(tb[TCA_BPF_PARMS_FLAGS]);
		if (flags & ~TCA_BPF_SCH_OFFLOAD)
			return -EINVAL;
		req->offload = flags & TCA_BPF_SCH_OFFLOAD;
		if (req->offload && !dev->netdev_ops->ndo_setup_tc)
			return -EOPNOTSUPP;
	}
	prog_fd = nla_get_u32(tb[TCA_BPF_PARMS_PROG]);
	req->prog = req->offload ?
		    bpf_prog_get_type_dev(prog_fd, BPF_PROG_TYPE_SCHED_CLS, dev) :
		    bpf_prog_get_type(prog_fd, BPF_PROG_TYPE_SCHED_CLS);
	if (IS_ERR(req->prog))
		return PTR_ERR(req->prog);
	return 0;
}

static enum tc_bpf_command bpf_sch_get_cmd(const struct bpf_sch_miniq *mq,
					   const struct bpf_sch_swap_req *req)
{
	if (!mq->offloaded && req->offload)
		return TC_BPF_ADD;
	if (mq->offloaded && !req->offload)
		return TC_BPF_DESTROY;
	if (mq->offloaded && req->offload)
		return TC_BPF_REPLACE;

	return TC_BPF_DESTROY;
}

static bool bpf_sch_offloaded(const struct tc_sch_bpf_offload *off)
{
	if (off->command == TC_BPF_ADD)
		return true;
	if (off->command == TC_BPF_DESTROY)
		return false;
	if (off->command == TC_BPF_REPLACE)
		return true;

	return false;
}

static int bpf_sch_swap_offloaded(struct net_device *dev,
				  struct bpf_sch_miniq *mq,
				  struct bpf_sch_swap_req *req)
{
	struct tc_sch_bpf_offload off = {
		.command	= bpf_sch_get_cmd(mq, req),
		.type		= req->type,
		.prog		= req->prog,
	};
	int ret = dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_SCHBPF, &off);

	if (!ret)
		mq->offloaded = bpf_sch_offloaded(&off);
	return ret;
}

static int bpf_sch_swap_one(struct net_device *dev, struct bpf_sch_miniq *mq,
			    struct bpf_sch_swap_req *req)
{
	int ret = 0;

	ASSERT_RTNL();

	if (mq->offloaded || req->offload)
		ret = bpf_sch_swap_offloaded(dev, mq, req);
	if (!ret)
		mini_qdisc_pair_swap(&mq->miniqp, prog_to_tcf(req->prog));
	return ret;
}

static void bpf_sch_fill_old(struct bpf_sch_miniq *mq,
			     struct bpf_sch_swap_req *req,
			     enum tc_sch_bpf_type type)
{
	struct mini_Qdisc *miniq = mini_qdisc_get_active(&mq->miniqp);

	memset(req, 0, sizeof(*req));
	req->type = type;
	if (miniq) {
		req->prog = tcf_to_prog(miniq->tp);
		req->offload = mq->offloaded;
	}
}

static int bpf_sch_change(struct Qdisc *sch, struct nlattr *opt)
{
	bool swap_ingress = false, swap_egress = false;
	struct bpf_sch_swap_req ingress = {
		.type = TC_SETUP_SCHBPF_INGRESS,
	}, egress_old, egress = {
		.type = TC_SETUP_SCHBPF_EGRESS,
	};
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct nlattr *tb[TCA_BPF_MAX + 1];
	int ret = 0;

	ASSERT_RTNL();

	if (!opt) {
		swap_ingress = swap_egress = true;
		goto out;
	}

	ret = nla_parse_nested(tb, TCA_BPF_SCH_MAX, opt, bpf_policy, NULL);
	if (ret < 0)
		return ret;
	if (tb[TCA_BPF_PARMS_INGRESS]) {
		ret = bpf_sch_get_prog(dev, tb[TCA_BPF_PARMS_INGRESS],
				       &ingress);
		if (ret)
			return ret;
		swap_ingress = true;
	}
	if (tb[TCA_BPF_PARMS_EGRESS]) {
		ret = bpf_sch_get_prog(dev, tb[TCA_BPF_PARMS_EGRESS],
				       &egress);
		if (ret) {
			if (ingress.prog)
				bpf_prog_put(ingress.prog);
			return ret;
		}
		swap_egress = true;
	}
out:
	bpf_sch_fill_old(&q->egress, &egress_old, TC_SETUP_SCHBPF_EGRESS);
	if (swap_egress)
		ret = bpf_sch_swap_one(dev, &q->egress, &egress);
	if (swap_ingress && !ret) {
		ret = bpf_sch_swap_one(dev, &q->ingress, &ingress);
		if (ret)
			WARN_ON(bpf_sch_swap_one(dev, &q->egress, &egress_old));
	}

	return ret;
}

static int bpf_sch_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int ret;

	mini_qdisc_pair_init(&q->ingress.miniqp, sch, &dev->miniq_ingress);
	mini_qdisc_pair_init(&q->egress.miniqp, sch, &dev->miniq_egress);

	ret = bpf_sch_change(sch, opt);
	if (!ret) {
		net_inc_ingress_queue();
		net_inc_egress_queue();

		sch->flags |= TCQ_F_CPUSTATS;
	}

	return ret;
}

static void bpf_sch_destroy(struct Qdisc *sch)
{
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct bpf_sch_swap_req ingress = {
		.type = TC_SETUP_SCHBPF_INGRESS,
	}, egress = {
		.type = TC_SETUP_SCHBPF_EGRESS,
	};

	net_dec_ingress_queue();
	net_dec_egress_queue();

	bpf_sch_swap_one(dev, &q->ingress, &ingress);
	bpf_sch_swap_one(dev, &q->egress, &egress);
}

static struct Qdisc_ops bpf_qdisc_ops __read_mostly = {
	.id		= "bpf",
	.priv_size	= sizeof(struct bpf_sch_data),
	.init		= bpf_sch_init,
	.select_run_fn	= bpf_sch_select_run_fn,
	.destroy	= bpf_sch_destroy,
	.change		= bpf_sch_change,
	.dump		= bpf_sch_dump,
	.owner		= THIS_MODULE,
};

static int __init bpf_sch_module_init(void)
{
	return register_qdisc(&bpf_qdisc_ops);
}

static void __exit bpf_sch_module_exit(void)
{
	unregister_qdisc(&bpf_qdisc_ops);
}

module_init(bpf_sch_module_init);
module_exit(bpf_sch_module_exit);

MODULE_ALIAS("sch_bpf");
MODULE_AUTHOR("Daniel Borkmann");
MODULE_LICENSE("GPL");
