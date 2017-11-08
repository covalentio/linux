/*
 * Lightweight BPF based pseudo qdisc for ingress and egress.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * Author: Daniel Borkmann <daniel@iogearbox.net>
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

struct bpf_sch_swap_req {
	enum tc_sch_bpf_type type;
	struct bpf_prog *prog;
	bool offload;
};

static const struct nla_policy bpf_parms_policy[TCA_BPF_PARMS_MAX + 1] = {
	[TCA_BPF_PARMS_PROG]	= { .type = NLA_U32 },
	[TCA_BPF_PARMS_FLAGS]	= { .type = NLA_U32 },
};

static const struct nla_policy bpf_policy[TCA_BPF_SCH_MAX + 1] = {
	[TCA_BPF_PARMS_INGRESS]	= { .type = NLA_NESTED },
	[TCA_BPF_PARMS_EGRESS]	= { .type = NLA_NESTED },
};

static __always_inline void *tcf_to_priv(const struct tcf_proto *tp)
{
	return (void *)tp;
}

static __always_inline struct tcf_proto *priv_to_tcf(void *private_data)
{
	return private_data;
}

static __always_inline int
bpf_schs_run(const struct bpf_prog *prog, struct sk_buff *skb)
{
	int ret;

	switch ((ret = BPF_PROG_RUN(prog, skb))) {
	case TC_ACT_OK:
	case TC_ACT_SHOT:
	case TC_ACT_STOLEN:
	case TC_ACT_REDIRECT:
	case TC_ACT_UNSPEC:
		return ret;
	default:
		return TC_ACT_SHOT;
	}
}

static int bpf_schs_ingress(struct sk_buff *skb, const struct tcf_proto *tp,
			    struct tcf_result *res, bool unused)
{
	const struct bpf_prog *prog = tcf_to_priv(tp);
	int ret;

	bpf_compute_data_pointers(skb);
	qdisc_skb_cb(skb)->tc_classid = 0;
	__skb_push(skb, skb->mac_len);
	rcu_read_lock();
	ret = bpf_schs_run(prog, skb);
	rcu_read_unlock();
	__skb_pull(skb, skb->mac_len);
	res->classid = qdisc_skb_cb(skb)->tc_classid;
	return ret;
}

static int bpf_schs_egress(struct sk_buff *skb, const struct tcf_proto *tp,
			   struct tcf_result *res, bool unused)
{
	const struct bpf_prog *prog = tcf_to_priv(tp);
	int ret;

	bpf_compute_data_pointers(skb);
	qdisc_skb_cb(skb)->tc_classid = 0;
	rcu_read_lock();
	ret = bpf_schs_run(prog, skb);
	rcu_read_unlock();
	res->classid = qdisc_skb_cb(skb)->tc_classid;
	return ret;
}

static void bpf_schs_rcu_cb(struct mini_Qdisc *miniq)
{
	bpf_prog_put(tcf_to_priv(miniq->tp));
}

static void bpf_schs_select_run_fn(struct Qdisc *qdisc,
				   struct mini_Qdisc_pair *miniqp)
{
	struct bpf_sch_data *q = qdisc_priv(qdisc);

	if (miniqp == &q->ingress.miniqp)
		mini_qdisc_pair_set_cbs(miniqp, bpf_schs_ingress,
					bpf_schs_rcu_cb);
	else if (miniqp == &q->egress.miniqp)
		mini_qdisc_pair_set_cbs(miniqp, bpf_schs_egress,
					bpf_schs_rcu_cb);
	else
		WARN_ONCE(1, "Invalid mini_Qdisc_pair selected!\n");
}

static int bpf_schs_dump(struct Qdisc *sch, struct sk_buff *skb)
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
		prog = tcf_to_priv(miniq->tp);
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
		prog = tcf_to_priv(miniq->tp);
		if (nla_put_u32(skb, TCA_BPF_PARMS_PROG, prog->aux->id))
			goto nla_put_failure;
		nla_nest_end(skb, nest_inner);
	}

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

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

static enum tc_bpf_command bpf_schs_get_cmd(const struct bpf_sch_miniq *mq,
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

static bool bpf_schs_offloaded(const struct tc_sch_bpf_offload *off)
{
	if (off->command == TC_BPF_ADD)
		return true;
	if (off->command == TC_BPF_DESTROY)
		return false;
	if (off->command == TC_BPF_REPLACE)
		return true;

	return false;
}

static int bpf_schs_swap_offloaded(struct net_device *dev,
				   struct bpf_sch_miniq *mq,
				   struct bpf_sch_swap_req *req)
{
	struct tc_sch_bpf_offload off = {
		.command	= bpf_schs_get_cmd(mq, req),
		.type		= req->type,
		.prog		= req->prog,
	};
	int ret = dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_SCHBPF, &off);

	if (!ret)
		mq->offloaded = bpf_schs_offloaded(&off);
	return ret;
}

static int bpf_schs_swap_one(struct net_device *dev, struct bpf_sch_miniq *mq,
			     struct bpf_sch_swap_req *req)
{
	int ret = 0;

	ASSERT_RTNL();

	if (mq->offloaded || req->offload)
		ret = bpf_schs_swap_offloaded(dev, mq, req);
	if (!ret)
		mini_qdisc_pair_swap(&mq->miniqp, priv_to_tcf(req->prog));
	return ret;
}

static void bpf_schs_fill_old(struct bpf_sch_miniq *mq,
			      struct bpf_sch_swap_req *req,
			      enum tc_sch_bpf_type type)
{
	struct mini_Qdisc *miniq = mini_qdisc_get_active(&mq->miniqp);

	memset(req, 0, sizeof(*req));
	req->type = type;
	if (miniq) {
		req->prog = tcf_to_priv(miniq->tp);
		req->offload = mq->offloaded;
	}
}

static int bpf_schs_change(struct Qdisc *sch, struct nlattr *opt)
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
	bpf_schs_fill_old(&q->egress, &egress_old, TC_SETUP_SCHBPF_EGRESS);
	if (swap_egress)
		ret = bpf_schs_swap_one(dev, &q->egress, &egress);
	if (swap_ingress && !ret) {
		ret = bpf_schs_swap_one(dev, &q->ingress, &ingress);
		if (ret)
			WARN_ON(bpf_schs_swap_one(dev, &q->egress, &egress_old));
	}

	return ret;
}

static int bpf_schs_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	mini_qdisc_pair_init(&q->ingress.miniqp, sch, &dev->miniq_ingress);
	mini_qdisc_pair_init(&q->egress.miniqp, sch, &dev->miniq_egress);

	net_inc_ingress_queue();
	net_inc_egress_queue();

	sch->flags |= TCQ_F_CPUSTATS;

	/* On error, bpf_schs_destroy() will be called, where we'll
	 * decrement the static keys, etc.
	 */
	return bpf_schs_change(sch, opt);
}

static void bpf_schs_destroy(struct Qdisc *sch)
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

	bpf_schs_swap_one(dev, &q->ingress, &ingress);
	bpf_schs_swap_one(dev, &q->egress, &egress);
}

static struct Qdisc_ops bpfs_qdisc_ops __read_mostly = {
	.id		= "bpf",
	.priv_size	= sizeof(struct bpf_sch_data),
	.init		= bpf_schs_init,
	.select_run_fn	= bpf_schs_select_run_fn,
	.destroy	= bpf_schs_destroy,
	.change		= bpf_schs_change,
	.dump		= bpf_schs_dump,
	.owner		= THIS_MODULE,
};

static __always_inline int
bpf_schm_run(const struct bpf_prog *prog, struct sk_buff *skb)
{
	/* In multi-prog mode, _all_ progs are evaluated and the
	 * highest supported BPF return value always takes priority
	 * over the others for the final verdict.
	 */
	int ret;

	switch ((ret = BPF_PROG_RUN(prog, skb))) {
	case TC_ACT_OK:
	case TC_ACT_SHOT:
	case TC_ACT_STOLEN:
	case TC_ACT_UNSPEC:
		return ret;
	default:
		return TC_ACT_SHOT;
	}
}

static int bpf_schm_ingress(struct sk_buff *skb, const struct tcf_proto *tp,
			    struct tcf_result *res, bool unused)
{
	struct bpf_prog_array *array = tcf_to_priv(tp);
	struct bpf_prog **prog = array->progs, *__prog;
	int ret = TC_ACT_UNSPEC, __ret;

	bpf_compute_data_pointers(skb);
	qdisc_skb_cb(skb)->tc_classid = 0;
	__skb_push(skb, skb->mac_len);
	rcu_read_lock();
	while ((__prog = *prog)) {
		if ((__ret = bpf_schm_run(__prog, skb)) > ret)
			ret = __ret;
		prog++;
	}
	rcu_read_unlock();
	__skb_pull(skb, skb->mac_len);
	res->classid = qdisc_skb_cb(skb)->tc_classid;
	return ret;
}

static int bpf_schm_egress(struct sk_buff *skb, const struct tcf_proto *tp,
			   struct tcf_result *res, bool unused)
{
	struct bpf_prog_array *array = tcf_to_priv(tp);
	struct bpf_prog **prog = array->progs, *__prog;
	int ret = TC_ACT_UNSPEC, __ret;

	bpf_compute_data_pointers(skb);
	qdisc_skb_cb(skb)->tc_classid = 0;
	rcu_read_lock();
	while ((__prog = *prog)) {
		if ((__ret = bpf_schm_run(__prog, skb)) > ret)
			ret = __ret;
		prog++;
	}
	rcu_read_unlock();
	res->classid = qdisc_skb_cb(skb)->tc_classid;
	return ret;
}

static void bpf_schm_rcu_cb(struct mini_Qdisc *miniq)
{
	struct bpf_prog_array *array = tcf_to_priv(miniq->tp);
	struct bpf_prog **prog = array->progs, *__prog;

	while ((__prog = *prog)) {
		bpf_prog_put(__prog);
		prog++;
	}

	bpf_prog_array_free(array);
}

static void bpf_schm_select_run_fn(struct Qdisc *qdisc,
				   struct mini_Qdisc_pair *miniqp)
{
	struct bpf_sch_data *q = qdisc_priv(qdisc);

	if (miniqp == &q->ingress.miniqp)
		mini_qdisc_pair_set_cbs(miniqp, bpf_schm_ingress,
					bpf_schm_rcu_cb);
	else if (miniqp == &q->egress.miniqp)
		mini_qdisc_pair_set_cbs(miniqp, bpf_schm_egress,
					bpf_schm_rcu_cb);
	else
		WARN_ONCE(1, "Invalid mini_Qdisc_pair selected!\n");
}

static int bpf_schm_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct bpf_prog **prog, *__prog;
	struct bpf_prog_array *array;
	struct nlattr *nest, *nest_inner;
	struct mini_Qdisc *miniq;

	ASSERT_RTNL();

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	miniq = mini_qdisc_get_active(&q->ingress.miniqp);
	if (miniq) {
		nest_inner = nla_nest_start(skb, TCA_BPF_PARMS_INGRESS);
		if (nest_inner == NULL)
			goto nla_put_failure;
		array = tcf_to_priv(miniq->tp);
		prog = array->progs;
		while ((__prog = *prog)) {
			if (nla_put_u32(skb, TCA_BPF_PARMS_PROG,
					__prog->aux->id))
				goto nla_put_failure;
			prog++;
		}
		nla_nest_end(skb, nest_inner);
	}

	miniq = mini_qdisc_get_active(&q->egress.miniqp);
	if (miniq) {
		nest_inner = nla_nest_start(skb, TCA_BPF_PARMS_EGRESS);
		if (nest_inner == NULL)
			goto nla_put_failure;
		array = tcf_to_priv(miniq->tp);
		prog = array->progs;
		while ((__prog = *prog)) {
			if (nla_put_u32(skb, TCA_BPF_PARMS_PROG,
					__prog->aux->id))
				goto nla_put_failure;
			prog++;
		}
		nla_nest_end(skb, nest_inner);
	}

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

struct bpf_schm_swap_req {
	struct bpf_prog_array *array;
};

static void bpf_schm_swap_arr(struct net_device *dev, struct bpf_sch_miniq *mq,
			      struct bpf_schm_swap_req *req)
{
	ASSERT_RTNL();
	mini_qdisc_pair_swap(&mq->miniqp, priv_to_tcf(req->array));
}

static int
bpf_schm_get_prog_array(struct net_device *dev, struct bpf_sch_data *q,
			struct nlattr *opt, struct bpf_sch_swap_req *req)
{
	struct bpf_sch_swap_req ingress = {
		.type = TC_SETUP_SCHBPF_UNSPEC,
	};
	struct mini_Qdisc *miniq;


#if 0
	miniq = mini_qdisc_get_active(&q->ingress.miniqp);
	if (miniq) {
		nest_inner = nla_nest_start(skb, TCA_BPF_PARMS_INGRESS);
		if (nest_inner == NULL)
			goto nla_put_failure;
		array = tcf_to_priv(miniq->tp);
		prog = array->progs;
		while ((__prog = *prog)) {
			if (nla_put_u32(skb, TCA_BPF_PARMS_PROG,
					__prog->aux->id))
				goto nla_put_failure;
			prog++;
		}
		nla_nest_end(skb, nest_inner);
	}
#endif

	return 0;
}

static int bpf_schm_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct bpf_schm_swap_req ingress = {}, egress = {};
	bool swap_ingress = false, swap_egress = false;
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
		ret = bpf_schm_get_prog_array(dev, q, tb[TCA_BPF_PARMS_INGRESS],
					      &ingress);
		if (ret)
			return ret;
		swap_ingress = true;
	}
	if (tb[TCA_BPF_PARMS_EGRESS]) {
		ret = bpf_schm_get_prog_array(dev, q, tb[TCA_BPF_PARMS_EGRESS],
					      &egress);
		if (ret)
			return ret;
		swap_egress = true;
	}
out:
	if (swap_egress)
		bpf_schm_swap_arr(dev, &q->egress, &egress);
	if (swap_ingress)
		bpf_schm_swap_arr(dev, &q->ingress, &ingress);

	return ret;
}

static int bpf_schm_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	mini_qdisc_pair_init(&q->ingress.miniqp, sch, &dev->miniq_ingress);
	mini_qdisc_pair_init(&q->egress.miniqp, sch, &dev->miniq_egress);

	net_inc_ingress_queue();
	net_inc_egress_queue();

	sch->flags |= TCQ_F_CPUSTATS;

	/* On error, bpf_schm_destroy() will be called, where we'll
	 * decrement the static keys, etc.
	 */
	return bpf_schm_change(sch, opt);
}

static void bpf_schm_destroy(struct Qdisc *sch)
{
	struct bpf_schm_swap_req ingress = {}, egress = {};
	struct bpf_sch_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	net_dec_ingress_queue();
	net_dec_egress_queue();

	bpf_schm_swap_arr(dev, &q->egress, &egress);
	bpf_schm_swap_arr(dev, &q->ingress, &ingress);
}

static struct Qdisc_ops bpfm_qdisc_ops __read_mostly = {
	.id		= "bpf_multi",
	.priv_size	= sizeof(struct bpf_sch_data),
	.init		= bpf_schm_init,
	.select_run_fn	= bpf_schm_select_run_fn,
	.destroy	= bpf_schm_destroy,
	.change		= bpf_schm_change,
	.dump		= bpf_schm_dump,
	.owner		= THIS_MODULE,
};

static int __init bpf_sch_module_init(void)
{
	int ret;

	ret = register_qdisc(&bpfs_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&bpfm_qdisc_ops);
		if (ret)
			unregister_qdisc(&bpfs_qdisc_ops);
	}

	return ret;
}

static void __exit bpf_sch_module_exit(void)
{
	unregister_qdisc(&bpfs_qdisc_ops);
	unregister_qdisc(&bpfm_qdisc_ops);
}

module_init(bpf_sch_module_init);
module_exit(bpf_sch_module_exit);

MODULE_ALIAS("sch_bpf");
MODULE_AUTHOR("Daniel Borkmann");
MODULE_LICENSE("GPL");
