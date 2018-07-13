/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linux BPF SK_MSG Data Structures
 */
#ifndef __LINUX_SK_MSG_H__
#define __LINUX_SK_MSG_H__

#include <stdarg.h>

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/compat.h>
#include <linux/skbuff.h>
#include <linux/linkage.h>
#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/cryptohash.h>
#include <linux/set_memory.h>
#include <linux/kallsyms.h>
#include <linux/if_vlan.h>
#include <linux/scatterlist.h>
#include <net/strparser.h>

#include <uapi/linux/filter.h>
#include <uapi/linux/bpf.h>

struct sk_msg_buff {
	void *data;
	void *data_end;
	__u32 apply_bytes;
	__u32 cork_bytes;
	int eval;
	int sg_copybreak;
	int sg_start;
	int sg_curr;
	int sg_end;
	/* We have +1 scatterlist element here to account for the
	 * possibility we may need to chain a sg if we have new
	 * data to insert or the ring loops around in the 'apply'
	 * action case. kTLS expect sg list for encryption so to
	 * allow sending the entire msg in one crypto API call we
	 * may use this.
	 */
	struct scatterlist sg_data[MAX_SKB_FRAGS + 1];
	bool sg_copy[MAX_SKB_FRAGS];
	__u32 flags;
	struct sock *sk_redir;
	struct sock *sk;
	struct sk_buff *skb;
	struct list_head list;
};

enum __sk_action {
	__SK_DROP = 0,
	__SK_PASS,
	__SK_REDIRECT,
	__SK_NONE,
};

struct smap_psock {
	struct rcu_head	rcu;
	refcount_t refcnt;

	/* datapath variables */
	struct sk_buff_head rxqueue;
	bool strp_enabled;

	/* datapath error path cache across tx work invocations */
	int save_rem;
	int save_off;
	struct sk_buff *save_skb;

	/* datapath variables for tx_msg ULP */
	struct sock *sk_redir;
	int apply_bytes;
	int cork_bytes;
	int sg_size;
	int eval;
	struct sk_msg_buff *cork;
	struct list_head ingress;

	struct strparser strp;
	struct bpf_prog *bpf_tx_msg;
	struct bpf_prog *bpf_parse;
	struct bpf_prog *bpf_verdict;
	struct list_head maps;
	spinlock_t maps_lock;

	/* Back reference used when sock callback trigger sockmap operations */
	struct sock *sock;
	unsigned long state;

	struct work_struct tx_work;
	struct work_struct gc_work;

	struct proto *sk_proto;
	void (*save_close)(struct sock *sk, long timeout);
	void (*save_data_ready)(struct sock *sk);
	void (*save_write_space)(struct sock *sk);
};

static inline void bpf_compute_data_pointers_sg(struct sk_msg_buff *md)
{
	struct scatterlist *sg = md->sg_data + md->sg_start;

	if (md->sg_copy[md->sg_start]) {
		md->data = md->data_end = 0;
	} else {
		md->data = sg_virt(sg);
		md->data_end = md->data + sg->length;
	}
}

static inline int bpf_map_msg_verdict(int _rc, struct sk_msg_buff *md)
{
	return ((_rc == SK_PASS) ?
	       (md->sk_redir ? __SK_REDIRECT : __SK_PASS) :
	       __SK_DROP);
}

static inline struct smap_psock *smap_psock_sk(const struct sock *sk)
{
	return rcu_dereference_sk_user_data(sk);
}

struct sock *do_msg_redirect_map(struct sk_msg_buff *md);
void smap_release_sock(struct smap_psock *psock, struct sock *sock);
#endif
