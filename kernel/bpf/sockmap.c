/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

/* A BPF sock_map is used to store sock objects. This is primarly used
 * for doing socket redirect with BPF helper routines.
 *
 * A sock map may have BPF programs attached to it, currently a program
 * used to parse packets and a program to provide a verdict and redirect
 * decision on the packet are supported. Any programs attached to a sock
 * map are inherited by sock objects when they are added to the map. If
 * no BPF programs are attached the sock object may only be used for sock
 * redirect.
 *
 * A sock object may be in multiple maps, but can only inherit a single
 * parse or verdict program. If adding a sock object to a map would result
 * in having multiple parsing programs the update will return an EBUSY error.
 *
 * For reference this program is similar to devmap used in XDP context
 * reviewing these together may be useful. For an example please review
 * ./samples/bpf/sockmap/.
 */
#include <linux/bpf.h>
#include <net/sock.h>
#include <linux/filter.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <net/strparser.h>
#include <net/tcp.h>

#define SOCK_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY)

struct bpf_stab {
	struct bpf_map map;
	struct sock **sock_map;
	struct bpf_prog *bpf_tx_msg;
	struct bpf_prog *bpf_parse;
	struct bpf_prog *bpf_verdict;
};

enum smap_psock_state {
	SMAP_TX_RUNNING,
};

struct smap_psock_map_entry {
	struct list_head list;
	struct sock **entry;
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

	struct strparser strp;
	struct bpf_prog *bpf_tx_msg;
	struct bpf_prog *bpf_parse;
	struct bpf_prog *bpf_verdict;
	struct list_head maps;

	/* Back reference used when sock callback trigger sockmap operations */
	struct sock *sock;
	unsigned long state;

	struct work_struct tx_work;
	struct work_struct gc_work;

	void (*save_data_ready)(struct sock *sk);
	void (*save_write_space)(struct sock *sk);
	void (*save_state_change)(struct sock *sk);
};

static void smap_release_sock(struct smap_psock *psock, struct sock *sock);

static inline struct smap_psock *smap_psock_sk(const struct sock *sk)
{
	return rcu_dereference_sk_user_data(sk);
}

enum __sk_action {
	__SK_DROP = 0,
	__SK_PASS,
	__SK_REDIRECT,
	__SK_NONE,
};

static int memcopy_from_iter(struct sock *sk, struct scatterlist *sg,
			     int sg_num, struct iov_iter *from, int bytes)
{
	int i, rc = 0;

	for (i = 0; i < sg_num; ++i) {
		int copy = sg[i].length;
		char *to = sg_virt(&sg[i]);

		if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY)
			rc = copy_from_iter_nocache(to, copy, from);
		else
			rc = copy_from_iter(to, copy, from);

		if (rc != copy) {
			rc = -EFAULT;
			goto out;
		}

		bytes -= copy;
		if (!bytes)
			break;
	}
out:
	return rc;
}

static int bpf_tcp_push(struct sock *sk, struct scatterlist *sg,
			int *sg_end, int flags, bool charge)
{
	int sendpage_flags = flags | MSG_SENDPAGE_NOTLAST;
	int offset, ret = 0;
	struct page *p;
	size_t size;

	size = sg->length;
	offset = sg->offset;

	while (1) {
		if (sg_is_last(sg))
			sendpage_flags = flags;

		tcp_rate_check_app_limited(sk);
		p = sg_page(sg);
retry:
		ret = do_tcp_sendpages(sk, p, offset, size, sendpage_flags);
		if (ret != size) {
			if (ret > 0) {
				offset += ret;
				size -= ret;
				goto retry;
			}

			if (charge)
				sk_mem_uncharge(sk,
						sg->length - size - sg->offset);

			sg->offset = offset;
			sg->length = size;
			return ret;
		}

		put_page(p);
		if (charge)
			sk_mem_uncharge(sk, sg->length);
		*sg_end += 1;
		sg = sg_next(sg);
		if (!sg)
			break;

		offset = sg->offset;
		size = sg->length;
	}

	return 0;
}

static inline void bpf_compute_data_pointers_sg(struct sk_msg_buff *md)
{
	md->data = sg_virt(md->sg_data);
	md->data_end = md->data + md->sg_data->length;
}

static void return_mem_sg(struct sock *sk, struct scatterlist *sg, int end)
{
	int i;

	for (i = 0; i < end; ++i)
		sk_mem_uncharge(sk, sg[i].length);
}

static int free_sg(struct sock *sk, struct scatterlist *sg, int start, int len)
{
	int i, free = 0;

	for (i = start; i < len; ++i) {
		free += sg[i].length;
		sk_mem_uncharge(sk, sg[i].length);
		put_page(sg_page(&sg[i]));
	}

	return free;
}

static unsigned int smap_do_tx_msg(struct sock *sk,
				   struct smap_psock *psock,
				   struct sk_msg_buff *md)
{
	struct bpf_prog *prog;
	unsigned int rc, _rc;

	preempt_disable();
	rcu_read_lock();

	/* If the policy was removed mid-send then default to 'accept' */
	prog = READ_ONCE(psock->bpf_tx_msg);
	if (unlikely(!prog)) {
		_rc = SK_PASS;
		goto verdict;
	}

	bpf_compute_data_pointers_sg(md);
	_rc = (*prog->bpf_func)(md, prog->insnsi);

verdict:
	rcu_read_unlock();
	preempt_enable();

	/* Moving return codes from UAPI namespace into internal namespace */
	rc = ((_rc == SK_PASS) ?
	      (md->map ? __SK_REDIRECT : __SK_PASS) :
	      __SK_DROP);

	return rc;
}

static int bpf_tcp_sendmsg_do_redirect(struct scatterlist *sg, int sg_num,
				       struct sk_msg_buff *md, int flags)
{
	int i, sg_curr = 0, err, free;
	struct smap_psock *psock;
	struct sock *sk;

	rcu_read_lock();
	sk = do_msg_redirect_map(md);
	if (unlikely(!sk))
		goto out_rcu;

	psock = smap_psock_sk(sk);
	if (unlikely(!psock))
		goto out_rcu;

	if (!refcount_inc_not_zero(&psock->refcnt))
		goto out_rcu;

	rcu_read_unlock();
	lock_sock(sk);
	err = bpf_tcp_push(sk, sg, &sg_curr, flags, false);
	if (unlikely(err))
		goto out;
	release_sock(sk);
	smap_release_sock(psock, sk);
	return 0;
out_rcu:
	rcu_read_unlock();
out:
	for (i = sg_curr; i < sg_num; ++i) {
		free += sg[i].length;
		put_page(sg_page(&sg[i]));
	}
	return free;
}

static int bpf_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	int err = 0, eval = __SK_NONE, sg_size = 0, sg_num = 0;
	int flags = msg->msg_flags | MSG_NO_SHARED_FRAGS;
	struct sk_msg_buff md = {0};
	struct smap_psock *psock;
	size_t copy, copied = 0;
	struct scatterlist *sg;
	long timeo;

	sg = md.sg_data;
	sg_init_table(sg, MAX_SKB_FRAGS);

	/* Its possible a sock event or user removed the psock _but_ the ops
	 * have not been reprogrammed yet so we get here. In this case fallback
	 * to tcp_sendmsg. Note this only works because we _only_ ever allow
	 * a single ULP there is no hierarchy here.
	 */
	rcu_read_lock();
	psock = smap_psock_sk(sk);
	if (unlikely(!psock)) {
		rcu_read_unlock();
		return tcp_sendmsg(sk, msg, size);
	}

	/* Increment the psock refcnt to ensure its not released while sending a
	 * message. Required because sk lookup and bpf programs are used in
	 * separate rcu critical sections. Its OK if we lose the map entry
	 * but we can't lose the sock reference, possible when the refcnt hits
	 * zero and garbage collection calls sock_put().
	 */
	if (!refcount_inc_not_zero(&psock->refcnt)) {
		rcu_read_unlock();
		return tcp_sendmsg(sk, msg, size);
	}

	rcu_read_unlock();

	lock_sock(sk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);

	while (msg_data_left(msg)) {
		int sg_curr;

		if (sk->sk_err) {
			err = sk->sk_err;
			goto out_err;
		}

		copy = msg_data_left(msg);
		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;

		/* sg_size indicates bytes already allocated and sg_num
		 * is last sg element used. This is used when alloc_sg
		 * partially allocates a scatterlist and then is sent
		 * to wait for memory. In normal case (no memory pressure)
		 * both sg_nun and sg_size are zero.
		 */
		copy = copy - sg_size;
		err = sk_alloc_sg(sk, copy, sg, &sg_num, &sg_size, 0);
		if (err) {
			if (err != -ENOSPC)
				goto wait_for_memory;
			copy = sg_size;
		}

		err = memcopy_from_iter(sk, sg, sg_num, &msg->msg_iter, copy);
		if (err < 0) {
			free_sg(sk, sg, 0, sg_num);
			goto out_err;
		}

		copied += copy;

		/* If msg is larger than MAX_SKB_FRAGS we can send multiple
		 * scatterlists per msg. However BPF decisions apply to the
		 * entire msg.
		 */
		if (eval == __SK_NONE)
			eval = smap_do_tx_msg(sk, psock, &md);

		switch (eval) {
		case __SK_PASS:
			sg_mark_end(sg + sg_num - 1);
			err = bpf_tcp_push(sk, sg, &sg_curr, flags, true);
			if (unlikely(err)) {
				copied -= free_sg(sk, sg, sg_curr, sg_num);
				goto out_err;
			}
			break;
		case __SK_REDIRECT:
			sg_mark_end(sg + sg_num - 1);
			goto do_redir;
		case __SK_DROP:
		default:
			copied -= free_sg(sk, sg, 0, sg_num);
			goto out_err;
		}


		sg_num = 0;
		sg_size = 0;
		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		err = sk_stream_wait_memory(sk, &timeo);
		if (err)
			goto out_err;
	}
out_err:
	if (err < 0)
		err = sk_stream_error(sk, msg->msg_flags, err);
	release_sock(sk);
	smap_release_sock(psock, sk);
	return copied ? copied : err;

do_redir:
	/* To avoid deadlock with multiple socks all doing redirects to
	 * each other we must first drop the current sock lock and release
	 * the psock. Then get the redirect socket (assuming it still
	 * exists), take it's lock, and finally do the send here. If the
	 * redirect fails there is nothing to do, we don't want to blame
	 * the sender for remote socket failures. Instead we simply
	 * continue making forward progress.
	 */
	return_mem_sg(sk, sg, sg_num);
	release_sock(sk);
	smap_release_sock(psock, sk);
	copied -= bpf_tcp_sendmsg_do_redirect(sg, sg_num, &md, flags);
	return copied;
}

static int bpf_tcp_sendpage(struct sock *sk, struct page *page,
			    int offset, size_t size, int flags)
{
	struct smap_psock *psock;
	int rc, _rc = __SK_PASS;
	struct bpf_prog *prog;
	struct sk_msg_buff md;

	preempt_disable();
	rcu_read_lock();
	psock = smap_psock_sk(sk);
	if (unlikely(!psock))
		goto verdict;

	/* If the policy was removed mid-send then default to 'accept' */
	prog = READ_ONCE(psock->bpf_tx_msg);
	if (unlikely(!prog))
		goto verdict;

	/* Calculate pkt data pointers and run BPF program */
	md.data = page_address(page) + offset;
	md.data_end = md.data + size;
	_rc = (*prog->bpf_func)(&md, prog->insnsi);

verdict:
	rcu_read_unlock();
	preempt_enable();

	/* Moving return codes from UAPI namespace into internal namespace */
	rc = ((_rc == SK_PASS) ? __SK_PASS : __SK_DROP);

	switch (rc) {
	case __SK_PASS:
		lock_sock(sk);
		rc = tcp_sendpage_locked(sk, page, offset, size, flags);
		release_sock(sk);
		break;
	case __SK_REDIRECT:
	/* Fall through and free skb no redirect support yet */
	case __SK_DROP:
	default:
		rc = -EACCES;
	}

	return rc;
}

static int bpf_tcp_msg_add(struct smap_psock *psock,
			   struct sock *sk,
			   struct bpf_prog *tx_msg)
{
	struct bpf_prog *orig_tx_msg;

	orig_tx_msg = xchg(&psock->bpf_tx_msg, tx_msg);
	if (orig_tx_msg)
		bpf_prog_put(orig_tx_msg);

	return tcp_set_ulp_id(sk, TCP_ULP_BPF);
}

struct proto tcp_bpf_proto;
static int bpf_tcp_init(struct sock *sk)
{
	sk->sk_prot = &tcp_bpf_proto;
	return 0;
}

static void bpf_tcp_release(struct sock *sk)
{
	sk->sk_prot = &tcp_prot;
}

static struct tcp_ulp_ops bpf_tcp_ulp_ops __read_mostly = {
	.name			= "bpf_tcp",
	.uid			= TCP_ULP_BPF,
	.owner			= NULL,
	.init			= bpf_tcp_init,
	.release		= bpf_tcp_release,
};

static int bpf_tcp_ulp_register(void)
{
	tcp_bpf_proto = tcp_prot;
	tcp_bpf_proto.sendmsg = bpf_tcp_sendmsg;
	tcp_bpf_proto.sendpage = bpf_tcp_sendpage;
	return tcp_register_ulp(&bpf_tcp_ulp_ops);
}

static int smap_verdict_func(struct smap_psock *psock, struct sk_buff *skb)
{
	struct bpf_prog *prog = READ_ONCE(psock->bpf_verdict);
	int rc;

	if (unlikely(!prog))
		return __SK_DROP;

	skb_orphan(skb);
	/* We need to ensure that BPF metadata for maps is also cleared
	 * when we orphan the skb so that we don't have the possibility
	 * to reference a stale map.
	 */
	TCP_SKB_CB(skb)->bpf.map = NULL;
	skb->sk = psock->sock;
	bpf_compute_data_pointers(skb);
	preempt_disable();
	rc = (*prog->bpf_func)(skb, prog->insnsi);
	preempt_enable();
	skb->sk = NULL;

	/* Moving return codes from UAPI namespace into internal namespace */
	return rc == SK_PASS ?
		(TCP_SKB_CB(skb)->bpf.map ? __SK_REDIRECT : __SK_PASS) :
		__SK_DROP;
}

static void smap_do_verdict(struct smap_psock *psock, struct sk_buff *skb)
{
	struct sock *sk;
	int rc;

	rc = smap_verdict_func(psock, skb);
	switch (rc) {
	case __SK_REDIRECT:
		sk = do_sk_redirect_map(skb);
		if (likely(sk)) {
			struct smap_psock *peer = smap_psock_sk(sk);

			if (likely(peer &&
				   test_bit(SMAP_TX_RUNNING, &peer->state) &&
				   !sock_flag(sk, SOCK_DEAD) &&
				   sock_writeable(sk))) {
				skb_set_owner_w(skb, sk);
				skb_queue_tail(&peer->rxqueue, skb);
				schedule_work(&peer->tx_work);
				break;
			}
		}
	/* Fall through and free skb otherwise */
	case __SK_DROP:
	default:
		kfree_skb(skb);
	}
}

static void smap_report_sk_error(struct smap_psock *psock, int err)
{
	struct sock *sk = psock->sock;

	sk->sk_err = err;
	sk->sk_error_report(sk);
}

/* Called with lock_sock(sk) held */
static void smap_state_change(struct sock *sk)
{
	struct smap_psock_map_entry *e, *tmp;
	struct smap_psock *psock;
	struct socket_wq *wq;
	struct sock *osk;

	rcu_read_lock();

	/* Allowing transitions into an established syn_recv states allows
	 * for early binding sockets to a smap object before the connection
	 * is established.
	 */
	switch (sk->sk_state) {
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		break;
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_LISTEN:
		break;
	case TCP_CLOSE:
		/* Only release if the map entry is in fact the sock in
		 * question. There is a case where the operator deletes
		 * the sock from the map, but the TCP sock is closed before
		 * the psock is detached. Use cmpxchg to verify correct
		 * sock is removed.
		 */
		psock = smap_psock_sk(sk);
		if (unlikely(!psock))
			break;
		write_lock_bh(&sk->sk_callback_lock);
		list_for_each_entry_safe(e, tmp, &psock->maps, list) {
			osk = cmpxchg(e->entry, sk, NULL);
			if (osk == sk) {
				list_del(&e->list);
				smap_release_sock(psock, sk);
			}
		}
		write_unlock_bh(&sk->sk_callback_lock);
		break;
	default:
		psock = smap_psock_sk(sk);
		if (unlikely(!psock))
			break;
		smap_report_sk_error(psock, EPIPE);
		break;
	}

	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_all(&wq->wait);
	rcu_read_unlock();
}

static void smap_read_sock_strparser(struct strparser *strp,
				     struct sk_buff *skb)
{
	struct smap_psock *psock;

	rcu_read_lock();
	psock = container_of(strp, struct smap_psock, strp);
	smap_do_verdict(psock, skb);
	rcu_read_unlock();
}

/* Called with lock held on socket */
static void smap_data_ready(struct sock *sk)
{
	struct smap_psock *psock;

	rcu_read_lock();
	psock = smap_psock_sk(sk);
	if (likely(psock)) {
		write_lock_bh(&sk->sk_callback_lock);
		strp_data_ready(&psock->strp);
		write_unlock_bh(&sk->sk_callback_lock);
	}
	rcu_read_unlock();
}

static void smap_tx_work(struct work_struct *w)
{
	struct smap_psock *psock;
	struct sk_buff *skb;
	int rem, off, n;

	psock = container_of(w, struct smap_psock, tx_work);

	/* lock sock to avoid losing sk_socket at some point during loop */
	lock_sock(psock->sock);
	if (psock->save_skb) {
		skb = psock->save_skb;
		rem = psock->save_rem;
		off = psock->save_off;
		psock->save_skb = NULL;
		goto start;
	}

	while ((skb = skb_dequeue(&psock->rxqueue))) {
		rem = skb->len;
		off = 0;
start:
		do {
			if (likely(psock->sock->sk_socket))
				n = skb_send_sock_locked(psock->sock,
							 skb, off, rem);
			else
				n = -EINVAL;
			if (n <= 0) {
				if (n == -EAGAIN) {
					/* Retry when space is available */
					psock->save_skb = skb;
					psock->save_rem = rem;
					psock->save_off = off;
					goto out;
				}
				/* Hard errors break pipe and stop xmit */
				smap_report_sk_error(psock, n ? -n : EPIPE);
				clear_bit(SMAP_TX_RUNNING, &psock->state);
				kfree_skb(skb);
				goto out;
			}
			rem -= n;
			off += n;
		} while (rem);
		kfree_skb(skb);
	}
out:
	release_sock(psock->sock);
}

static void smap_write_space(struct sock *sk)
{
	struct smap_psock *psock;

	rcu_read_lock();
	psock = smap_psock_sk(sk);
	if (likely(psock && test_bit(SMAP_TX_RUNNING, &psock->state)))
		schedule_work(&psock->tx_work);
	rcu_read_unlock();
}

static void smap_stop_sock(struct smap_psock *psock, struct sock *sk)
{
	tcp_cleanup_ulp(sk);
	if (!psock->strp_enabled)
		return;
	sk->sk_data_ready = psock->save_data_ready;
	sk->sk_write_space = psock->save_write_space;
	sk->sk_state_change = psock->save_state_change;
	psock->save_data_ready = NULL;
	psock->save_write_space = NULL;
	psock->save_state_change = NULL;
	strp_stop(&psock->strp);
	psock->strp_enabled = false;
}

static void smap_destroy_psock(struct rcu_head *rcu)
{
	struct smap_psock *psock = container_of(rcu,
						  struct smap_psock, rcu);

	/* Now that a grace period has passed there is no longer
	 * any reference to this sock in the sockmap so we can
	 * destroy the psock, strparser, and bpf programs. But,
	 * because we use workqueue sync operations we can not
	 * do it in rcu context
	 */
	schedule_work(&psock->gc_work);
}

static void smap_release_sock(struct smap_psock *psock, struct sock *sock)
{
	if (refcount_dec_and_test(&psock->refcnt)) {
		smap_stop_sock(psock, sock);
		clear_bit(SMAP_TX_RUNNING, &psock->state);
		rcu_assign_sk_user_data(sock, NULL);
		call_rcu_sched(&psock->rcu, smap_destroy_psock);
	}
}

static int smap_parse_func_strparser(struct strparser *strp,
				       struct sk_buff *skb)
{
	struct smap_psock *psock;
	struct bpf_prog *prog;
	int rc;

	rcu_read_lock();
	psock = container_of(strp, struct smap_psock, strp);
	prog = READ_ONCE(psock->bpf_parse);

	if (unlikely(!prog)) {
		rcu_read_unlock();
		return skb->len;
	}

	/* Attach socket for bpf program to use if needed we can do this
	 * because strparser clones the skb before handing it to a upper
	 * layer, meaning skb_orphan has been called. We NULL sk on the
	 * way out to ensure we don't trigger a BUG_ON in skb/sk operations
	 * later and because we are not charging the memory of this skb to
	 * any socket yet.
	 */
	skb->sk = psock->sock;
	bpf_compute_data_pointers(skb);
	rc = (*prog->bpf_func)(skb, prog->insnsi);
	skb->sk = NULL;
	rcu_read_unlock();
	return rc;
}

static int smap_read_sock_done(struct strparser *strp, int err)
{
	return err;
}

static int smap_init_sock(struct smap_psock *psock,
			  struct sock *sk)
{
	static const struct strp_callbacks cb = {
		.rcv_msg = smap_read_sock_strparser,
		.parse_msg = smap_parse_func_strparser,
		.read_sock_done = smap_read_sock_done,
	};

	return strp_init(&psock->strp, sk, &cb);
}

static void smap_init_progs(struct smap_psock *psock,
			    struct bpf_stab *stab,
			    struct bpf_prog *verdict,
			    struct bpf_prog *parse)
{
	struct bpf_prog *orig_parse, *orig_verdict;

	orig_parse = xchg(&psock->bpf_parse, parse);
	orig_verdict = xchg(&psock->bpf_verdict, verdict);

	if (orig_verdict)
		bpf_prog_put(orig_verdict);
	if (orig_parse)
		bpf_prog_put(orig_parse);
}

static void smap_start_sock(struct smap_psock *psock, struct sock *sk)
{
	if (sk->sk_data_ready == smap_data_ready)
		return;
	psock->save_data_ready = sk->sk_data_ready;
	psock->save_write_space = sk->sk_write_space;
	psock->save_state_change = sk->sk_state_change;
	sk->sk_data_ready = smap_data_ready;
	sk->sk_write_space = smap_write_space;
	sk->sk_state_change = smap_state_change;
	psock->strp_enabled = true;
}

static void sock_map_remove_complete(struct bpf_stab *stab)
{
	bpf_map_area_free(stab->sock_map);
	kfree(stab);
}

static void smap_gc_work(struct work_struct *w)
{
	struct smap_psock_map_entry *e, *tmp;
	struct smap_psock *psock;

	psock = container_of(w, struct smap_psock, gc_work);

	/* no callback lock needed because we already detached sockmap ops */
	if (psock->strp_enabled)
		strp_done(&psock->strp);

	cancel_work_sync(&psock->tx_work);
	__skb_queue_purge(&psock->rxqueue);

	/* At this point all strparser and xmit work must be complete however
	 * an outstanding scatterlist reference may still be in-flight
	 */
	if (psock->bpf_parse)
		bpf_prog_put(psock->bpf_parse);
	if (psock->bpf_verdict)
		bpf_prog_put(psock->bpf_verdict);
	if (psock->bpf_tx_msg)
		bpf_prog_put(psock->bpf_tx_msg);

	list_for_each_entry_safe(e, tmp, &psock->maps, list) {
		list_del(&e->list);
		kfree(e);
	}

	sock_put(psock->sock);
	kfree(psock);
}

static struct smap_psock *smap_init_psock(struct sock *sock,
					  struct bpf_stab *stab)
{
	struct smap_psock *psock;

	psock = kzalloc_node(sizeof(struct smap_psock),
			     GFP_ATOMIC | __GFP_NOWARN,
			     stab->map.numa_node);
	if (!psock)
		return ERR_PTR(-ENOMEM);

	psock->sock = sock;
	skb_queue_head_init(&psock->rxqueue);
	INIT_WORK(&psock->tx_work, smap_tx_work);
	INIT_WORK(&psock->gc_work, smap_gc_work);
	INIT_LIST_HEAD(&psock->maps);
	refcount_set(&psock->refcnt, 1);

	rcu_assign_sk_user_data(sock, psock);
	sock_hold(sock);
	return psock;
}

static struct bpf_map *sock_map_alloc(union bpf_attr *attr)
{
	struct bpf_stab *stab; int err = -EINVAL;
	u64 cost;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 || attr->map_flags & ~SOCK_CREATE_FLAG_MASK)
		return ERR_PTR(-EINVAL);

	if (attr->value_size > KMALLOC_MAX_SIZE)
		return ERR_PTR(-E2BIG);

	err = bpf_tcp_ulp_register();
	if (err && err != -EEXIST)
		return ERR_PTR(err);

	stab = kzalloc(sizeof(*stab), GFP_USER);
	if (!stab)
		return ERR_PTR(-ENOMEM);

	/* mandatory map attributes */
	stab->map.map_type = attr->map_type;
	stab->map.key_size = attr->key_size;
	stab->map.value_size = attr->value_size;
	stab->map.max_entries = attr->max_entries;
	stab->map.map_flags = attr->map_flags;
	stab->map.numa_node = bpf_map_attr_numa_node(attr);

	/* make sure page count doesn't overflow */
	cost = (u64) stab->map.max_entries * sizeof(struct sock *);
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_stab;

	stab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	/* if map size is larger than memlock limit, reject it early */
	err = bpf_map_precharge_memlock(stab->map.pages);
	if (err)
		goto free_stab;

	err = -ENOMEM;
	stab->sock_map = bpf_map_area_alloc(stab->map.max_entries *
					    sizeof(struct sock *),
					    stab->map.numa_node);
	if (!stab->sock_map)
		goto free_stab;

	return &stab->map;
free_stab:
	kfree(stab);
	return ERR_PTR(err);
}

static void smap_list_remove(struct smap_psock *psock, struct sock **entry)
{
	struct smap_psock_map_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &psock->maps, list) {
		if (e->entry == entry) {
			list_del(&e->list);
			break;
		}
	}
}

static void sock_map_free(struct bpf_map *map)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	int i;

	synchronize_rcu();

	/* At this point no update, lookup or delete operations can happen.
	 * However, be aware we can still get a socket state event updates,
	 * and data ready callabacks that reference the psock from sk_user_data
	 * Also psock worker threads are still in-flight. So smap_release_sock
	 * will only free the psock after cancel_sync on the worker threads
	 * and a grace period expire to ensure psock is really safe to remove.
	 */
	rcu_read_lock();
	for (i = 0; i < stab->map.max_entries; i++) {
		struct smap_psock *psock;
		struct sock *sock;

		sock = xchg(&stab->sock_map[i], NULL);
		if (!sock)
			continue;

		write_lock_bh(&sock->sk_callback_lock);
		psock = smap_psock_sk(sock);
		smap_list_remove(psock, &stab->sock_map[i]);
		smap_release_sock(psock, sock);
		write_unlock_bh(&sock->sk_callback_lock);
	}
	rcu_read_unlock();

	if (stab->bpf_verdict)
		bpf_prog_put(stab->bpf_verdict);
	if (stab->bpf_parse)
		bpf_prog_put(stab->bpf_parse);
	if (stab->bpf_tx_msg)
		bpf_prog_put(stab->bpf_tx_msg);

	sock_map_remove_complete(stab);
}

static int sock_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	u32 i = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (i >= stab->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (i == stab->map.max_entries - 1)
		return -ENOENT;

	*next = i + 1;
	return 0;
}

struct sock  *__sock_map_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);

	if (key >= map->max_entries)
		return NULL;

	return READ_ONCE(stab->sock_map[key]);
}

static int sock_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct smap_psock *psock;
	int k = *(u32 *)key;
	struct sock *sock;

	if (k >= map->max_entries)
		return -EINVAL;

	sock = xchg(&stab->sock_map[k], NULL);
	if (!sock)
		return -EINVAL;

	write_lock_bh(&sock->sk_callback_lock);
	psock = smap_psock_sk(sock);
	if (!psock)
		goto out;

	if (psock->bpf_parse)
		smap_stop_sock(psock, sock);
	smap_list_remove(psock, &stab->sock_map[k]);
	smap_release_sock(psock, sock);
out:
	write_unlock_bh(&sock->sk_callback_lock);
	return 0;
}

/* Locking notes: Concurrent updates, deletes, and lookups are allowed and are
 * done inside rcu critical sections. This ensures on updates that the psock
 * will not be released via smap_release_sock() until concurrent updates/deletes
 * complete. All operations operate on sock_map using cmpxchg and xchg
 * operations to ensure we do not get stale references. Any reads into the
 * map must be done with READ_ONCE() because of this.
 *
 * A psock is destroyed via call_rcu and after any worker threads are cancelled
 * and syncd so we are certain all references from the update/lookup/delete
 * operations as well as references in the data path are no longer in use.
 *
 * Psocks may exist in multiple maps, but only a single set of parse/verdict
 * programs may be inherited from the maps it belongs to. A reference count
 * is kept with the total number of references to the psock from all maps. The
 * psock will not be released until this reaches zero. The psock and sock
 * user data data use the sk_callback_lock to protect critical data structures
 * from concurrent access. This allows us to avoid two updates from modifying
 * the user data in sock and the lock is required anyways for modifying
 * callbacks, we simply increase its scope slightly.
 *
 * Rules to follow,
 *  - psock must always be read inside RCU critical section
 *  - sk_user_data must only be modified inside sk_callback_lock and read
 *    inside RCU critical section.
 *  - psock->maps list must only be read & modified inside sk_callback_lock
 *  - sock_map must use READ_ONCE and (cmp)xchg operations
 *  - BPF verdict/parse programs must use READ_ONCE and xchg operations
 */
static int sock_map_ctx_update_elem(struct bpf_sock_ops_kern *skops,
				    struct bpf_map *map,
				    void *key, u64 flags)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct smap_psock_map_entry *e = NULL;
	struct bpf_prog *verdict, *parse, *tx_msg;
	struct sock *osock, *sock;
	struct smap_psock *psock;
	u32 i = *(u32 *)key;
	int err;

	if (unlikely(flags > BPF_EXIST))
		return -EINVAL;

	if (unlikely(i >= stab->map.max_entries))
		return -E2BIG;

	sock = READ_ONCE(stab->sock_map[i]);
	if (flags == BPF_EXIST && !sock)
		return -ENOENT;
	else if (flags == BPF_NOEXIST && sock)
		return -EEXIST;

	sock = skops->sk;

	/* 1. If sock map has BPF programs those will be inherited by the
	 * sock being added. If the sock is already attached to BPF programs
	 * this results in an error.
	 */
	verdict = READ_ONCE(stab->bpf_verdict);
	parse = READ_ONCE(stab->bpf_parse);
	tx_msg = READ_ONCE(stab->bpf_tx_msg);

	if (parse && verdict) {
		/* bpf prog refcnt may be zero if a concurrent attach operation
		 * removes the program after the above READ_ONCE() but before
		 * we increment the refcnt. If this is the case abort with an
		 * error.
		 */
		verdict = bpf_prog_inc_not_zero(stab->bpf_verdict);
		if (IS_ERR(verdict))
			return PTR_ERR(verdict);

		parse = bpf_prog_inc_not_zero(stab->bpf_parse);
		if (IS_ERR(parse)) {
			bpf_prog_put(verdict);
			return PTR_ERR(parse);
		}
	}

	if (tx_msg) {
		tx_msg = bpf_prog_inc_not_zero(stab->bpf_tx_msg);
		if (IS_ERR(tx_msg)) {
			if (verdict)
				bpf_prog_put(verdict);
			if (parse)
				bpf_prog_put(parse);
			return PTR_ERR(tx_msg);
		}
	}

	write_lock_bh(&sock->sk_callback_lock);
	psock = smap_psock_sk(sock);

	/* 2. Do not allow inheriting programs if psock exists and has
	 * already inherited programs. This would create confusion on
	 * which parser/verdict program is running. If no psock exists
	 * create one. Inside sk_callback_lock to ensure concurrent create
	 * doesn't update user data.
	 */
	if (psock) {
		if (READ_ONCE(psock->bpf_parse) && parse) {
			err = -EBUSY;
			goto out_progs;
		}
		if (READ_ONCE(psock->bpf_tx_msg) && tx_msg) {
			err = -EBUSY;
			goto out_progs;
		}
		if (!refcount_inc_not_zero(&psock->refcnt)) {
			err = -EAGAIN;
			goto out_progs;
		}
	} else {
		psock = smap_init_psock(sock, stab);
		if (IS_ERR(psock)) {
			err = PTR_ERR(psock);
			goto out_progs;
		}

		set_bit(SMAP_TX_RUNNING, &psock->state);
	}

	e = kzalloc(sizeof(*e), GFP_ATOMIC | __GFP_NOWARN);
	if (!e) {
		err = -ENOMEM;
		goto out_progs;
	}
	e->entry = &stab->sock_map[i];

	/* 3. At this point we have a reference to a valid psock that is
	 * running. Attach any BPF programs needed.
	 */
	if (tx_msg) {
		err = bpf_tcp_msg_add(psock, sock, tx_msg);
		if (err)
			goto out_free;
	}

	if (parse && verdict && !psock->strp_enabled) {
		err = smap_init_sock(psock, sock);
		if (err)
			goto out_free;
		smap_init_progs(psock, stab, verdict, parse);
		smap_start_sock(psock, sock);
	}

	/* 4. Place psock in sockmap for use and stop any programs on
	 * the old sock assuming its not the same sock we are replacing
	 * it with. Because we can only have a single set of programs if
	 * old_sock has a strp we can stop it.
	 */
	list_add_tail(&e->list, &psock->maps);
	write_unlock_bh(&sock->sk_callback_lock);

	osock = xchg(&stab->sock_map[i], sock);
	if (osock) {
		struct smap_psock *opsock = smap_psock_sk(osock);

		write_lock_bh(&osock->sk_callback_lock);
		if (osock != sock && parse)
			smap_stop_sock(opsock, osock);
		smap_list_remove(opsock, &stab->sock_map[i]);
		smap_release_sock(opsock, osock);
		write_unlock_bh(&osock->sk_callback_lock);
	}
	return 0;
out_free:
	smap_release_sock(psock, sock);
out_progs:
	if (verdict)
		bpf_prog_put(verdict);
	if (parse)
		bpf_prog_put(parse);
	if (tx_msg)
		bpf_prog_put(tx_msg);
	write_unlock_bh(&sock->sk_callback_lock);
	kfree(e);
	return err;
}

int sock_map_prog(struct bpf_map *map, struct bpf_prog *prog, u32 type)
{
	struct bpf_stab *stab = container_of(map, struct bpf_stab, map);
	struct bpf_prog *orig;

	if (unlikely(map->map_type != BPF_MAP_TYPE_SOCKMAP))
		return -EINVAL;

	switch (type) {
	case BPF_SK_MSG_VERDICT:
		orig = xchg(&stab->bpf_tx_msg, prog);
		break;
	case BPF_SK_SKB_STREAM_PARSER:
		orig = xchg(&stab->bpf_parse, prog);
		break;
	case BPF_SK_SKB_STREAM_VERDICT:
		orig = xchg(&stab->bpf_verdict, prog);
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (orig)
		bpf_prog_put(orig);

	return 0;
}

static void *sock_map_lookup(struct bpf_map *map, void *key)
{
	return NULL;
}

static int sock_map_update_elem(struct bpf_map *map,
				void *key, void *value, u64 flags)
{
	struct bpf_sock_ops_kern skops;
	u32 fd = *(u32 *)value;
	struct socket *socket;
	int err;

	socket = sockfd_lookup(fd, &err);
	if (!socket)
		return err;

	skops.sk = socket->sk;
	if (!skops.sk) {
		fput(socket->file);
		return -EINVAL;
	}

	if (skops.sk->sk_type != SOCK_STREAM ||
	    skops.sk->sk_protocol != IPPROTO_TCP) {
		fput(socket->file);
		return -EOPNOTSUPP;
	}

	err = sock_map_ctx_update_elem(&skops, map, key, flags);
	fput(socket->file);
	return err;
}

const struct bpf_map_ops sock_map_ops = {
	.map_alloc = sock_map_alloc,
	.map_free = sock_map_free,
	.map_lookup_elem = sock_map_lookup,
	.map_get_next_key = sock_map_get_next_key,
	.map_update_elem = sock_map_update_elem,
	.map_delete_elem = sock_map_delete_elem,
};

BPF_CALL_4(bpf_sock_map_update, struct bpf_sock_ops_kern *, bpf_sock,
	   struct bpf_map *, map, void *, key, u64, flags)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return sock_map_ctx_update_elem(bpf_sock, map, key, flags);
}

const struct bpf_func_proto bpf_sock_map_update_proto = {
	.func		= bpf_sock_map_update,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};
