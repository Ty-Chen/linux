# 网络通信之发包

### 一. 简介

  本文将分析网络协议栈发包的整个流程，根据顺序我们将依次介绍套接字文件系统、传输层、网络层、数据链路层、硬件设备层的相关发包处理流程，内容较多较复杂，主要掌握整个流程即可。

### 二. 套接字文件系统

  在前文中已经介绍了套接字`socket`和文件描述符`fd`以及对应的文件`file`的关系。在用户态使用网络编程的时候，我们可以采用`write()`和`read()`的方式通过文件描述符写入。套接字文件系统的操作定义如下，读对应的是`sock_read_iter()`，写对应的是`sock_read_iter()`

```text
static const struct file_operations socket_file_ops = {
    .owner =  THIS_MODULE,
    .llseek =  no_llseek,
    .read_iter =  sock_read_iter,
    .write_iter =  sock_write_iter,
    .poll =    sock_poll,
    .unlocked_ioctl = sock_ioctl,
    .mmap =    sock_mmap,
    .release =  sock_close,
    .fasync =  sock_fasync,
    .sendpage =  sock_sendpage,
    .splice_write = generic_splice_sendpage,
    .splice_read =  sock_splice_read,
};
```

  `sock_write_iter()`首先从文件`file`中取的对应的套接字`sock`，接着调用`sock_sendmsg()`发送消息。`sock_sendmsg()`则调用定义在`inet_stream_ops`中的`sendmsg()`函数，即`inet_sendmsg()`。`inet_sendmsg()`会获取协议对应的`sendmsg()`函数并调用，对于TCP来说则是`tcp_sendmsg()`。

```text
static ssize_t sock_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct socket *sock = file->private_data;
    struct msghdr msg = {.msg_iter = *from,
                 .msg_iocb = iocb};
    ssize_t res;
......
    res = sock_sendmsg(sock, &msg);
    *from = msg.msg_iter;
    return res;
}
​
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{ 
    int ret = sock->ops->sendmsg(sock, msg, msg_data_left(msg));
    ......
}
​
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
    struct sock *sk = sock->sk;
......
    return sk->sk_prot->sendmsg(sk, msg, size);
}
```

### 三. TCP层

  通过前文分析我们知道`sk_buff`存放了所有需要发送的数据包，因此来自于用户态的`msg`也需要填写至其中。`tcp_sendmsg()`需要首先要分配空闲的`sk_buff`并拷贝`msg`，接着需要将该消息发送出去。其中消息的拷贝考虑到可能较长需要分片，因此会循环分配，循环主要逻辑为：

* 调用`tcp_send_mss()`计算`MSS`大小，
* 调用`tcp_write_queue_tail()`获取`sk_buff`链表最后一项，因为可能还有剩余空间。
* `copy`小于0说明当前`sk_buff`并无可用空间，因此需要调用 `sk_stream_alloc_skb()`重新分配 `sk_buff`，然后调用 `skb_entail()`将新分配的 `sk_buff` 放到队列尾部，`copy`赋值为`size_goal`
* 由于`sk_buff`存在连续数据区域和离散的数据区`skb_shared_info`，因此需要分别讨论。调用 `skb_add_data_nocache()`可以 将数据拷贝到连续的数据区域。调用`skb_copy_to_page_nocache()` 则将数据拷贝到 struct `skb_shared_info` 结构指向的不需要连续的页面区域。
* 根据上面得到的`sk_buff`进行发送。如果累积了较多的数据包，则调用`__tcp_push_pending_frames()`发送，如果是第一个包则调用`tcp_push_one()`。二者最后均会调用`tcp_write_xmit`发送。

```text
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    int ret;
    lock_sock(sk);
    ret = tcp_sendmsg_locked(sk, msg, size);
    release_sock(sk);
    return ret;
}
​
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct ubuf_info *uarg = NULL;
    struct sk_buff *skb;
    struct sockcm_cookie sockc;
    int flags, err, copied = 0;
    int mss_now = 0, size_goal, copied_syn = 0;
    bool process_backlog = false;
    bool zc = false;
    long timeo;
......
    /* Ok commence sending. */
    copied = 0;
restart:
    mss_now = tcp_send_mss(sk, &size_goal, flags);
    err = -EPIPE;
    if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
        goto do_error;
    while (msg_data_left(msg)) {
        int copy = 0;
        skb = tcp_write_queue_tail(sk);
        if (skb)
            copy = size_goal - skb->len;
        if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) {
            bool first_skb;
            int linear;
......
            first_skb = tcp_rtx_and_write_queues_empty(sk);
            linear = select_size(first_skb, zc);
            skb = sk_stream_alloc_skb(sk, linear, sk->sk_allocation,
                          first_skb);
......
            skb_entail(sk, skb);
            copy = size_goal;
......
        }
        /* Try to append data to the end of skb. */
        if (copy > msg_data_left(msg))
            copy = msg_data_left(msg);
        /* Where to copy to? */
        if (skb_availroom(skb) > 0 && !zc) {
            /* We have some space in skb head. Superb! */
            copy = min_t(int, copy, skb_availroom(skb));
            err = skb_add_data_nocache(sk, skb, &msg->msg_iter, copy);
......
        } else if (!zc) {
......
            err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
                               pfrag->page,
                               pfrag->offset,
                               copy);
......
            /* Update the skb. */
            if (merge) {
                skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
            } else {
                skb_fill_page_desc(skb, i, pfrag->page,
                           pfrag->offset, copy);
                page_ref_inc(pfrag->page);
            }
            pfrag->offset += copy;
......
        if (!copied)
            TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;
        tp->write_seq += copy;
        TCP_SKB_CB(skb)->end_seq += copy;
        tcp_skb_pcount_set(skb, 0);
        copied += copy;
        if (!msg_data_left(msg)) {
            if (unlikely(flags & MSG_EOR))
                TCP_SKB_CB(skb)->eor = 1;
            goto out;
        }
        if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))
            continue;
        if (forced_push(tp)) {
            tcp_mark_push(tp, skb);
            __tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
        } else if (skb == tcp_send_head(sk))
            tcp_push_one(sk, mss_now);
......
        mss_now = tcp_send_mss(sk, &size_goal, flags);
    }
......
}
```

  `tcp_write_xmit()`的核心部分为一个循环，每次调用`tcp_send_head()`获取头部`sk_buff`，若已经读完则退出循环。循环内逻辑为：

* 调用`tcp_init_tso_segs()`进行TSO（TCP Segmentation Offload）相关工作。当需要发送较大的网络包的时候，我们可以选择在协议栈中进行分段，也可以选择延迟到硬件网卡去进行自动分段以降低CPU负载。
* 调用`tcp_cwnd_test()`检查现在拥塞窗口是否允许发包，如果允许，返回可以发送多少个`sk_buff`。
* 调用`tcp_snd_wnd_test()`检测当前第一个`sk_buff`的序列号是否满足要求： `sk_buff` 中的 `end_seq` 和 `tcp_wnd_end(tp)` 之间的关系，也即这个 `sk_buff` 是否在滑动窗口的允许范围之内。
* `tso_segs`为1可能是`nagle`协议导致，需要进行判断。其次需要判断TSO是否延迟到硬件网卡进行。
* 调用`tcp_mss_split_point()`判断是否会因为超出 `mss` 而分段，还会判断另一个条件，就是是否在滑动窗口的运行范围之内，如果小于窗口的大小，也需要分段，也即需要调用 `tso_fragment()`。
* 调用`tcp_small_queue_check()`检查是否需要采取[小队列](https://lwn.net/Articles/507065/)：TCP小队列对每个TCP数据流中，能够同时参与排队的字节数做出了限制，这个限制是通过`net.ipv4.tcp_limit_output_bytes`内核选项实现的。当TCP发送的数据超过这个限制时，多余的数据会被放入另外一个队列中，再通过`tastlet`机制择机发送。
* 调用`tcp_transmit_skb()`完成`sk_buff`的真正发送工作。

```text
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
               int push_one, gfp_t gfp)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct sk_buff *skb;
    unsigned int tso_segs, sent_pkts;
    int cwnd_quota;
......
    max_segs = tcp_tso_segs(sk, mss_now);
    while ((skb = tcp_send_head(sk))) {
        unsigned int limit;
......
        tso_segs = tcp_init_tso_segs(skb, mss_now);
......
        cwnd_quota = tcp_cwnd_test(tp, skb);
......
        if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {
            is_rwnd_limited = true;
            break;
        }
        if (tso_segs == 1) {
            if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
                             (tcp_skb_is_last(sk, skb) ?
                              nonagle : TCP_NAGLE_PUSH))))
                break;
        } else {
            if (!push_one &&
                tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
                         &is_rwnd_limited, max_segs))
                break;
        }
        limit = mss_now;
        if (tso_segs > 1 && !tcp_urg_mode(tp))
            limit = tcp_mss_split_point(sk, skb, mss_now,
                            min_t(unsigned int, cwnd_quota, max_segs), nonagle);
        if (skb->len > limit &&
            unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
            break;
        if (tcp_small_queue_check(sk, skb, 0))
            break;
        if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
            break;
repair:
        /* Advance the send_head.  This one is sent out.
         * This call will increment packets_out.
         */
        tcp_event_new_data_sent(sk, skb);
        tcp_minshall_update(tp, mss_now, skb);
        sent_pkts += tcp_skb_pcount(skb);
        if (push_one)
            break;
    }
......
}
```

  `tcp_transmit_skb()`函数主要完成TCP头部的填充。这里面有源端口，设置为 `inet_sport`，有目标端口，设置为 `inet_dport`；有序列号，设置为 `tcb->seq`；有确认序列号，设置为 `tp->rcv_nxt`。所有的 `flags` 设置为 `tcb->tcp_flags`。设置选项为 `opts`。设置窗口大小为 `tp->rcv_wnd`。完成之后调用 `icsk_af_ops` 的 `queue_xmit()` 方法，`icsk_af_ops` 指向 `ipv4_specific`，也即调用的是 `ip_queue_xmit()` 函数，进入IP层。

```text
​
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
                gfp_t gfp_mask)
{
    const struct inet_connection_sock *icsk = inet_csk(sk);
    struct inet_sock *inet;
    struct tcp_sock *tp;
    struct tcp_skb_cb *tcb;
    struct tcphdr *th;
    int err;
​
    tp = tcp_sk(sk);
​
    skb->skb_mstamp = tp->tcp_mstamp;
    inet = inet_sk(sk);
    tcb = TCP_SKB_CB(skb);
    memset(&opts, 0, sizeof(opts));
​
    tcp_header_size = tcp_options_size + sizeof(struct tcphdr);
    skb_push(skb, tcp_header_size);
​
    /* Build TCP header and checksum it. */
    th = (struct tcphdr *)skb->data;
    th->source      = inet->inet_sport;
    th->dest        = inet->inet_dport;
    th->seq         = htonl(tcb->seq);
    th->ack_seq     = htonl(tp->rcv_nxt);
    *(((__be16 *)th) + 6)   = htons(((tcp_header_size >> 2) << 12) |
                    tcb->tcp_flags);
​
    th->check       = 0;
    th->urg_ptr     = 0;
......
    tcp_options_write((__be32 *)(th + 1), tp, &opts);
    th->window  = htons(min(tp->rcv_wnd, 65535U));
......
    err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);
......
}
```

### 四. IP层

  `ip_queue_xmit()`实际调用`__ip_queue_xmit()`，其逻辑为

* 调用`ip_route_output_ports()`选取路由，也即我要发送这个包应该从哪个网卡出去
* 填充IP层头部。在这里面，服务类型设置为 `tos`，标识位里面设置是否允许分片 `frag_off`。如果不允许，而遇到 `MTU` 太小过不去的情况，就发送 `ICMP` 报错。`TTL` 是这个包的存活时间，为了防止一个 `IP` 包迷路以后一直存活下去，每经过一个路由器 `TTL` 都减一，减为零则“死去”。设置 `protocol`，指的是更上层的协议，这里是 `TCP`。源地址和目标地址由 `ip_copy_addrs()` 设置。最后设置 `options`。
* 调用`ip_local_out()`发送IP包

```text
/* Note: skb->sk can be different from sk, in case of tunnels */
int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,
            __u8 tos)
{
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct ip_options_rcu *inet_opt;
    struct flowi4 *fl4;
    struct rtable *rt;
    struct iphdr *iph;
    int res;
......
    inet_opt = rcu_dereference(inet->inet_opt);
    fl4 = &fl->u.ip4;
    rt = skb_rtable(skb);
    if (rt)
        goto packet_routed;
    /* Make sure we can route this packet. */
    rt = (struct rtable *)__sk_dst_check(sk, 0);
    if (!rt) {
        __be32 daddr;
        /* Use correct destination address if we have options. */
        daddr = inet->inet_daddr;
......
        rt = ip_route_output_ports(net, fl4, sk,
                       daddr, inet->inet_saddr,
                       inet->inet_dport,
                       inet->inet_sport,
                       sk->sk_protocol,
                       RT_CONN_FLAGS_TOS(sk, tos),
                       sk->sk_bound_dev_if);
        if (IS_ERR(rt))
            goto no_route;
        sk_setup_caps(sk, &rt->dst);
    }
    skb_dst_set_noref(skb, &rt->dst);
packet_routed:
    if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
        goto no_route;
    /* OK, we know where to send it, allocate and build IP header. */
    skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    *((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (tos & 0xff));
    if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
        iph->frag_off = htons(IP_DF);
    else
        iph->frag_off = 0;
    iph->ttl      = ip_select_ttl(inet, &rt->dst);
    iph->protocol = sk->sk_protocol;
    ip_copy_addrs(iph, fl4);
    /* Transport layer set skb->h.foo itself. */
    if (inet_opt && inet_opt->opt.optlen) {
        iph->ihl += inet_opt->opt.optlen >> 2;
        ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);
    }
    ip_select_ident_segs(net, skb, sk,
                 skb_shinfo(skb)->gso_segs ?: 1);
    /* TODO : should we use skb->sk here instead of sk ? */
    skb->priority = sk->sk_priority;
    skb->mark = sk->sk_mark;
    res = ip_local_out(net, sk, skb);
    rcu_read_unlock();
......
}
```

  下面看看选取路由的部分，其调用链为`ip_route_output_ports()->ip_route_output_flow()->__ip_route_output_key()->ip_route_output_key_hash()->ip_route_output_key_hash_rcu()`。最终会先调用`fib_lookup()`进行路由查找，接着会调用`__mkroute_output()`创建`rtable`结构体实例`rth`表示找到的路由表项并返回。

```text
struct rtable *ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4, struct fib_result *res, const struct sk_buff *skb)
{
    struct net_device *dev_out = NULL;
    int orig_oif = fl4->flowi4_oif;
    unsigned int flags = 0;
    struct rtable *rth;
......
     err = fib_lookup(net, fl4, res, 0);
......
make_route:
    rth = __mkroute_output(res, fl4, orig_oif, dev_out, flags);
......
}
```

  `fib_lookup()`首先调用`fib_get_table()`获取对应的路由表，接着调用`fib_table_lookup()`在路由表中找寻对应的路由。由于IP本身是点分十进制的数，所以在路由表中实际采取的是`Trie`树结构体进行存储以便于查找匹配。通过`Trie`树可以完美契合IP地址的分类方式，迅速找到符合的路由。

```text
static inline int fib_lookup(struct net *net, const struct flowi4 *flp, struct fib_result *res, unsigned int flags)
{  
    struct fib_table *tb;
......
    tb = fib_get_table(net, RT_TABLE_MAIN);
    if (tb)
        err = fib_table_lookup(tb, flp, res, flags | FIB_LOOKUP_NOREF);
......
}
```

 `ip_local_out()`首先调用`__ip_local_out()`，实际调用`nf_hook()`，`nf_hook()`是大名鼎鼎的`netfilter`在IP层注册的钩子函数的位置。接着会调用`dst_output()`进行数据发送。

```text
int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  int err;

  err = __ip_local_out(net, sk, skb);
  if (likely(err == 1))
    err = dst_output(net, sk, skb);

  return err;
}

int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  struct iphdr *iph = ip_hdr(skb);
  iph->tot_len = htons(skb->len);
  skb->protocol = htons(ETH_P_IP);

  return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
           net, sk, skb, NULL, skb_dst(skb)->dev,
           dst_output);
}
```

  关于`Netfilter`，我打算在后面单独开一篇文章详细介绍，因为的确很复杂而且具有研究价值。这里先简单介绍一下。下图是`Netfilter`和对应的`iptables`, `ip_tables`的关系示意图。由此可见，我们可以在用户态通过`iptables`命令操作，而实际上则是在IP层通过五个挂载点实现控制。

![img](https://static001.geekbang.org/resource/image/75/4d/75c8257049eed99499e802fcc2eacf4d.png)

  五个挂载点实际工作位置如下图所示

![img](https://static001.geekbang.org/resource/image/76/da/765e5431fe4b17f62b1b5712cc82abda.png)

`filter` 表处理过滤功能，主要包含以下三个链。

* INPUT 链：过滤所有目标地址是本机的数据包
* FORWARD 链：过滤所有路过本机的数据包
* OUTPUT 链：过滤所有由本机产生的数据包

`nat` 表主要处理网络地址转换，可以进行 SNAT（改变源地址）、DNAT（改变目标地址），包含以下三个链。

* PREROUTING 链：可以在数据包到达时改变目标地址
* OUTPUT 链：可以改变本地产生的数据包的目标地址
* POSTROUTING 链：在数据包离开时改变数据包的源地址

  在这里，网络包马上就要发出去了，因而是 `NF_INET_LOCAL_OUT`，也即 `ouput` 链，如果用户曾经在 `iptables` 里面写过某些规则，就会在 `nf_hook` 这个函数里面起作用。

  `dst_output()`实际调用的就是 `struct rtable` 成员 `dst` 的 `ouput()` 函数。在 `rt_dst_alloc()` 中，我们可以看到，`output()` 函数指向的是 `ip_output()`。

```text
/* Output packet to network from transport.  */
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return skb_dst(skb)->output(net, sk, skb);
}

int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb_dst(skb)->dev;
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
          net, sk, skb, NULL, dev,
          ip_finish_output,
          !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```

  在 `ip_output` 里面我们又看到了熟悉的 `NF_HOOK`。这一次是 `NF_INET_POST_ROUTING`，也即 `POSTROUTING` 链，处理完之后调用 `ip_finish_output()`进入MAC层。

### 五. MAC层

  `ip_finish_output()`实际调用`ip_finish_output2()`，其主要逻辑为：

* 找到 `struct rtable` 路由表里面的下一跳，下一跳一定和本机在同一个局域网中，可以通过二层进行通信，因而通过 `__ipv4_neigh_lookup_noref()`，查找如何通过二层访问下一跳。
* 如果没有找到，则调用`__neigh_create()`进行创建
* 调用`neigh_output()`发送网络报

```text
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
......
	return ip_finish_output2(net, sk, skb);
}

static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	u32 nexthop;
......
	nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
	if (!IS_ERR(neigh)) {
		int res;
		sock_confirm_neigh(skb, neigh);
		res = neigh_output(neigh, skb);
		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();
	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb(skb);
	return -EINVAL;
}
```

  `__ipv4_neigh_lookup_noref()`实际调用`___neigh_lookup_noref()`从本地的 ARP 表中查找下一跳的 MAC 地址，具体做法为获取下一跳哈希值，并在哈希表中找取对应的节点`neighbour`

```text
static inline struct neighbour *__ipv4_neigh_lookup_noref(struct net_device *dev, u32 key)
{
......
	return ___neigh_lookup_noref(&arp_tbl, neigh_key_eq32, arp_hashfn, &key, dev);
}

static inline struct neighbour *___neigh_lookup_noref( struct neigh_table *tbl,
	bool (*key_eq)(const struct neighbour *n, const void *pkey),
	__u32 (*hash)(const void *pkey, const struct net_device *dev, __u32 *hash_rnd),
	const void *pkey, struct net_device *dev)
{
	struct neigh_hash_table *nht = rcu_dereference_bh(tbl->nht);
	struct neighbour *n;
	u32 hash_val;
	hash_val = hash(pkey, dev, nht->hash_rnd) >> (32 - nht->hash_shift);
	for (n = rcu_dereference_bh(nht->hash_buckets[hash_val]);
	     n != NULL;
	     n = rcu_dereference_bh(n->next)) {
		if (n->dev == dev && key_eq(n, pkey))
			return n;
	}
	return NULL;
}
```

  其中ARP表`neigh_table *arp_tbl`定义为

```text
struct neigh_table arp_tbl = {
    .family     = AF_INET,
    .key_len    = 4,    
    .protocol   = cpu_to_be16(ETH_P_IP),
    .hash       = arp_hash,
    .key_eq     = arp_key_eq,
    .constructor    = arp_constructor,
    .proxy_redo = parp_redo,
    .id     = "arp_cache",
......
    .gc_interval    = 30 * HZ, 
    .gc_thresh1 = 128,  
    .gc_thresh2 = 512,  
    .gc_thresh3 = 1024,
};
```

  `__neigh_create()`逻辑为

* 调用`neigh_alloc()`创建`neighbour`结构体用于维护MAC地址和ARP相关的信息
* 调用了 `arp_tbl` 的 `constructor` 函数，也即调用了 `arp_constructor`，在这里面定义了 ARP 的操作 `arp_hh_ops`
* 将创建的 `struct neighbour` 结构放入一个哈希表，这是一个数组加链表的链式哈希表，先计算出哈希值 `hash_val`得到相应的链表，然后循环这个链表找到对应的项，如果找不到就在最后插入一项

```text
struct neighbour *__neigh_create(struct neigh_table *tbl, const void *pkey,
				 struct net_device *dev, bool want_ref)
{
	return ___neigh_create(tbl, pkey, dev, false, want_ref);
}

static struct neighbour *___neigh_create(struct neigh_table *tbl,
					 const void *pkey, struct net_device *dev,
					 bool exempt_from_gc, bool want_ref)
{
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl, dev, exempt_from_gc);
	u32 hash_val;
	unsigned int key_len = tbl->key_len;
	int error;
	struct neigh_hash_table *nht;
......
	/* Protocol specific setup. */
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}
......
	if (atomic_read(&tbl->entries) > (1 << nht->hash_shift))
		nht = neigh_hash_grow(tbl, nht->hash_shift + 1);
	hash_val = tbl->hash(n->primary_key, dev, nht->hash_rnd) >> (32 - nht->hash_shift);
......
	n->dead = 0;
	if (!exempt_from_gc)
		list_add_tail(&n->gc_list, &n->tbl->gc_list);
	if (want_ref)
		neigh_hold(n);
	rcu_assign_pointer(n->next,
			   rcu_dereference_protected(nht->hash_buckets[hash_val],
						     lockdep_is_held(&tbl->lock)));
	rcu_assign_pointer(nht->hash_buckets[hash_val], n);
......
}

static const struct neigh_ops arp_hh_ops = { 
    .family = AF_INET, 
    .solicit = arp_solicit, 
    .error_report = arp_error_report, 
    .output = neigh_resolve_output, 
    .connected_output = neigh_resolve_output,
};
```

  在 `neigh_alloc()` 中，比较重要的有两个成员，一个是 `arp_queue`，上层想通过 `ARP` 获取 MAC 地址的任务都放在这个队列里面。另一个是 `timer` 定时器，设置成过一段时间就调用 `neigh_timer_handler()`来处理这些 ARP 任务。

```text
static struct neighbour *neigh_alloc(struct neigh_table *tbl, struct net_device *dev)
{
    struct neighbour *n = NULL;
    unsigned long now = jiffies;
    int entries;
......
    n = kzalloc(tbl->entry_size + dev->neigh_priv_len, GFP_ATOMIC);
    if (!n)
        goto out_entries;

    __skb_queue_head_init(&n->arp_queue);
    rwlock_init(&n->lock);
    seqlock_init(&n->ha_lock);
    n->updated    = n->used = now;
    n->nud_state    = NUD_NONE;
    n->output    = neigh_blackhole;
    seqlock_init(&n->hh.hh_lock);
    n->parms    = neigh_parms_clone(&tbl->parms);
    setup_timer(&n->timer, neigh_timer_handler, (unsigned long)n);

    NEIGH_CACHE_STAT_INC(tbl, allocs);
    n->tbl      = tbl;
    refcount_set(&n->refcnt, 1);
    n->dead      = 1;
......
}
```

  完成了`__neigh_create()`后，`ip_finish_output2()`就会调用`neigh_output()`发送网络包。按照上面对于 `struct neighbour` 的操作函数 `arp_hh_ops` 的定义，`output` 调用的是 `neigh_resolve_output()`。 `neigh_resolve_output()` 逻辑为

* 调用 `neigh_event_send()` 触发一个事件，看能否激活 `ARP`
* 当 `ARP` 发送完毕，就可以调用 `dev_queue_xmit()` 发送二层网络包了。

```text
int neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb)
{
    if (!neigh_event_send(neigh, skb)) {
......
        rc = dev_queue_xmit(skb);
    }
......
}
```

  在 `__neigh_event_send()` 中，激活 `ARP` 分两种情况，第一种情况是马上激活，也即 `immediate_probe()`。另一种情况是延迟激活则仅仅设置一个 `timer`。然后将 `ARP` 包放在 `arp_queue()` 上。如果马上激活，就直接调用 `neigh_probe()`；如果延迟激活，则定时器到了就会触发 `neigh_timer_handler()`，在这里面还是会调用 `neigh_probe()`。

```text
static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	unsigned long now = jiffies;
	
	if (neigh->used != now)
		neigh->used = now;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	bool immediate_probe = false;
......
	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {
		if (NEIGH_VAR(neigh->parms, MCAST_PROBES) +
		    NEIGH_VAR(neigh->parms, APP_PROBES)) {
			unsigned long next, now = jiffies;
			atomic_set(&neigh->probes, NEIGH_VAR(neigh->parms, UCAST_PROBES));
			neigh->nud_state     = NUD_INCOMPLETE;
			neigh->updated = now;
			next = now + max(NEIGH_VAR(neigh->parms, RETRANS_TIME), HZ/2);
			neigh_add_timer(neigh, next);
			immediate_probe = true;
		} else {
			neigh->nud_state = NUD_FAILED;
			neigh->updated = jiffies;
			write_unlock_bh(&neigh->lock);
			kfree_skb(skb);
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {
		neigh_dbg(2, "neigh %p is delayed\n", neigh);
		neigh->nud_state = NUD_DELAY;
		neigh->updated = jiffies;
		neigh_add_timer(neigh, jiffies +
				NEIGH_VAR(neigh->parms, DELAY_PROBE_TIME));
	}
	if (neigh->nud_state == NUD_INCOMPLETE) {
		if (skb) {
			while (neigh->arp_queue_len_bytes + skb->truesize >
			       NEIGH_VAR(neigh->parms, QUEUE_LEN_BYTES)) {
				struct sk_buff *buff;
				buff = __skb_dequeue(&neigh->arp_queue);
				if (!buff)
					break;
				neigh->arp_queue_len_bytes -= buff->truesize;
				kfree_skb(buff);
				NEIGH_CACHE_STAT_INC(neigh->tbl, unres_discards);
			}
			skb_dst_force(skb);
			__skb_queue_tail(&neigh->arp_queue, skb);
			neigh->arp_queue_len_bytes += skb->truesize;
		}
		rc = 1;
	}
out_unlock_bh:
	if (immediate_probe)
		neigh_probe(neigh);
	else
		write_unlock(&neigh->lock);
......
}
```

  `neigh_probe()`会从 `arp_queue` 中拿出 `ARP` 包来，然后调用 `struct neighbour` 的 `solicit` 操作，即`arp_solicit()`，最终调用`arp_send_dst()`创建并发送`ARP`包，并将结果放在`struct dst_entry`中。

```text
static void neigh_probe(struct neighbour *neigh)
        __releases(neigh->lock)
{
    struct sk_buff *skb = skb_peek_tail(&neigh->arp_queue);
......
    if (neigh->ops->solicit)
        neigh->ops->solicit(neigh, skb);
......
}

static void arp_send_dst(int type, int ptype, __be32 dest_ip,
                         struct net_device *dev, __be32 src_ip,
                         const unsigned char *dest_hw,
                         const unsigned char *src_hw,
                         const unsigned char *target_hw,
                         struct dst_entry *dst)
{
    struct sk_buff *skb;
......
    skb = arp_create(type, ptype, dest_ip, dev, src_ip,
                         dest_hw, src_hw, target_hw);
......
    skb_dst_set(skb, dst_clone(dst));
    arp_xmit(skb);
}
```

  当 `ARP` 发送完毕，就可以调用 `dev_queue_xmit()` 发送二层网络包了，实际调用`__dev_queue_xmit()`。

```text
/**
 *  __dev_queue_xmit - transmit a buffer
 *  @skb: buffer to transmit
 *  @accel_priv: private data used for L2 forwarding offload
 *
 *  Queue a buffer for transmission to a network device. 
 */
static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
{
    struct net_device *dev = skb->dev;
    struct netdev_queue *txq;
    struct Qdisc *q;
......
    txq = netdev_pick_tx(dev, skb, accel_priv);
    q = rcu_dereference_bh(txq->qdisc);

    if (q->enqueue) {
        rc = __dev_xmit_skb(skb, q, dev, txq);
        goto out;
    }
......
}
```

  每个块设备都有队列，用于将内核的数据放到队列里面，然后设备驱动从队列里面取出后，将数据根据具体设备的特性发送给设备。网络设备也是类似的，对于发送来说，有一个发送队列 `struct netdev_queue *txq`。这里还有另一个变量叫做 `struct Qdisc`，该队列就是大名鼎鼎的[流控队列](http://www.tldp.org/HOWTO/Traffic-Control-HOWTO/)了。经过流控许可发送，最终就会调用`__dev_xmit_skb()`进行发送。

  `__dev_xmit_skb()` 会将请求放入队列，然后调用 `__qdisc_run()` 处理队列中的数据。`qdisc_restart` 用于数据的发送。`qdisc` 的另一个功能是用于控制网络包的发送速度，因而如果超过速度，就需要重新调度，则会调用 `__netif_schedule()`。

```text
static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
                 struct net_device *dev,
                 struct netdev_queue *txq)
{
......
    rc = q->enqueue(skb, q, &to_free) & NET_XMIT_MASK;
    if (qdisc_run_begin(q)) {
......
        __qdisc_run(q);
    }
......    
}

void __qdisc_run(struct Qdisc *q)
{
    int quota = dev_tx_weight;
    int packets;
        while (qdisc_restart(q, &packets)) {
            /*
             * Ordered by possible occurrence: Postpone processing if
             * 1. we've exceeded packet quota
             * 2. another process needs the CPU;
             */
            quota -= packets;
            if (quota <= 0 || need_resched()) {
                __netif_schedule(q);
                break;
            }
        }
    qdisc_run_end(q);
}
```

  `__netif_schedule()` 会调用 `__netif_reschedule()`发起一个软中断 `NET_TX_SOFTIRQ`。设备驱动程序处理中断分两个过程，一个是屏蔽中断的关键处理逻辑，一个是延迟处理逻辑。工作队列是延迟处理逻辑的处理方案，软中断也是一种方案。在系统初始化的时候，我们会定义软中断的处理函数。例如，`NET_TX_SOFTIRQ` 的处理函数是 `net_tx_action()`，用于发送网络包。还有一个 `NET_RX_SOFTIRQ` 的处理函数是 `net_rx_action()`，用于接收网络包。

```text
static void __netif_reschedule(struct Qdisc *q)
{
    struct softnet_data *sd;
    unsigned long flags;
    local_irq_save(flags);
    sd = this_cpu_ptr(&softnet_data);
    q->next_sched = NULL;
    *sd->output_queue_tailp = q;
    sd->output_queue_tailp = &q->next_sched;
    raise_softirq_irqoff(NET_TX_SOFTIRQ);
    local_irq_restore(flags);
}
```

  `net_tx_action()` 调用了 `qdisc_run()`，最终和`__dev_xmit_skb()`一样调用 `__qdisc_run()`，通过`qdisc_restart()`完成发包。

```text
static __latent_entropy void net_tx_action(struct softirq_action *h)
{
    struct softnet_data *sd = this_cpu_ptr(&softnet_data);
......
    if (sd->output_queue) {
        struct Qdisc *head;

        local_irq_disable();
        head = sd->output_queue;
        sd->output_queue = NULL;
        sd->output_queue_tailp = &sd->output_queue;
        local_irq_enable();

        while (head) {
            struct Qdisc *q = head;
            spinlock_t *root_lock;

            head = head->next_sched;
......
            qdisc_run(q);
        }
    }
}
```

  `qdisc_restart()` 将网络包从 `Qdisc` 的队列中拿下来，然后调用 `sch_direct_xmit()` 进行发送。

```text
static inline int qdisc_restart(struct Qdisc *q, int *packets)
{
    struct netdev_queue *txq;
    struct net_device *dev;
    spinlock_t *root_lock;
    struct sk_buff *skb;
    bool validate;

    /* Dequeue packet */
    skb = dequeue_skb(q, &validate, packets);
    if (unlikely(!skb))
        return 0;

    root_lock = qdisc_lock(q);
    dev = qdisc_dev(q);
    txq = skb_get_tx_queue(dev, skb);

    return sch_direct_xmit(skb, q, dev, txq, root_lock, validate);
}
```

   `sch_direct_xmit()` 调用 `dev_hard_start_xmit()` 进行发送，如果发送不成功，会返回 `NETDEV_TX_BUSY`。这说明网络卡很忙，于是就调用 `dev_requeue_skb()`，重新放入队列。

```text
int sch_direct_xmit(struct sk_buff *skb, struct Qdisc *q,
            struct net_device *dev, struct netdev_queue *txq,
            spinlock_t *root_lock, bool validate)
{
    int ret = NETDEV_TX_BUSY;

    if (likely(skb)) {
        if (!netif_xmit_frozen_or_stopped(txq))
            skb = dev_hard_start_xmit(skb, dev, txq, &ret); 
    } 
......
    if (dev_xmit_complete(ret)) {
        /* Driver sent out skb successfully or skb was consumed */
        ret = qdisc_qlen(q);
    } else {
        /* Driver returned NETDEV_TX_BUSY - requeue skb */
        ret = dev_requeue_skb(skb, q);
    }   
......
}
```

   `dev_hard_start_xmit()` 通过一个 while 循环每次在队列中取出一个 `sk_buff`，调用 `xmit_one()` 发送。接下来的调用链为：`xmit_one()->netdev_start_xmit()->__netdev_start_xmit()`。

```text
struct sk_buff *dev_hard_start_xmit(struct sk_buff *first, struct net_device *dev, 
                                    struct netdev_queue *txq, int *ret) 
{
    struct sk_buff *skb = first;
    int rc = NETDEV_TX_OK;

    while (skb) {
        struct sk_buff *next = skb->next;
        rc = xmit_one(skb, dev, txq, next != NULL);
        skb = next; 
        if (netif_xmit_stopped(txq) && skb) {
            rc = NETDEV_TX_BUSY;
            break;      
        }       
    }   
......
}


static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops, 
               struct sk_buff *skb, struct net_device *dev, bool more)          
{
    skb->xmit_more = more ? 1 : 0;
    return ops->ndo_start_xmit(skb, dev);
}
```

  这个时候，已经到了设备驱动层了。我们能看到，[drivers/net/ethernet/intel/ixgbe/ixgbe\_main.c](drivers/net/ethernet/intel/ixgbe/ixgbe_main.c)里面有对于这个网卡的操作的定义（英特尔网卡有多种不同的型号，对应于intel目录下不同的驱动，这里我们仅挑选其中的一种来做分析）。在这里面，我们可以找到对于 `ndo_start_xmit()` 的定义，实际会调用 `ixgb_xmit_frame()`。在 `ixgb_xmit_frame()` 中，我们会得到这个网卡对应的适配器，然后将其放入硬件网卡的队列中。至此，整个发送才算结束。

```text
static const struct net_device_ops ixgbe_netdev_ops = {
        .ndo_open               = ixgbe_open,
        .ndo_stop               = ixgbe_close,
        .ndo_start_xmit         = ixgbe_xmit_frame,
......
};

static netdev_tx_t ixgbe_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev)
{
	return __ixgbe_xmit_frame(skb, netdev, NULL);
}

static netdev_tx_t
ixgbe_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_ring *tx_ring;
	/*
	 * The minimum packet size for olinfo paylen is 17 so pad the skb
	 * in order to meet this minimum size requirement.
	 */
	if (skb_put_padto(skb, 17))
		return NETDEV_TX_OK;
	tx_ring = ring ? ring : adapter->tx_ring[skb->queue_mapping];
	if (unlikely(test_bit(__IXGBE_TX_DISABLED, &tx_ring->state)))
		return NETDEV_TX_BUSY;
	return ixgbe_xmit_frame_ring(skb, adapter, tx_ring);
}
```

### 总结

  整个网络协议栈的发送流程很长，中间也有不少关键步骤值得注意，值得仔细研究。

![img](https://static001.geekbang.org/resource/image/79/6f/79cc42f3163d159a66e163c006d9f36f.png)

### 源码资料

\[1\] [socket\_file\_ops](https://code.woboq.org/linux/linux/net/socket.c.html#sock_write_iter)

\[2\] [tcp\_sendmsg\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp.c.html#tcp_sendmsg)

\[3\] [tcp\_write\_xmit\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp_output.c.html#tcp_write_xmit)

\[4\] [ip\_queue\_xmit\(\)](https://code.woboq.org/linux/linux/net/ipv4/ip_output.c.html#__ip_queue_xmit)

\[5\] [ip\_finish\_output\(\)](https://code.woboq.org/linux/linux/net/ipv4/ip_output.c.html#292)

\[6\] [neigh\_resolve\_output\(\)](https://code.woboq.org/linux/linux/net/core/neighbour.c.html#neigh_resolve_output)

### 参考资料

\[1\] wiki

\[2\] [elixir.bootlin.com/linux](https://elixir.bootlin.com/linux/v5.7-rc1/source)

\[3\] [woboq](https://code.woboq.org/)

\[4\] Linux-insides

\[5\] 深入理解Linux内核

\[6\] Linux内核设计的艺术

\[7\] 极客时间 趣谈Linux操作系统

\[8\] 深入理解Linux网络技术内幕

