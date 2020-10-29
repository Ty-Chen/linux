# 网络通信之收包

## 一. 简介

  本文将分析网络协议栈收包的整个流程，收包和发包是刚好相反的过程。根据顺序我们将依次介绍硬件设备驱动层、数据链路层、网络层、传输层、套接字文件系统的相关发包处理流程，内容较多较复杂，主要掌握整个流程即可。

## 二. 网卡驱动层

  网卡作为一个硬件，接收到网络包后靠中断来通知操作系统。但是这里有个问题：网络包的到来往往是很难预期的。网络吞吐量比较大的时候，网络包的到达会十分频繁。这个时候，如果非常频繁地去触发中断，会造成频繁的上下文切换，带来极大的开销。因此硬件处理厂商设计了一种机制，就是当一些网络包到来触发了中断，内核处理完这些网络包之后，我们可以先进入主动轮询 `poll` 网卡的方式主动去接收到来的网络包。如果一直有，就一直处理，等处理告一段落，就返回干其他的事情。当再有下一批网络包到来的时候，再中断，再轮询 `poll`。这样就会大大减少中断的数量，提升网络处理的效率，这种处理方式我们称为 [NAPI](https://en.wikipedia.org/wiki/New_API)。

  本文以 Intel\(R\) PRO/10GbE 网卡驱动为例，在网卡驱动程序初始化的时候，我们会调用 `ixgb_init_module()`注册一个驱动 `ixgb_driver`，并且调用它的 `probe` 函数 `ixgb_probe()`。

```c
static struct pci_driver ixgb_driver = {
    .name     = ixgb_driver_name,
    .id_table = ixgb_pci_tbl,
    .probe    = ixgb_probe,
    .remove   = ixgb_remove,
    .err_handler = &ixgb_err_handler
};
MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) PRO/10GbE Network Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
​
static int __init
ixgb_init_module(void)
{
    pr_info("%s - version %s\n", ixgb_driver_string, ixgb_driver_version);
    pr_info("%s\n", ixgb_copyright);
    return pci_register_driver(&ixgb_driver);
}
module_init(ixgb_init_module);
```

   `ixgb_probe()` 会创建一个 `struct net_device` 表示这个网络设备，并且调用 `netif_napi_add()` 函数为这个网络设备注册一个轮询 `poll` 函数 `ixgb_clean()`，将来一旦出现网络包的时候，就通过该函数来轮询。

```c
static int
ixgb_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    struct net_device *netdev = NULL;
    struct ixgb_adapter *adapter;
......
    netdev = alloc_etherdev(sizeof(struct ixgb_adapter));
    SET_NETDEV_DEV(netdev, &pdev->dev);
​
    pci_set_drvdata(pdev, netdev);
    adapter = netdev_priv(netdev);
    adapter->netdev = netdev;
    adapter->pdev = pdev;
    adapter->hw.back = adapter;
    adapter->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);
    adapter->hw.hw_addr = pci_ioremap_bar(pdev, BAR_0);
......
    netdev->netdev_ops = &ixgb_netdev_ops;
    ixgb_set_ethtool_ops(netdev);
    netdev->watchdog_timeo = 5 * HZ;
    netif_napi_add(netdev, &adapter->napi, ixgb_clean, 64);
​
    strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);
​
    adapter->bd_number = cards_found;
    adapter->link_speed = 0;
    adapter->link_duplex = 0;
......
}
```

  网卡被激活的时候会调用函数 `ixgb_open()->ixgb_up()`，在这里面注册一个硬件的中断处理函数。

```c
intixgb_up(struct ixgb_adapter *adapter)
{ 
    struct net_device *netdev = adapter->netdev;
...... 
    err = request_irq(adapter->pdev->irq, ixgb_intr, irq_flags, netdev->name, netdev);
......
}
```

  如果一个网络包到来，触发了硬件中断，就会调用 `ixgb_intr()`，这里面会调用 `__napi_schedule()`。

```c
static irqreturn_t ixgb_intr(int irq, void *data)
{ 
    struct net_device *netdev = data; 
    struct ixgb_adapter *adapter = netdev_priv(netdev); 
    struct ixgb_hw *hw = &adapter->hw;
...... 
    if (napi_schedule_prep(&adapter->napi)) 
    { 
        IXGB_WRITE_REG(&adapter->hw, IMC, ~0); 
        __napi_schedule(&adapter->napi); 
    } 
    return IRQ_HANDLED;
}
```

  `__napi_schedule()` 处于中断处理的关键部分，在被调用的时候，中断是暂时关闭的。处理网络包是个复杂的过程，需要到中断处理的延迟处理部分执行，所以 `____napi_schedule()` 将当前设备放到 `struct softnet_data` 结构的 `poll_list` 里面，说明在延迟处理部分可以接着处理这个 `poll_list` 里面的网络设备。然后 `____napi_schedule()` 触发一个软中断 `NET_RX_SOFTIRQ`，通过软中断触发中断处理的延迟处理部分，也是常用的手段。

```c
/**
 * __napi_schedule - schedule for receive
 * @n: entry to schedule
 *
 * The entry's receive function will be scheduled to run.
 * Consider using __napi_schedule_irqoff() if hard irqs are masked.
 */
void __napi_schedule(struct napi_struct *n)
{
    unsigned long flags;
    local_irq_save(flags);
    ____napi_schedule(this_cpu_ptr(&softnet_data), n);
    local_irq_restore(flags);
}
​
static inline void ____napi_schedule(struct softnet_data *sd,
             struct napi_struct *napi)
{
    list_add_tail(&napi->poll_list, &sd->poll_list);
    __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```

软中断 `NET_RX_SOFTIRQ` 对应的中断处理函数是 `net_rx_action()`，其逻辑为

* 调用`this_cpu_ptr()`，得到 `struct softnet_data` 结构，这个结构在发送的时候我们也遇到过。当时它的 `output_queue` 用于网络包的发送，这里的 `poll_list` 用于网络包的接收。
* 进入循环，从 `poll_list` 里面取出有网络包到达的设备，然后调用 `napi_poll()` 来轮询这些设备，`napi_poll()` 会调用最初设备初始化的时候注册的 `poll` 函数，对于 `ixgb_driver`对应的函数是 `ixgb_clean()`。

```c
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
    struct softnet_data *sd = this_cpu_ptr(&softnet_data);
......
    for (;;) {
        struct napi_struct *n;
......
        n = list_first_entry(&list, struct napi_struct, poll_list);
        budget -= napi_poll(n, &repoll);
......
    }
}
​
struct softnet_data 
{ 
    struct list_head poll_list;
...... 
    struct Qdisc *output_queue; 
    struct Qdisc **output_queue_tailp;
......
}
```

  `ixgb_clean()` 实际调用`ixgb_clean_rx_irq()`。在网络设备的驱动层，有一个用于接收网络包的 `rx_ring`。它是一个环，从网卡硬件接收的包会放在这个环里面。这个环里面的 `buffer_info[]`是一个数组，存放的是网络包的内容。`i` 和 `j` 是这个数组的下标，在 `ixgb_clean_rx_irq()` 里面的 `while` 循环中，依次处理环里面的数据。在这里面，我们看到了 `i` 和 `j` 加一之后，如果超过了数组的大小，就跳回下标 0，就说明这是一个环。`ixgb_check_copybreak()` 函数将 `buffer_info` 里面的内容拷贝到 `struct sk_buff *skb`，从而可以作为一个网络包进行后续的处理，然后调用 `netif_receive_skb()`进入MAC层继续进行收包的解析处理。

```c
static int ixgb_clean(struct napi_struct *napi, int budget)
{
    struct ixgb_adapter *adapter = container_of(napi, struct ixgb_adapter, napi);
    int work_done = 0;
    ixgb_clean_tx_irq(adapter);
    ixgb_clean_rx_irq(adapter, &work_done, budget);
......
    return work_done;
}
​
static bool
ixgb_clean_rx_irq(struct ixgb_adapter *adapter, int *work_done, int work_to_do)
{
    struct ixgb_desc_ring *rx_ring = &adapter->rx_ring;
    struct net_device *netdev = adapter->netdev;
    struct pci_dev *pdev = adapter->pdev;
    struct ixgb_rx_desc *rx_desc, *next_rxd;
    struct ixgb_buffer *buffer_info, *next_buffer, *next2_buffer;
    u32 length;
    unsigned int i, j;
    int cleaned_count = 0;
    bool cleaned = false;
​
    i = rx_ring->next_to_clean;
    rx_desc = IXGB_RX_DESC(*rx_ring, i);
    buffer_info = &rx_ring->buffer_info[i];
​
    while (rx_desc->status & IXGB_RX_DESC_STATUS_DD) {
        struct sk_buff *skb;
        u8 status;
​
        status = rx_desc->status;
        skb = buffer_info->skb;
        buffer_info->skb = NULL;
​
        prefetch(skb->data - NET_IP_ALIGN);
​
        if (++i == rx_ring->count)
            i = 0;
        next_rxd = IXGB_RX_DESC(*rx_ring, i);
        prefetch(next_rxd);
​
        j = i + 1;
        if (j == rx_ring->count)
            j = 0;
        next2_buffer = &rx_ring->buffer_info[j];
        prefetch(next2_buffer);
​
        next_buffer = &rx_ring->buffer_info[i];
......
        length = le16_to_cpu(rx_desc->length);
        rx_desc->length = 0;
......
        ixgb_check_copybreak(&adapter->napi, buffer_info, length, &skb);
​
        /* Good Receive */
        skb_put(skb, length);
​
        /* Receive Checksum Offload */
        ixgb_rx_checksum(adapter, rx_desc, skb);
​
        skb->protocol = eth_type_trans(skb, netdev);
​
        netif_receive_skb(skb);
......
        /* use prefetched values */
        rx_desc = next_rxd;
        buffer_info = next_buffer;
    }
​
    rx_ring->next_to_clean = i;
......
}
```

## 三. MAC层

  从 `netif_receive_skb()` 函数开始，我们就进入了内核的网络协议栈。接下来的调用链为：`netif_receive_skb()->netif_receive_skb_internal()->__netif_receive_skb()->__netif_receive_skb_core()`。在 `__netif_receive_skb_core()` 中，我们先是处理了二层的一些逻辑，如对于 VLAN 的处理，如果不是则调用`deliver_ptype_list_skb()` 在一个协议列表中逐个匹配在网络包 struct sk\_buff 里面定义的 `skb->protocol`，该变量表示三层使用的协议类型。

```c
static int __netif_receive_skb_core(struct sk_buff *skb, bool pfmemalloc)
{
    struct packet_type *ptype, *pt_prev;
......
    if (skb_vlan_tag_present(skb)) {
        if (pt_prev) {
            ret = deliver_skb(skb, pt_prev, orig_dev);
            pt_prev = NULL;
        }
        if (vlan_do_receive(&skb))
            goto another_round;
        else if (unlikely(!skb))
            goto out;
    }
......
    type = skb->protocol;
......
    deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
             &orig_dev->ptype_specific);
......
}
​
static inline void deliver_ptype_list_skb(struct sk_buff *skb,
            struct packet_type **pt,
            struct net_device *orig_dev,
            __be16 type,
            struct list_head *ptype_list)
{
    struct packet_type *ptype, *pt_prev = *pt;
​
    list_for_each_entry_rcu(ptype, ptype_list, list) {
        if (ptype->type != type)
            continue;
        if (pt_prev)
            deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }
    *pt = pt_prev;
}
```

无论是VLAN还是普通的包，最后的发送均会调用`deliver_skb()`，该函数会调用协议定义好的函数进行网络层解析。对于IP协议即为`ip_rcv()`。

```c
static inline int deliver_skb(struct sk_buff *skb,
			      struct packet_type *pt_prev,
			      struct net_device *orig_dev)
{
    if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC)))
        return -ENOMEM;
    refcount_inc(&skb->users);
    return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}

static struct packet_type ip_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_IP),
    .func = ip_rcv,
};
```

## 四. 网络层

  在`ip_rcv()`中，我们又看到了熟悉的Netfilter，这次对应的是`PREROUTING`状态，执行完定义的钩子函数后，会继续执行`ip_rcv_finish()`。

```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);
	skb = ip_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}
```

  `ip_rcv_finish()` 首先调用`ip_rcv_finish_core()`，该函数会先检测是否为广播、组播，如果不是则得到网络包对应的路由表，然后调用 `dst_input()`，在 `dst_input()` 中，调用的是 `struct rtable` 的成员的 `dst` 的 `input()` 函数。在 `rt_dst_alloc()` 中，我们可以看到`input` 函数指向的是 `ip_local_deliver()`。

```c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb->dev;
    int ret;
    /* if ingress device is enslaved to an L3 master device pass the
	  * skb to its handler for processing
	  */
    skb = l3mdev_ip_rcv(skb);
    if (!skb)
	      return NET_RX_SUCCESS;
    ret = ip_rcv_finish_core(net, sk, skb, dev);
    if (ret != NET_RX_DROP)
        ret = dst_input(skb);
    return ret;
}

static inline int dst_input(struct sk_buff *skb)
{
    return skb_dst(skb)->input(skb);
}
```

  进入`ip_local_deliver()`意味着从`PREROUTING`确认进入本机处理，所以进入了状态`INPUT`，如果 IP 层进行了分段，则进行重新的组合。接下来就是我们熟悉的 `NF_HOOK`。在经过 `iptables` 规则处理完毕后，会调用 `ip_local_deliver_finish()`。

```c
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);
	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
```

  `ip_local_deliver_finish()`首先调用`__skb_pull()`从`sk_buff`中取下一个，接着调用`ip_protocol_deliver_rcu()`，该函数会从`inet_protos[protocol]`中找寻对应的处理函数进一步对收到的数据包进行解析。对应TCP的是`tcp_v4_rcv()`，UDP则是`udp_rcv()`。

```c
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    __skb_pull(skb, skb_network_header_len(skb));
    rcu_read_lock();
    ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
    rcu_read_unlock();
	return 0;
}

static struct net_protocol tcp_protocol = {
......
  .handler  =  tcp_v4_rcv,
......
};

static struct net_protocol udp_protocol = {
......
  .handler =  udp_rcv,
......
};
```

## 五. 传输层

  在 `tcp_v4_rcv()` 中，首先会获取 TCP 的头部，接着就开始处理 TCP 层的事情。因为 TCP 层是分状态的，状态被维护在数据结构 `struct sock` 里面，因而要根据 `IP` 地址以及 `TCP` 头里面的内容，在 `tcp_hashinfo` 中找到这个包对应的 struct sock，从而得到这个包对应的连接的状态。接下来就根据不同的状态做不同的处理。如在前文三次握手的分析中已经剖析了`TCP_NEW_SYN_RECV`后续的逻辑。对于正常通信包，则会涉及到三条队列的操作。

```c
int tcp_v4_rcv(struct sk_buff *skb)
{
    struct net *net = dev_net(skb->dev);
    int sdif = inet_sdif(skb);
    const struct iphdr *iph;
    const struct tcphdr *th;
    bool refcounted;
    struct sock *sk;
    int ret;
......
    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);
lookup:
    sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source,
			       th->dest, sdif, &refcounted);
    if (!sk)
        goto no_tcp_socket;
process:
    if (sk->sk_state == TCP_TIME_WAIT)
        goto do_time_wait;
    if (sk->sk_state == TCP_NEW_SYN_RECV) {
    ......
    }
......
    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);
    tcp_v4_fill_cb(skb, iph, th);
    skb->dev = NULL;
    if (sk->sk_state == TCP_LISTEN) {
        ret = tcp_v4_do_rcv(sk, skb);
        goto put_and_return;
    }
......
    if (!sock_owned_by_user(sk)) {
        ret = tcp_v4_do_rcv(sk, skb);
    } else if (tcp_add_backlog(sk, skb)) {
        goto discard_and_relse;
    }
......
    case TCP_TW_SYN: {
......
    }
    /* to ACK */
    /* fall through */
    case TCP_TW_ACK:
......
    case TCP_TW_RST:
......
    case TCP_TW_SUCCESS:;
    }
    goto discard_it;
}
```

  网络包接收过程中常见的三个队列为

* backlog 队列：软中断过程中的数据包处理队列
* prequeue 队列：用户态进程读队列
* sk\_receive\_queue 队列：内核态数据包缓存队列

  存在三个队列的原因是运行至`tcp_v4_rcv()`时，依然处于软中断的处理逻辑里，所以必然会占用这个软中断。如果用户态使用了系统调用`read()`读取数据包，则放入`prequeue`队列等待读取，如果暂时没有读取请求，则放入内核态的缓存队列`sk_receive_queue`中等候用户态请求。

  `tcp_v4_rcv()`调用`sock_owned_by_user()`判断该包现在是否正在被用户态进行读操作，如果没有则调用`tcp_add_backlog()`暂存在 `backlog` 队列中，并且抓紧离开软中断的处理过程，如果是则调用 `tcp_prequeue()`，将数据包放入 `prequeue` 队列并且离开软中断的处理过程。在这个函数里面，会对 `sysctl_tcp_low_latency` 进行判断，也即是不是要低时延地处理网络包。如果把 `sysctl_tcp_low_latency` 设置为 0，那就要放在 `prequeue` 队列中暂存，这样不用等待网络包处理完毕，就可以离开软中断的处理过程，但是会造成比较长的时延。如果把 `sysctl_tcp_low_latency` 设置为 1，则调用 `tcp_v4_do_rcv()`立即处理。

  **特别注意**：在2017年的一个[patch](https://lwn.net/Articles/729155/)中，有大佬提出取消prequeue队列以顺应新的TCP需求。但是我们这里依然以三条队列进行分析，实际上代码中较新的版本已经没有了`tcp_prequeue()`函数。之所以取消`prequeue`，是因为在大多使用事件驱动\(epoll\)的当下，已经很少有阻塞在`recvfrom()`或者`read()`的服务端代码了。**下面分析中会加上`prequeue`相关功能，但是实际代码中不一定有**。

  在 `tcp_v4_do_rcv()` 中会分两种情况处理，一种情况是连接已经建立，处于 `TCP_ESTABLISHED` 状态，调用 `tcp_rcv_established()`。另一种情况，就是未建立连接的状态，调用 `tcp_rcv_state_process()`。关于`tcp_rcv_state_process()`在三次握手中已分析过了，这里重点看`tcp_rcv_established()`。该函数会调用 `tcp_data_queue()`，将数据包放入 `sk_receive_queue` 队列进行处理。

```c
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
{
	const struct tcphdr *th = (const struct tcphdr *)skb->data;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int len = skb->len;
......
	tcp_data_queue(sk, skb);
	tcp_data_snd_check(sk);
	tcp_ack_snd_check(sk);
	return;
......
}
```

  在 `tcp_data_queue()` 中，对于收到的网络包，我们要分情况进行处理。

* 第一种情况，`seq == tp->rcv_nxt`，说明来的网络包正是我服务端期望的下一个网络包。
  * 调用 `sock_owned_by_user()`判断用户进程是否正在等待读取，如果是则直接调用 `skb_copy_datagram_msg()`，将网络包拷贝给用户进程就可以了。如果用户进程没有正在等待读取，或者因为内存原因没有能够拷贝成功，`tcp_queue_rcv()` 里面还是将网络包放入 `sk_receive_queue` 队列。
  * 调用`tcp_rcv_nxt_update()` 将 `tp->rcv_nxt` 设置为 `end_seq`，也即当前的网络包接收成功后，更新下一个期待的网络包
  * 判断一下另一个队列`out_of_order_queue`，即乱序队列的情况，看看乱序队列里面的包会不会因为这个新的网络包的到来，也能放入到 `sk_receive_queue` 队列中。
* 第二种情况，`end_seq` 小于 `rcv_nxt`，也即服务端期望网络包 5。但是，来了一个网络包 3，怎样才会出现这种情况呢？肯定是服务端早就收到了网络包 3，但是 ACK 没有到达客户端，中途丢了，那客户端就认为网络包 3 没有发送成功，于是又发送了一遍，这种情况下，要赶紧给客户端再发送一次 ACK，表示早就收到了。
* 第三种情况，`seq` 大于 `rcv_nxt + tcp_receive_window`。这说明客户端发送得太猛了。本来 `seq` 肯定应该在接收窗口里面的，这样服务端才来得及处理，结果现在超出了接收窗口，说明客户端一下子把服务端给塞满了。这种情况下，服务端不能再接收数据包了，只能发送 ACK 了，在 ACK 中会将接收窗口为 0 的情况告知客户端，客户端就知道不能再发送了。这个时候双方只能交互窗口探测数据包，直到服务端因为用户进程把数据读走了，空出接收窗口，才能在 ACK 里面再次告诉客户端，又有窗口了，又能发送数据包了。
* 第四种情况，`seq` 小于 `rcv_nxt`，但是 `end_seq` 大于 `rcv_nxt`，这说明从 `seq` 到 `rcv_nxt` 这部分网络包原来的 ACK 客户端没有收到，所以重新发送了一次，从 `rcv_nxt` 到 `end_seq` 是新发送的，可以放入 `sk_receive_queue` 队列。
* 第五种情况，是正好在接收窗口内但是不是期望接收的下一个包，则说明发生了乱序，调用`tcp_data_queue_ofo()`加入乱序队列中。

```c
static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    bool fragstolen = false;
......
    if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {
    	if (tcp_receive_window(tp) == 0)
        	goto out_of_window;

    	/* Ok. In sequence. In window. */
    	if (tp->ucopy.task == current &&
        		tp->copied_seq == tp->rcv_nxt && tp->ucopy.len &&
        		sock_owned_by_user(sk) && !tp->urg_data) {
      		int chunk = min_t(unsigned int, skb->len, tp->ucopy.len);

      		__set_current_state(TASK_RUNNING);

      		if (!skb_copy_datagram_msg(skb, 0, tp->ucopy.msg, chunk)) {
        		tp->ucopy.len -= chunk;
        		tp->copied_seq += chunk;
        		eaten = (chunk == skb->len);
        		tcp_rcv_space_adjust(sk);
      		}
    	}

    	if (eaten <= 0) {
queue_and_out:
......
      	eaten = tcp_queue_rcv(sk, skb, 0, &fragstolen);
    	}
    	tcp_rcv_nxt_update(tp, TCP_SKB_CB(skb)->end_seq);
......
    	if (!RB_EMPTY_ROOT(&tp->out_of_order_queue)) 
        	tcp_ofo_queue(sk);
......
    	return;
    }
    if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
    	/* A retransmit, 2nd most common case.  Force an immediate ack. */
    	tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

out_of_window:
    	tcp_enter_quickack_mode(sk);
    	inet_csk_schedule_ack(sk);
drop:
    	tcp_drop(sk, skb);
    	return;
    }

    /* Out of window. F.e. zero window probe. */
    if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt + tcp_receive_window(tp)))
    	goto out_of_window;

    tcp_enter_quickack_mode(sk);

    if (before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
    	/* Partial packet, seq < rcv_next < end_seq */
    	tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);
    	/* If window is closed, drop tail of packet. But after
     	* remembering D-SACK for its head made in previous line.
     	*/
    	if (!tcp_receive_window(tp))
        	goto out_of_window;
    	goto queue_and_out;
  	}

  	tcp_data_queue_ofo(sk, skb);
}
```

## 六. 套接字层

  当接收的网络包进入各种队列之后，接下来我们就要等待用户进程去读取它们了。读取一个 `socket`，就像读取一个文件一样，读取 `socket` 的文件描述符，通过 `read` 系统调用。`read` 系统调用对于一个文件描述符的操作，大致过程都是类似的，在文件系统那一节，我们已经详细解析过。最终它会调用到用来表示一个打开文件的结构 `stuct file` 指向的 `file_operations` 操作。

```c
static const struct file_operations socket_file_ops = {
......
  .read_iter =  sock_read_iter,
......
};
```

  `sock_read_iter()`首先从虚拟文件系统中获取对应的文件，然后通过`file`获取对应的套接字`sock`，接着调用`sock_recvmsg()`读取该套接字对应的连接的数据包缓存队列。

```c
static ssize_t sock_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct socket *sock = file->private_data;
	struct msghdr msg = {.msg_iter = *to,
			     .msg_iocb = iocb};
	ssize_t res;
......
	res = sock_recvmsg(sock, &msg, msg.msg_flags);
	*to = msg.msg_iter;
	return res;
}
```

  `sock_recvmsg()`实际调用`sock_recvmmsg_nosec()`，该函数会调用套接字对应的读操作，即`inet_recvmsg()`。

```text
int sock_recvmsg(struct socket *sock, struct msghdr *msg, int flags)
{
	int err = security_socket_recvmsg(sock, msg, msg_data_left(msg), flags);
	return err ?: sock_recvmsg_nosec(sock, msg, flags);
}

static inline int sock_recvmsg_nosec(struct socket *sock, struct msghdr *msg,
				     int flags)
{
	return sock->ops->recvmsg(sock, msg, msg_data_left(msg), flags);
}
```

  `inet_recvmsg()`会调用协议对应的读操作，即`tcp_recvmsg()`进行读操作。

```c
int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		 int flags)
{
	struct sock *sk = sock->sk;
......
	err = sk->sk_prot->recvmsg(sk, msg, size, flags & MSG_DONTWAIT,
				   flags & ~MSG_DONTWAIT, &addr_len);
......
}
```

  `tcp_recvmsg()`通过一个循环读取队列中的数据包，直至读完。循环内的逻辑为：

* 处理`sk_receive_queue`队列：调用`skb_peek_tail()`获取队列中的一项，并调用`skb_queue_walk()`处理。如果找到了网络包，就跳到 `found_ok_skb` 这里。这里会调用 `skb_copy_datagram_msg()`将网络包拷贝到用户进程中，然后直接进入下一层循环。
* 处理`prequeue`队列**（已废弃）**：直到 `sk_receive_queue` 队列处理完毕才到了 `sysctl_tcp_low_latency` 判断。如果不需要低时延，则会有 `prequeue` 队列。于是跳到 `do_prequeue` 这里，调用 `tcp_prequeue_process()` 进行处理。
* 处理`backlog`队列：调用`release_sock()`完成。`release_sock()` 会调用 `__release_sock()`，这里面会依次处理队列中的网络包。
* 处理完所有队列后，调用 `sk_wait_data()`，继续等待在哪里，等待网络包的到来。

```c
int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err, inq;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct sk_buff *skb, *last;
......
	do {
		u32 offset;
......
		/* Next get a buffer. */
		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			last = skb;
......
			offset = *seq - TCP_SKB_CB(skb)->seq;
......
			if (offset < skb->len)
				goto found_ok_skb;
......
		}
		/* Well, if we have backlog, try to process it now yet. */
		if (copied >= target && !sk->sk_backlog.tail)
			break;
		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} 
......
		tcp_cleanup_rbuf(sk, copied);
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else {
			sk_wait_data(sk, &timeo, last);
		}
......
found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;
		/* Do we have urgent data here? */
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}
		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			if (err) {
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}
		*seq += used;
		copied += used;
		len -= used;
		tcp_rcv_space_adjust(sk);
......
	} while (len > 0);
......
}
```

## 总结

  至此网络协议栈的收发流程都已经分析完毕了。收包流程可以总结为以下过程

* 硬件网卡接收到网络包之后，通过 DMA 技术，将网络包放入 Ring Buffer；
* 硬件网卡通过中断通知 CPU 新的网络包的到来；
* 网卡驱动程序会注册中断处理函数 ixgb\_intr；
* 中断处理函数处理完需要暂时屏蔽中断的核心流程之后，通过软中断 NET\_RX\_SOFTIRQ 触发接下来的处理过程；
* NET\_RX\_SOFTIRQ 软中断处理函数 `net_rx_action`，`net_rx_action` 会调用 `napi_poll`，进而调用 `ixgb_clean_rx_irq`，从 Ring Buffer 中读取数据到内核 `struct sk_buff`；
* 调用 `netif_receive_skb` 进入内核网络协议栈，进行一些关于 VLAN 的二层逻辑处理后，调用 `ip_rcv` 进入三层 IP 层；
* 在 IP 层，会处理 `iptables` 规则，然后调用 `ip_local_deliver` 交给更上层 TCP 层；
* 在 TCP 层调用 `tcp_v4_rcv`，这里面有三个队列需要处理，如果当前的 `Socket` 不是正在被读取，则放入 `backlog` 队列，如果正在被读取，不需要很实时的话，则放入 `prequeue` 队列，其他情况调用 `tcp_v4_do_rcv`；
* 在 `tcp_v4_do_rcv` 中，如果是处于 `TCP_ESTABLISHED` 状态，调用 `tcp_rcv_established`，其他的状态，调用 `tcp_rcv_state_process`；
* 在 `tcp_rcv_established` 中，调用 `tcp_data_queue`，如果序列号能够接的上，则放入 `sk_receive_queue` 队列；
* 如果序列号接不上，则暂时放入 `out_of_order_queue` 队列，等序列号能够接上的时候，再放入 `sk_receive_queue` 队列。

至此内核接收网络包的过程到此结束，接下来就是用户态读取网络包的过程，这个过程分成几个层次。

* VFS 层：`read` 系统调用找到 `struct file`，根据里面的 `file_operations` 的定义，调用 `sock_read_iter` 函数。`sock_read_iter` 函数调用 `sock_recvmsg` 函数。
* Socket 层：从 `struct file` 里面的 `private_data` 得到 `struct socket`，根据里面 `ops`的定义，调用 `inet_recvmsg` 函数。
* Sock 层：从 `struct socket` 里面的 `sk` 得到 `struct sock`，根据里面 `sk_prot` 的定义，调用 `tcp_recvmsg` 函数。
* TCP 层：`tcp_recvmsg` 函数会依次读取 `receive_queue` 队列、`prequeue` 队列和 `backlog` 队列。

![img](https://static001.geekbang.org/resource/image/20/52/20df32a842495d0f629ca5da53e47152.png)

## 源码资料

\[1\] [ixgb\_init\_module\(\)](https://code.woboq.org/linux/linux/drivers/net/ethernet/intel/ixgb/ixgb_main.c.html#ixgb_init_module)

\[2\] [\_\_napi\_schedule\(\)](https://code.woboq.org/linux/linux/net/core/dev.c.html#5967)

\[3\] [ip\_rcv\(\)](https://code.woboq.org/linux/linux/net/ipv4/ip_input.c.html#ip_rcv)

\[4\] [tcp\_v4\_rcv\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp_ipv4.c.html#tcp_v4_rcv)

\[5\] [sock\_read\_iter\(\)](https://code.woboq.org/linux/linux/net/socket.c.html#sock_read_iter)

\[6\] [inet\_recvmsg\(\)](https://code.woboq.org/linux/linux/net/ipv4/af_inet.c.html#inet_recvmsg)

\[7\] [tcp\_recvmsg\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp.c.html#tcp_recvmsg)

## 参考资料

\[1\] wiki

\[2\] [elixir.bootlin.com/linux](https://elixir.bootlin.com/linux/v5.7-rc1/source)

\[3\] [woboq](https://code.woboq.org/)

\[4\] Linux-insides

\[5\] 深入理解Linux内核

\[6\] Linux内核设计的艺术

\[7\] 极客时间 趣谈Linux操作系统

\[8\] 深入理解Linux网络技术内幕

