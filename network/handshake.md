# 网络通信之三次握手

### 一. 前言

  三次握手的基本知识在前文中已说明，本文从源码入手来详细分析其实现原理。

### 二. 基本过程和API

  一个简单的TCP客户端/服务端模型如下所示，其中`Socket()`会创建套接字并返回描述符，在前文已经详细分析过。之后`bind()`会绑定本地的IP/Port二元组用以定位，而`connect(), listen(), accept()`则是本篇的重点所在，即通过三次握手完成连接的建立。

![img](https://static001.geekbang.org/resource/image/99/da/997e39e5574252ada22220e4b3646dda.png)

### 三. 源码分析

#### 3.1 `bind`

  首先来看看`bind()`函数。其API如下所示

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
​
struct sockaddr_in {
    __kernel_sa_family_t  sin_family;  /* Address family    */
    __be16    sin_port;  /* Port number      */
    struct in_addr  sin_addr;  /* Internet address    */
​
    /* Pad to size of `struct sockaddr'. */
    unsigned char    __pad[__SOCK_SIZE__ - sizeof(short int) -
      sizeof(unsigned short int) - sizeof(struct in_addr)];
};
​
struct in_addr {
    __be32  s_addr;
};
```

  该函数比较简单，主要是为套接字分配指定的IP地址及端口。在 `bind()` 中主要逻辑如下

* 调用`sockfd_lookup_light()` 根据 `fd` 文件描述符，找到 struct socket 结构
* 调用`move_addr_to_kernel()`将 `sockaddr` 从用户态拷贝到内核态
* 调用 `struct socket` 结构里面 `ops` 的 `bind()` 函数。根据前面创建 `socket` 的时候的设定，调用的是 `inet_stream_ops` 的 `bind()` 函数，也即调用 `inet_bind()`。

```c
SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{
    return __sys_bind(fd, umyaddr, addrlen);
}
​
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    struct socket *sock;
    struct sockaddr_storage address;
    int err, fput_needed;
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock) {
        err = move_addr_to_kernel(umyaddr, addrlen, &address);
        if (!err) {
            err = security_socket_bind(sock,
                           (struct sockaddr *)&address,
                           addrlen);
            if (!err)
                err = sock->ops->bind(sock,
                              (struct sockaddr *)
                              &address, addrlen);
        }
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

  `sockfd_lookup_light()`主要逻辑如下：

* 调用`fdget()->__fdget()->__fget_light()->__fcheck_files()`获取文件`file`和`flag`组合成的结构体`fd`
* 调用`sock_from_file()`获取`file`对应的套接字`sock`

```c
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
    struct fd f = fdget(fd);
    struct socket *sock;
    *err = -EBADF;
    if (f.file) {
        sock = sock_from_file(f.file, err);
        if (likely(sock)) {
            *fput_needed = f.flags;
            return sock;
        }
        fdput(f);
    }
    return NULL;
}
```

  `inet_bind()`作用于网络层，因为传输层实际并无IP地址信息。主要逻辑为

* 调用 `sk_prot` 的 `get_port()` 函数，也即 `inet_csk_get_port()` 来检查端口是否冲突，是否可以绑定。
* 如果允许，则会设置 `struct inet_sock` 的本地地址 `inet_saddr` 和本地端口 `inet_sport`，对方的地址 `inet_daddr` 和对方的端口 `inet_dport` 都初始化为 0。

```c
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sock *sk = sock->sk;
......
    return __inet_bind(sk, uaddr, addr_len, false, true);
}
​
int __inet_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len,
        bool force_bind_address_no_port, bool with_lock)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    unsigned short snum;
......
    snum = ntohs(addr->sin_port);
......
    inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
    if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
        inet->inet_saddr = 0;  /* Use device */
    /* Make sure we are allowed to bind here. */
    if (snum || !(inet->bind_address_no_port ||
              force_bind_address_no_port)) {
        if (sk->sk_prot->get_port(sk, snum)) {
            inet->inet_saddr = inet->inet_rcv_saddr = 0;
            err = -EADDRINUSE;
            goto out_release_sock;
        }
......
    }
......
    inet->inet_sport = htons(inet->inet_num);
    inet->inet_daddr = 0;
    inet->inet_dport = 0;
    sk_dst_reset(sk);
......
}
```

#### 3.2 `listen`

  `listen()`的API如下，其中`backlog`需要注意，其定义为套接字监听队列的最大长度，实际上会有个小坑，具体可见[这篇博文](https://segmentfault.com/a/1190000019252960)分析。

```c
int listen(int sockfd, int backlog);
```

  其函数调用如下，主要逻辑为

* 调用`sockfd_lookup_light()`查找套接字
* 根据`sysctl_somaxconn`和`backlog`取较小值作为监听的队列上限
* 调用 `ops` 的 `listen()` 函数，实际调用`inet_stream_ops`中的`inet_listen()`

```c
SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
    return __sys_listen(fd, backlog);
}
​
int __sys_listen(int fd, int backlog)
{
    struct socket *sock;
    int err, fput_needed;
    int somaxconn;
    sock = sockfd_lookup_light(fd, &err, &fput_needed);
    if (sock) {
        somaxconn = sock_net(sock->sk)->core.sysctl_somaxconn;
        if ((unsigned int)backlog > somaxconn)
            backlog = somaxconn;
        err = security_socket_listen(sock, backlog);
        if (!err)
            err = sock->ops->listen(sock, backlog);
        fput_light(sock->file, fput_needed);
    }
    return err;
}
```

  `inet_listen()`主要逻辑为判断套接字`sock`是否处于监听状态`TCP_LISTEN`，如果不是则调用`inet_csk_listen_start()`进入监听状态。

```c
int inet_listen(struct socket *sock, int backlog)
{
    struct sock *sk = sock->sk;
    unsigned char old_state;
    int err, tcp_fastopen;
......
    sk->sk_max_ack_backlog = backlog;
    /* Really, if the socket is already in listen state
     * we can only allow the backlog to be adjusted.
     */
    if (old_state != TCP_LISTEN) {
......
        err = inet_csk_listen_start(sk, backlog);
......
    }
    err = 0;
out:
    release_sock(sk);
    return err;
}
```

  `inet_csk_listen_start()`主要逻辑如下：

* 建立了一个新的结构 `inet_connection_sock`，这个结构一开始是 `struct inet_sock`，`inet_csk` 其实做了一次强制类型转换扩大了结构。`struct inet_connection_sock` 结构比较复杂。如果打开它，你能看到处于各种状态的队列，各种超时时间、拥塞控制等字眼。我们说 TCP 是面向连接的，就是客户端和服务端都是有一个结构维护连接的状态，就是指这个结构。
* 初始化`icsk_accept_queue`队列。我们知道三次握手中有两个队列：半连接队列和全连接队列。其中半连接队列指三次握手还没完成，处于 `syn_rcvd` 的状态的连接，全连接指三次握手已经完毕，处于 `established` 状态的连接。`icsk_accept_queue`队列就是半连接队列，调用`accept()`函数时会从该队列取出连接进行判断，如果三次握手顺利完成则放入全连接队列。
* 将TCP状态设置为`TCP_LISTEN`，调用`get_port()`确保端口可用。

```c
int inet_csk_listen_start(struct sock *sk, int backlog)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct inet_sock *inet = inet_sk(sk);
    int err = -EADDRINUSE;
    
    reqsk_queue_alloc(&icsk->icsk_accept_queue);
    sk->sk_ack_backlog = 0;
    inet_csk_delack_init(sk);
    /* There is race window here: we announce ourselves listening,
     * but this transition is still not validated by get_port().
     * It is OK, because this socket enters to hash table only
     * after validation is complete.
     */
    inet_sk_state_store(sk, TCP_LISTEN);
    if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
        inet->inet_sport = htons(inet->inet_num);
        sk_dst_reset(sk);
        err = sk->sk_prot->hash(sk);
        if (likely(!err))
            return 0;
    }
    
    inet_sk_set_state(sk, TCP_CLOSE);
    return err;
}
```

#### 3.3`accept`

  `accept()`的API如下，服务端调用`accept()`会在监听套接字的基础上创建新的套接字来作为连接套接字，并返回连接套接字的描述符。

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

  对应的系统调用如下，从这里可以很清楚的看到新套接字的创立，主要逻辑为：

* 调用`sockfd_lookup_light()`查找描述符`fd`对应的监听套接字`sock`
* 创建新套接字`newsock`，类型和操作和监听套接字保持一致，并创建新的文件`newfile`和套接字绑定
* 调用套接字对应的`accept()`函数，即`inet_accept()`完成实际服务端握手过程
* 调用`fd_install()`关联套接字文件和套接字描述符，并返回连接的套接字描述符

```c
SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen)
{
	  return __sys_accept4(fd, upeer_sockaddr, upeer_addrlen, 0);
}

int __sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr,
		  int __user *upeer_addrlen, int flags)
{
	  struct socket *sock, *newsock;
	  struct file *newfile;
	  int err, len, newfd, fput_needed;
	  struct sockaddr_storage address;
......
	  sock = sockfd_lookup_light(fd, &err, &fput_needed);
......
	  newsock = sock_alloc();
......
	  newsock->type = sock->type;
	  newsock->ops = sock->ops;
......
	  __module_get(newsock->ops->owner);
	  newfd = get_unused_fd_flags(flags);
......
	  newfile = sock_alloc_file(newsock, flags, sock->sk->sk_prot_creator->name);
......
	  err = sock->ops->accept(sock, newsock, sock->file->f_flags, false);
	  if (err < 0)
		    goto out_fd;
	  if (upeer_sockaddr) {
		    len = newsock->ops->getname(newsock,
					(struct sockaddr *)&address, 2);
		    if (len < 0) {
			      err = -ECONNABORTED;
			      goto out_fd;
		    }
		    err = move_addr_to_user(&address,
					len, upeer_sockaddr, upeer_addrlen);
		    if (err < 0)
			      goto out_fd;
	  }
	/* File flags are not inherited via accept() unlike another OSes. */
	  fd_install(newfd, newfile);
......
}
```

  `inet_accept()`会提取监听套接字的网络层结构体`sk1`和新建套接字的`sk2`，调用`sk1`协议对应的`accept()`完成握手并保存连接状态于`sk2`中，这里实际调用的是`inet_csk_accept()`函数。接着将`sk2`和新建套接字进行关联。

```c
int inet_accept(struct socket *sock, struct socket *newsock, int flags,
        bool kern)
{
    struct sock *sk1 = sock->sk;
    int err = -EINVAL;
    struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err, kern);
    if (!sk2)
        goto do_err;
    lock_sock(sk2);
    sock_rps_record_flow(sk2);
    WARN_ON(!((1 << sk2->sk_state) &
          (TCPF_ESTABLISHED | TCPF_SYN_RECV |
          TCPF_CLOSE_WAIT | TCPF_CLOSE)));
    sock_graft(sk2, newsock);
    newsock->state = SS_CONNECTED;
    err = 0;
    release_sock(sk2);
do_err:
    return err;
}
```

  `inet_csk_accept()`函数会判断当前的半连接队列`rskq_accept_queue`是否为空，如果空则调用`inet_csk_wait_for_connect()`及逆行等待。如果不为空则从队列中取出一个连接，赋值给`newsk`并返回。

```c
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct request_sock_queue *queue = &icsk->icsk_accept_queue;
    struct request_sock *req;
    struct sock *newsk;
    int error;
......
    /* Find already established connection */
    if (reqsk_queue_empty(queue)) {
......
        error = inet_csk_wait_for_connect(sk, timeo);
......
    }
    req = reqsk_queue_remove(queue, sk);
    newsk = req->sk;
......
}
```

  `inet_csk_wait_for_connect()`调用 `schedule_timeout()`让出 CPU，并且将进程状态设置为 `TASK_INTERRUPTIBLE`。如果再次 CPU 醒来，我们会接着判断 `icsk_accept_queue` 是否为空，同时也会调用 `signal_pending` 看有没有信号可以处理。一旦 `icsk_accept_queue` 不为空，就从 `inet_csk_wait_for_connect()` 中返回，在队列中取出一个 `struct sock` 对象赋值给 `newsk`。

```c
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    DEFINE_WAIT(wait);
    int err;
    for (;;) {
        prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
        release_sock(sk);
        if (reqsk_queue_empty(&icsk->icsk_accept_queue))
            timeo = schedule_timeout(timeo);
        sched_annotate_sleep();
        lock_sock(sk);
        err = 0;
        if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
            break;
        err = -EINVAL;
        if (sk->sk_state != TCP_LISTEN)
            break;
        err = sock_intr_errno(timeo);
        if (signal_pending(current))
            break;
        err = -EAGAIN;
        if (!timeo)
            break;
    }
    finish_wait(sk_sleep(sk), &wait);
    return err;
}
```

#### 3.4 `connect`

  `connect()`函数通常由客户端发起，是三次握手的开始，服务端收到了`SYN`之后回复`ACK + SYN`并将该连接加入半连接队列，进入`SYN_RCVD`状态，第三次握手收到`ACK`后从半连接队列取出，加入全连接队列，此时的 socket 处于 `ESTABLISHED` 状态。`accept()`函数唤醒后检索队列，发现有连接则继续工作下去，从队列中取出该套接字并返回，供以后续读写使用。

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

  `connect()`对应的系统调用如下所示，其主要逻辑为：

* 调用`sockfd_lookup_light()`查找套接字描述符`fd`对应的套接字`sock`
* 调用`move_addr_to_kernel()`将目的地址发到内核中供使用
* 调用初始化`connect()`函数或者设置的特定`connect()`函数，这里会调用`inet_stream_connect()`发起连接

```c
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	return __sys_connect(fd, uservaddr, addrlen);
}

int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;
	err = move_addr_to_kernel(uservaddr, addrlen, &address);
	if (err < 0)
		goto out_put;
	err = security_socket_connect(sock, (struct sockaddr *)&address, addrlen);
	if (err)
		goto out_put;
	err = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,
				 sock->file->f_flags);
out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}
```

  `inet_stream_connect()`主要逻辑为

* 判断当前套接字状态，如果尚未连接则调用 `struct sock` 的 `sk->sk_prot->connect()`，也即 `tcp_prot` 的 `connect()` 函数`tcp_v4_connect()` 函数发起握手。
* 调用`inet_wait_for_connect()`，等待来自于服务端的`ACK`信号

```c
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
......
	err = __inet_stream_connect(sock, uaddr, addr_len, flags, 0);
......
}

int __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			  int addr_len, int flags, int is_sendmsg)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;
......
	switch (sock->state) {
......
	case SS_UNCONNECTED:
......
		if (BPF_CGROUP_PRE_CONNECT_ENABLED(sk)) {
			err = sk->sk_prot->pre_connect(sk, uaddr, addr_len);
			if (err)
				goto out;
		}
		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;
		sock->state = SS_CONNECTING;
......
	}
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
......
		/* Error code is set above */
		if (!timeo || !inet_wait_for_connect(sk, timeo, writebias))
			goto out;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}
......
	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */
	sock->state = SS_CONNECTED;
......
}
```

`tcp_v4_connect()`主要逻辑为

* 调用`ip_route_connect()`选择一条路由，根据选定的网卡填写该网卡的 IP 地址作为源IP地址
* 将客户端状态设置为`TCP_SYN_SENT`，初始化序列号`write_seq`
* 调用`tcp_connect()`发送`SYN`包

```c
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
    struct inet_sock *inet = inet_sk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    __be16 orig_sport, orig_dport;
    __be32 daddr, nexthop;
    struct flowi4 *fl4;
    struct rtable *rt;
......
    orig_sport = inet->inet_sport;
    orig_dport = usin->sin_port;
    fl4 = &inet->cork.fl.u.ip4;
    rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
                  RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
                  IPPROTO_TCP,
                  orig_sport, orig_dport, sk);
......
    /* Socket identity is still unknown (sport may be zero).
     * However we set state to SYN-SENT and not releasing socket
     * lock select source port, enter ourselves into the hash tables and
     * complete initialization after this.
     */
    tcp_set_state(sk, TCP_SYN_SENT);
    err = inet_hash_connect(tcp_death_row, sk);
    if (err)
        goto failure;
    sk_set_txhash(sk);
    rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
                   inet->inet_sport, inet->inet_dport, sk);
......
    /* OK, now commit destination to socket.  */
    sk->sk_gso_type = SKB_GSO_TCPV4;
    sk_setup_caps(sk, &rt->dst);
    rt = NULL;
    if (likely(!tp->repair)) {
        if (!tp->write_seq)
            tp->write_seq = secure_tcp_seq(inet->inet_saddr,
                               inet->inet_daddr,
                               inet->inet_sport,
                               usin->sin_port);
        tp->tsoffset = secure_tcp_ts_off(sock_net(sk),
                         inet->inet_saddr,
                         inet->inet_daddr);
    }
    inet->inet_id = tp->write_seq ^ jiffies;
......
    err = tcp_connect(sk);
......
}
```

`tcp_connect()`主要逻辑为

* 创建新的结构体 `struct tcp_sock`该结构体是 `struct inet_connection_sock` 的一个扩展，维护了更多的 TCP 的状态
* 调用`tcp_init_nondata_skb()` 初始化一个 `SYN` 包
* 调用`tcp_transmit_skb()` 将 `SYN` 包发送出去
* 调用`inet_csk_reset_xmit_timer()` 设置了一个 `timer`，如果 `SYN` 发送不成功，则再次发送。

```c
int tcp_connect(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct sk_buff *buff;
    int err;
......
    tcp_connect_init(sk);
......
    buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
......
    tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
    tcp_mstamp_refresh(tp);
    tp->retrans_stamp = tcp_time_stamp(tp);
    tcp_connect_queue_skb(sk, buff);
    tcp_ecn_send_syn(sk, buff);
    tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);
    /* Send off SYN; include data in Fast Open. */
    err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
          tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
......
    tp->snd_nxt = tp->write_seq;
    tp->pushed_seq = tp->write_seq;
    buff = tcp_send_head(sk);
    if (unlikely(buff)) {
        tp->snd_nxt	= TCP_SKB_CB(buff)->seq;
        tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
    }
    TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);
    /* Timer for repeating the SYN until an answer. */
    inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
                  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
    return 0;
}
```

  关于底层发包收包留到后面单独解析，这里先重点看三次握手的过程。当发包完成后，我们会等待接收ACK，接收数据包的调用链为`tcp_v4_rcv()->tcp_v4_do_rcv()->tcp_rcv_state_process()`。`tcp_rcv_state_process()`是一个服务端客户端通用函数，根据状态位来判断如何执行。

* 当服务端处于`TCP_LISTEN`状态时，收到第一次握手即客户端的`SYN`，调用`conn_request()`进行处理，其实调用的是 `tcp_v4_conn_request()`，更新自身状态、队列，然后调用`tcp_v4_send_synack()`发送第二次握手消息，进入状态`TCP_SYN_RECV`
* 当客户端处于`TCP_SYN_SENT`状态时，收到服务端返回的第二次握手消息`ACK + SYN`，调用`tcp_rcv_synsent_state_process()`进行处理，调用`tcp_send_ack()`发送`ACK`回复给服务端，进入`TCP_ESTABLISHED`状态
* 服务端处于`TCP_SYN_RECV`状态时，收到客户端返回的第三次握手消息`ACK`，进入`TCP_ESTABLISHED`状态

```c
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    const struct tcphdr *th = tcp_hdr(skb);
    struct request_sock *req;
    int queued = 0;
    bool acceptable;
    switch (sk->sk_state) {
    case TCP_CLOSE:
        goto discard;
    case TCP_LISTEN:
......
        if (th->syn) {
......
            acceptable = icsk->icsk_af_ops->conn_request(sk, skb) >= 0;
......
            consume_skb(skb);
            return 0;
        }
        goto discard;
    case TCP_SYN_SENT:
        tp->rx_opt.saw_tstamp = 0;
        tcp_mstamp_refresh(tp);
        queued = tcp_rcv_synsent_state_process(sk, skb, th);
        if (queued >= 0)
            return queued;
        /* Do step6 onward by hand. */
        tcp_urg(sk, skb, th);
        __kfree_skb(skb);
        tcp_data_snd_check(sk);
        return 0;
    }
......
    switch (sk->sk_state) {
    case TCP_SYN_RECV:
        tp->delivered++; /* SYN-ACK delivery isn't tracked in tcp_ack */
        if (!tp->srtt_us)
            tcp_synack_rtt_meas(sk, req);
......
        smp_mb();
        tcp_set_state(sk, TCP_ESTABLISHED);
        sk->sk_state_change(sk);
        /* Note, that this wakeup is only for marginal crossed SYN case.
         * Passively open sockets are not waked up, because
         * sk->sk_sleep == NULL and sk->sk_socket == NULL.
         */
        if (sk->sk_socket)
            sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
        tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale;
        tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
        if (tp->rx_opt.tstamp_ok)
            tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;
        if (!inet_csk(sk)->icsk_ca_ops->cong_control)
            tcp_update_pacing_rate(sk);
        /* Prevent spurious tcp_cwnd_restart() on first data packet */
        tp->lsndtime = tcp_jiffies32;
        tcp_initialize_rcv_mss(sk);
        tcp_fast_path_on(tp);
        break;
......
}
```

### 总结

  本文较为详细的叙述了三次握手的整个过程，四次挥手有着类似的过程因此不做赘述，其中的区别在于多了一个`TIME_WAIT`以及对应的定时器。下篇文章开始我们将详细分析发包和收包的整个网络协议栈流程。

### 源码资料

\[1\] [bind\(\)](https://code.woboq.org/linux/linux/net/socket.c.html#__sys_bind)

\[2\] [inet\_bind\(\)](https://code.woboq.org/linux/linux/net/ipv4/af_inet.c.html#inet_bind)

\[3\] [listen\(\)](https://code.woboq.org/linux/linux/net/socket.c.html#__sys_listen)

\[4\] [inet\_listen\(\)](https://code.woboq.org/linux/linux/net/ipv4/af_inet.c.html#inet_listen)

\[5\] [accept\(\)](https://code.woboq.org/linux/linux/net/socket.c.html#__sys_accept4)

\[6\] [inet\_accept\(\)](https://code.woboq.org/linux/linux/net/ipv4/af_inet.c.html#inet_accept)

\[7\] [inet\_csk\_accept\(\)](https://code.woboq.org/linux/linux/net/ipv4/inet_connection_sock.c.html#inet_csk_accept)

\[7\] [connect\(\)](https://code.woboq.org/linux/linux/net/socket.c.html#__sys_connect)

\[8\] [\_\_inet\_stream\_connect\(\)](https://code.woboq.org/linux/linux/net/ipv4/af_inet.c.html#inet_stream_connect)

\[9\] [tcp\_v4\_connect\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp_ipv4.c.html#tcp_v4_connect)

\[10\] [tcp\_conn\_request\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp_input.c.html#tcp_conn_request)

\[11\] [tcp\_rcv\_state\_process\(\)](https://code.woboq.org/linux/linux/net/ipv4/tcp_input.c.html#tcp_rcv_state_process)

### 参考资料

\[1\] wiki

\[2\] [elixir.bootlin.com/linux](https://elixir.bootlin.com/linux/v5.7-rc1/source)

\[3\] [woboq](https://code.woboq.org/)

\[4\] Linux-insides

\[5\] 深入理解Linux内核

\[6\] Linux内核设计的艺术

\[7\] 极客时间 趣谈Linux操作系统

\[8\] 深入理解Linux网络技术内幕

