# 套接字

### 一. 前言

  在前面我们逐一分析了进程间通信的各种方法：信号，管道，共享内存和信号量，本文开始将分析更为复杂也是更为常用的另一套进程间通信：网络通信。网络通信和其他进程间通信最大的区别在于不局限于单机，因此成为了互联网时代的主流选择，无论是分布式、云计算、微服务、容器及自动化运营都离不开网络通信，其重要性可想而知。

  经过30多年的发展，网络协议栈已经变得极为复杂，远远不是一两篇文章能够说清楚的东西，所以这里着重剖析我们更为关注的东西：网络编程涉及到的相关协议栈。从本文开始，将分别介绍套接字及其创建、网络连接的建立、网络包的发送、网络包的接收、`Netfilter`剖析、`select, poll 及 epoll`剖析。除此之外，介于之前有新同学请教TCP的一些基础问题，打算写一篇扩展篇从设计理念的角度出发好好分析TCP协议的方法面面。

&lt;!-- more --&gt;

### 二. 套接字结构体

  网络协议封装为多层，因此套接字结构体定义也有着多层结构，但是这里有一点要注意的：在网络通信中，我们通过网卡获取到的数据包至少包括了物理层，链路层和网络层的内容，因此套接字结构体仅仅从网络层开始，即通常我们只定义了传输层的套接字`socket`和网络层的套接字`sock`。`socket` 是用于负责对上给用户提供接口，并且和文件系统关联。而 `sock`负责向下对接内核网络协议栈。

  首先看传输层的`socket`结构体，这个结构体表征BSD套接字的通用特性。首先是状态`state`，用以表示连接情况。`type`是套接字类型，如`SOCK_STREAM`。`wq`是等待队列，在后续文章中会说明。`file`是套接字对应的文件指针，毕竟一切皆文件，所以需要统一的文件系统。`sock`结构体的`sk`变量则为网络层的套接字，`ops`是协议相关的一系列套接字操作。

```text
struct socket {
    socket_state        state;
    short           type;
    unsigned long       flags;
    struct socket_wq    *wq;
    struct file     *file;
    struct sock     *sk;
    const struct proto_ops  *ops;
};
```

  接着看看网络层，这一层即IP层，该结构体`sock`中包含了一个基本结构体`sock_common`，整体较为复杂，所以对于其重要变量进行了说明，以注释的形式在每个变量后进行分析。

```text
struct sock {
    struct sock_common  __sk_common;       // 网络层套接字通用结构体
......
    socket_lock_t       sk_lock;           // 套接字同步锁
    atomic_t        sk_drops;              // IP/UDP包丢包统计
    int         sk_rcvlowat;               // SO_RCVLOWAT标记位
......
    struct sk_buff_head sk_receive_queue;   // 收到的数据包队列
......
    int         sk_rcvbuf;                // 接收缓存大小
......
    union {
        struct socket_wq __rcu  *sk_wq;     // 等待队列
        struct socket_wq    *sk_wq_raw;
    };
......
    int         sk_sndbuf;                 // 发送缓存大小
    /* ===== cache line for TX ===== */
    int         sk_wmem_queued;            // 传输队列大小
    refcount_t      sk_wmem_alloc;          // 已确认的传输字节数
    unsigned long       sk_tsq_flags;       // TCP Small Queue标记位
    union {
        struct sk_buff  *sk_send_head;      // 发送队列对首
        struct rb_root  tcp_rtx_queue;       
    };
    struct sk_buff_head sk_write_queue;      // 发送队列
......
    u32         sk_pacing_status; /* see enum sk_pacing 发包速率控制状态*/ 
    long            sk_sndtimeo;            // SO_SNDTIMEO 标记位
    struct timer_list   sk_timer;           // 套接字清空计时器
    __u32           sk_priority;            // SO_PRIORITY 标记位
......
    unsigned long       sk_pacing_rate; /* bytes per second 发包速率*/
    unsigned long       sk_max_pacing_rate;  // 最大发包速率
    struct page_frag    sk_frag;            // 缓存页帧
......
    struct proto        *sk_prot_creator;
    rwlock_t        sk_callback_lock;
    int         sk_err,                   // 上次错误
                sk_err_soft;              // “软”错误：不会导致失败的错误
    u32         sk_ack_backlog;            // ack队列长度
    u32         sk_max_ack_backlog;        // 最大ack队列长度
    kuid_t          sk_uid;               // user id
    struct pid      *sk_peer_pid;          // 套接字对应的peer的id
......
    long            sk_rcvtimeo;          // 接收超时
    ktime_t         sk_stamp;             // 时间戳
......
    struct socket       *sk_socket;        // Identd协议报告IO信号
    void            *sk_user_data;        // RPC层私有信息
......
    struct sock_cgroup_data sk_cgrp_data;   // cgroup数据
    struct mem_cgroup   *sk_memcg;         // 内存cgroup关联
    void            (*sk_state_change)(struct sock *sk);    // 状态变化回调函数
    void            (*sk_data_ready)(struct sock *sk);      // 数据处理回调函数
    void            (*sk_write_space)(struct sock *sk);     // 写空间可用回调函数
    void            (*sk_error_report)(struct sock *sk);    // 错误报告回调函数
    int         (*sk_backlog_rcv)(struct sock *sk, struct sk_buff *skb);    // 处理存储区回调函数
......
    void                    (*sk_destruct)(struct sock *sk);    // 析构回调函数
    struct sock_reuseport __rcu *sk_reuseport_cb;              // group容器重用回调函数
......
};
​
​
```

   `sock_common`是套接口在网络层的最小表示，即最基本的网络层套接字信息，具体内容分析见注释。

```text
struct sock_common {
    /* skc_daddr and skc_rcv_saddr must be grouped on a 8 bytes aligned
     * address on 64bit arches : cf INET_MATCH()
     */
    union {
        __addrpair  skc_addrpair;
        struct {
            __be32  skc_daddr;      // 外部/目的IPV4地址
            __be32  skc_rcv_saddr;  // 本地绑定IPV4地址
        };
    };
    union  {
        unsigned int    skc_hash;   // 根据协议查找表获取的哈希值
        __u16       skc_u16hashes[2]; // 2个16位哈希值，UDP专用
    };
    /* skc_dport && skc_num must be grouped as well */
    union {
        __portpair  skc_portpair;   // 
        struct {
            __be16  skc_dport;      // inet_dport占位符
            __u16   skc_num;        // inet_num占位符
        };
    };
    unsigned short      skc_family;       // 网络地址family
    volatile unsigned char  skc_state;    // 连接状态
    unsigned char       skc_reuse:4;      // SO_REUSEADDR 标记位
    unsigned char       skc_reuseport:1;  // SO_REUSEPORT 标记位
    unsigned char       skc_ipv6only:1;   // IPV6标记位
    unsigned char       skc_net_refcnt:1; // 该套接字网络名字空间内引用数
    int         skc_bound_dev_if;        // 绑定设备索引
    union {
        struct hlist_node   skc_bind_node;     // 不同协议查找表组成的绑定哈希表
        struct hlist_node   skc_portaddr_node; // UDP/UDP-Lite protocol二级哈希表
    };
    struct proto        *skc_prot;            // 协议回调函数，根据协议不同而不同
......
    union {                                 
        struct hlist_node   skc_node;           // 不同协议查找表组成的主哈希表
        struct hlist_nulls_node skc_nulls_node;  // UDP/UDP-Lite protocol主哈希表
    };
    unsigned short      skc_tx_queue_mapping;    // 该连接的传输队列
    unsigned short      skc_rx_queue_mapping;    // 该连接的接受队列
......
    union {
        int     skc_incoming_cpu; // 多核下处理该套接字数据包的CPU编号
        u32     skc_rcv_wnd;      // 接收窗口大小
        u32     skc_tw_rcv_nxt; /* struct tcp_timewait_sock  */
    };
    refcount_t      skc_refcnt;   // 套接字引用计数
......
};
```

### 三. 套接字缓冲区结构体

  套接字结构体用于表征一个网络连接对应的本地接口的网络信息，而`sk_buff`则是该网络连接对应的数据包的存储。`sk_buff`的详细介绍宜参考《Linux网络技术内幕》，专门有一章来描述该结构体。对于我们学习源码来说，最重要的是了解其重点成员变量以及其整体结构。

  其源码大致可以分为四部分：

* 布局：方便搜索以及组织结构，主要是一个双向链表用于管理全部的`sk_buff`。每个`sk_buff`对应一个数据包，多个`sk_buff`以双向链表的形式组合而成。

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0201.jpg)

 除此之外还有指向`sock`的指针，缓冲区数据块大小，缓冲区及数据边界`tail，end，head，data，truesize`

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0202.jpg)

* 通用字段：与特定内核无关的字段，主要包括时间戳`tstamp`，网络设备`dev`，源设备`input_device`，L2-L4层包头对应的`mac_header, network_header, transport_header`等。其头部组织结构如下所示

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0203.jpg)

* 功能专用：当编译防火墙（`Netfilter`\) 以及`QOS`等时才会用到的特殊字段，在此暂时不做详细介绍
* 管理函数：由内核提供的简单的管理工具函数，用于对`sk_buff`元素和元素列表进行操作，如数据预留及对齐函数`skb_put(), skb_push()，skb_pull()，skb_reserve()`

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0204.jpg)

  再比如分配回收函数`alloc_skb()`和`dev_alloc_skb()`

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0205.jpg)

  释放内存函数`kfree_skb()`和`dev_kfree_skb()`

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0206.jpg)

  除此之外还有克隆，复制等函数，不做过多展开介绍。

  `sk_buff`的整体填充过程如下图所示：

![img](http://www.embeddedlinux.org.cn/linux_net/0596002556/images/understandlni_0208.jpg)

  通过以上学习，对`sk_buff`应该有了较为全面系统的了解，其详细源码如下所示，对于重点部分已写明中文注释，其他参见英文注释。

```text
struct sk_buff {
    union {
        struct {
            /* These two members must be first. 构成sk_buff链表*/
            struct sk_buff      *next;
            struct sk_buff      *prev;
            union {
                struct net_device   *dev;   //网络设备对应的结构体，很重要但是不是本文重点，所以不做展开
                /* Some protocols might use this space to store information,
                 * while device pointer would be NULL.
                 * UDP receive path is one user.
                 */
                unsigned long       dev_scratch;   // 对于某些不适用net_device的协议需要采用该字段存储信息，如UDP的接收路径
            };
        };
        struct rb_node      rbnode; /* used in netem, ip4 defrag, and tcp stack 将sk_buff以红黑树组织，在TCP中有用到*/
        struct list_head    list;   // sk_buff链表头指针
    };
    union {
        struct sock     *sk;       // 指向网络层套接字结构体
        int         ip_defrag_offset;
    };
    union {
        ktime_t     tstamp;    // 时间戳
        u64     skb_mstamp_ns; /* earliest departure time */
    };
    /* 存储私有信息
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
    char            cb[48] __aligned(8);
    union {
        struct {
            unsigned long   _skb_refdst;                   // 目标entry
            void        (*destructor)(struct sk_buff *skb); // 析构函数
        };
        struct list_head    tcp_tsorted_anchor;             // TCP发送队列(tp->tsorted_sent_queue)
    };
....
    unsigned int        len,    // 实际长度
                data_len;       // 数据长度
    __u16           mac_len,    // mac层长度
                hdr_len;        // 可写头部长度
    /* Following fields are _not_ copied in __copy_skb_header()
     * Note that queue_mapping is here mostly to fill a hole.
     */
    __u16           queue_mapping;   // 多队列设备的队列映射
......
    /* fields enclosed in headers_start/headers_end are copied
     * using a single memcpy() in __copy_skb_header()
     */
    /* private: */
    __u32           headers_start[0];   
    /* public: */
......
    __u8            __pkt_type_offset[0];
    __u8            pkt_type:3;
    __u8            ignore_df:1;
    __u8            nf_trace:1;
    __u8            ip_summed:2;
    __u8            ooo_okay:1;
    __u8            l4_hash:1;
    __u8            sw_hash:1;
    __u8            wifi_acked_valid:1;
    __u8            wifi_acked:1;
    __u8            no_fcs:1;
    /* Indicates the inner headers are valid in the skbuff. */
    __u8            encapsulation:1;
    __u8            encap_hdr_csum:1;
    __u8            csum_valid:1;
......
    __u8            __pkt_vlan_present_offset[0];
    __u8            vlan_present:1;
    __u8            csum_complete_sw:1;
    __u8            csum_level:2;
    __u8            csum_not_inet:1;
    __u8            dst_pending_confirm:1;
......
    __u8            ipvs_property:1;
    __u8            inner_protocol_type:1;
    __u8            remcsum_offload:1;
......
    union {
        __wsum      csum;
        struct {
            __u16   csum_start;
            __u16   csum_offset;
        };
    };
    __u32           priority;
    int         skb_iif;        // 接收到该数据包的网络接口的编号
    __u32           hash;
    __be16          vlan_proto;
    __u16           vlan_tci;
......
    union {
        __u32       mark;
        __u32       reserved_tailroom;
    };
    union {
        __be16      inner_protocol;
        __u8        inner_ipproto;
    };
    __u16           inner_transport_header;
    __u16           inner_network_header;
    __u16           inner_mac_header;
    __be16          protocol;
    __u16           transport_header;   // 传输层头部
    __u16           network_header;     // 网络层头部
    __u16           mac_header;         // mac层头部
    /* private: */
    __u32           headers_end[0];
    /* public: */
    /* These elements must be at the end, see alloc_skb() for details.  */
    sk_buff_data_t      tail;
    sk_buff_data_t      end;
    unsigned char       *head, *data;
    unsigned int        truesize;
    refcount_t      users;
......
};
```

### 四. 创建套接字

  众所周知我们通过`socket()`生成套接字，其系统调用如下，主要调用`sock_create()`创建结构体`socket`，并通过`sock_map_fd()`将其和文件描述符进行绑定。

```text
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
    return __sys_socket(family, type, protocol);
}
​
int __sys_socket(int family, int type, int protocol)
{
    int retval;
    struct socket *sock;
    int flags;
......
    retval = sock_create(family, type, protocol, &sock);
......
    return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```

  应用层调用`socket()`函数会传入三个参数：

* `family`：表示使用什么 `IP` 层协议。`AF_INET` 表示 `IPv4`，`AF_INET6` 表示 `IPv6`。这里需要注意的是，我们会常见到`AF_INET, AF_PACKET，AF_UNIX`等，`AF_UNIX`用于主机内进程间通信，`AF_INET`和`AF_PACKET`的区别在于前者只能看到IP层以上，而后者可以看到链路层信息，即作用域不同。
* `type`：表示 `socket` 类型。`SOCK_STREAM` 是面向数据流的，协议 `IPPROTO_TCP` 属于这种类型。`SOCK_DGRAM` 是面向数据报的，协议 `IPPROTO_UDP` 属于这种类型。如果在内核里面看的话，`IPPROTO_ICMP` 也属于这种类型。`SOCK_RAW` 是原始的 `IP` 包，`IPPROTO_IP` 属于这种类型。
* `protocol`： 表示的协议，包括 `IPPROTO_TCP`、`IPPTOTO_UDP`。

![packet\_class](https://segmentfault.com/img/remote/1460000020103414?w=586&h=417)

  `sock_create()`实际调用`__sock_create()`。这里首先调用`sock_alloc()`分配套接字结构体`sock`并赋值类型为`type`，接着调用对应的`create()`函数按照`protocol`对`sock`进行填充。

```text
int sock_create(int family, int type, int protocol, struct socket **res)
{
    return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}
​
int __sock_create(struct net *net, int family, int type, int protocol,
             struct socket **res, int kern)
{
    int err;
    struct socket *sock;
    const struct net_proto_family *pf;
......
    /*
     *  Allocate the socket and allow the family to set things up. if
     *  the protocol is 0, the family is instructed to select an appropriate
     *  default.
     */
    sock = sock_alloc();
......
    sock->type = type;
......
    rcu_read_lock();
    pf = rcu_dereference(net_families[family]);
......
    err = pf->create(net, sock, protocol, kern);
......
    *res = sock;
    return 0;
......
}
​
//net/ipv4/af_inet.cstatic 
const struct net_proto_family inet_family_ops = { 
    .family = PF_INET, 
    .create = inet_create,//这个用于socket系统调用创建
    ......
}
```

  `sock_alloc()`中我们看到了熟悉的东西：`new_inode_pseudo()`，即依照着虚拟文件系统的方式为套接字生成`inode`，接着通过`SOCKET_I()`获取其对应的`socket`，再进行填充。

```text
struct socket *sock_alloc(void)
{
    struct inode *inode;
    struct socket *sock;
    inode = new_inode_pseudo(sock_mnt->mnt_sb);
    if (!inode)
        return NULL;
    sock = SOCKET_I(inode);
    inode->i_ino = get_next_ino();
    inode->i_mode = S_IFSOCK | S_IRWXUGO;
    inode->i_uid = current_fsuid();
    inode->i_gid = current_fsgid();
    inode->i_op = &sockfs_inode_ops;
    return sock;
}
​
struct inode *new_inode_pseudo(struct super_block *sb)
{
    struct inode *inode = alloc_inode(sb);
    if (inode) {
        spin_lock(&inode->i_lock);
        inode->i_state = 0;
        spin_unlock(&inode->i_lock);
        INIT_LIST_HEAD(&inode->i_sb_list);
    }
    return inode;
}
​
static inline struct socket *SOCKET_I(struct inode *inode)
{
    return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}
​
struct socket_alloc {
    struct socket socket;
    struct inode vfs_inode;
};
```

  `inet_create()`主要逻辑如下

* 通过循环`list_for_each_entry_rcu`查看 `inetsw[sock->type]`，该数组会根据`type`找对应的协议号，如果找到了则得到了符合用户指定的 `family->type->protocol` 的 `struct inet_protosw *answer` 对象。
* `struct socket *sock` 的 `ops` 成员变量被赋值为 `answer` 的 `ops`。对于 TCP 来讲，就是 `inet_stream_ops`。后面任何用户对于这个 `socket` 的操作都是通过 `inet_stream_ops` 进行的。
* 调用`sk_alloc()`创建一个 网络层`struct sock *sk` 对象并赋值
* 调用`inet_sk()`创建一个 `struct inet_sock` 结构并赋值。上文已说明`INET`作用域，而`inet_sock`即是对`sock`的`INET`形式封装，在`sock`的基础上增加了很多新的特性。

```text
static int inet_create(struct net *net, struct socket *sock, int protocol,
               int kern)
{
    struct sock *sk;
    struct inet_protosw *answer;
    struct inet_sock *inet;
    struct proto *answer_prot;
    unsigned char answer_flags;
    int try_loading_module = 0;
    int err;
......
    list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {
        err = 0;
        /* Check the non-wild match. */
        if (protocol == answer->protocol) {
            if (protocol != IPPROTO_IP)
                break;
        } else {
            /* Check for the two wild cases. */
            if (IPPROTO_IP == protocol) {
                protocol = answer->protocol;
                break;
            }
            if (IPPROTO_IP == answer->protocol)
                break;
        }
        err = -EPROTONOSUPPORT;
    }
......
    sock->ops = answer->ops;
    answer_prot = answer->prot;
    answer_flags = answer->flags;
......
    sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
......
    inet = inet_sk(sk);
    inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;
    inet->nodefrag = 0;
    if (SOCK_RAW == sock->type) {
        inet->inet_num = protocol;
        if (IPPROTO_RAW == protocol)
            inet->hdrincl = 1;
    }
    if (net->ipv4.sysctl_ip_no_pmtu_disc)
        inet->pmtudisc = IP_PMTUDISC_DONT;
    else
        inet->pmtudisc = IP_PMTUDISC_WANT;
    inet->inet_id = 0;
    sock_init_data(sock, sk);
    sk->sk_destruct    = inet_sock_destruct;
    sk->sk_protocol    = protocol;
    sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
    inet->uc_ttl    = -1;
    inet->mc_loop   = 1;
    inet->mc_ttl    = 1;
    inet->mc_all    = 1;
    inet->mc_index  = 0;
    inet->mc_list   = NULL;
    inet->rcv_tos   = 0;
    sk_refcnt_debug_inc(sk);
    if (inet->inet_num) {
        /* It assumes that any protocol which allows
         * the user to assign a number at socket
         * creation time automatically
         * shares.
         */
        inet->inet_sport = htons(inet->inet_num);
        /* Add to protocol hash chains. */
        err = sk->sk_prot->hash(sk);
......
    }
    if (sk->sk_prot->init) {
        err = sk->sk_prot->init(sk);
......
}
```

  `inetsw`数组里面的内容是 `struct inet_protosw`，对于每个类型的协议均有一项，这一项里面是属于这个类型的协议。`inetsw` 数组是在系统初始化的时候初始化的，一个循环会将 `inetsw` 数组的每一项都初始化为一个链表。接下来一个循环将 `inetsw_array` 注册到 `inetsw` 数组里面去。

```text
static struct list_head inetsw[SOCK_MAX];

static int __init inet_init(void)
{
......
    /* Register the socket-side information for inet_create. */
    for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
        INIT_LIST_HEAD(r);
    for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
        inet_register_protosw(q);
......
}

static struct inet_protosw inetsw_array[] =
{
    {
        .type =       SOCK_STREAM,
        .protocol =   IPPROTO_TCP,
        .prot =       &tcp_prot,
        .ops =        &inet_stream_ops,
        .flags =      INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
    },
    {
        .type =       SOCK_DGRAM,
        .protocol =   IPPROTO_UDP,
        .prot =       &udp_prot,
        .ops =        &inet_dgram_ops,
        .flags =      INET_PROTOSW_PERMANENT,
     },
     {
        .type =       SOCK_DGRAM,
        .protocol =   IPPROTO_ICMP,
        .prot =       &ping_prot,
        .ops =        &inet_sockraw_ops,
        .flags =      INET_PROTOSW_REUSE,
     },
     {
        .type =       SOCK_RAW,
        .protocol =   IPPROTO_IP,  /* wild card */
        .prot =       &raw_prot,
        .ops =        &inet_sockraw_ops,
        .flags =      INET_PROTOSW_REUSE,
     }
}
```

  至此，套接字的创建就算完成了。

### 总结

  本文重点分析了套接字这一网络编程中的重要结构体以及其创建函数背后的逻辑，为后文网络编程的源码解析打下基础。

### 源码资料

\[1\] [socket](https://code.woboq.org/linux/linux/include/linux/net.h.html#socket)

\[2\] [sk\_buff](https://code.woboq.org/linux/linux/include/linux/skbuff.h.html#sk_buff)

\[3\] [socket\(\)](https://code.woboq.org/linux/linux/net/socket.c.html#__sys_socket)

\[4\] [inet\_create\(\)](https://code.woboq.org/linux/linux/net/ipv4/af_inet.c.html#inet_create)

### 参考资料

\[1\] wiki

\[2\] [elixir.bootlin.com/linux](https://elixir.bootlin.com/linux/v5.7-rc1/source)

\[3\] [woboq](https://code.woboq.org/)

\[4\] Linux-insides

\[5\] 深入理解Linux内核

\[6\] Linux内核设计的艺术

\[7\] 极客时间 趣谈Linux操作系统

\[8\] 深入理解Linux网络技术内幕  


