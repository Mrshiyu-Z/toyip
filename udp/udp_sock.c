#include "compile.h"
#include "ether.h"
#include "lib.h"
#include "list.h"
#include "socket.h"
#include "sock.h"
#include "udp.h"
#include "ip.h"
#include "netif.h"
#include "route.h"
#include <pthread.h>

#define UDP_PORTS        0x10000                           // UDP端口数量,这里是65535
#define UDP_HASH_SIZE    128                               // HASH表的大小,128
#define UDP_HASH_SLOTS   (UDP_PORTS / UDP_HASH_SIZE)       // HASH槽的端口数量,65535/128 == 512
#define UDP_HASH_MASK    (UDP_HASH_SIZE - 1)               // HASH掩码,128 - 1 == 127
#define UDP_BEST_UPDATE  10                                // 更新最佳HASH槽的频率
#define UDP_PORT_MIN     0x8000                            // UDP端口的最小值,32768
#define UDP_PORT_MAX     0xf000                            // UDP端口的最大值,61440
#define BEST_PORT_MIN    UDP_PORT_MIN                      // UDP最佳端口的最小值

#define udp_hash_slot(hash)    (&udp_table.slot[hash])     // 通过hash取对应HASH槽的指针
#define udp_slot(port)         udp_hash_slot(port & UDP_HASH_MASK) // 通过port取HASH槽指针
#define udp_best_slot()        udp_hash_slot(udp_table.best_slot)  // 获取最佳HASH槽的指针

#define udp_hash_head(hash)    (&udp_hash_slot(hash)->head) // 通过hash值获取HASH槽的头节点指针
#define udp_slot_head(port)    (&udp_slot(port)->head)      // 通过port获取HASH槽的头节点指针
#define udp_best_head()        (&udp_best_slot()->head)     // 获取最佳HASH槽的头节点指针

/*
    HASH槽
    @head: HASH链表的头节点
    @used: 使用情况
*/
struct hash_slot {
    struct hlist_head head;
    int used;
};

/*
    HASH表
    @slot: HASH槽
    @best_slot: 最佳HASH槽的索引
    @best_update: 更新HASH槽的计数器
    @mutex: 互斥锁
*/
struct hash_table {
    struct hash_slot slot[UDP_HASH_SIZE];
    int best_slot;
    int best_update;
    pthread_mutex_t mutex;
};

static struct hash_table udp_table;  // 定义一个udp的HASH表
static unsigned short udp_id;

static _inline void udp_hash_table_lock(void)
{
    pthread_mutex_lock(&udp_table.mutex);
}

static _inline void udp_hash_table_unlock(void)
{
    pthread_mutex_unlock(&udp_table.mutex);
}

/*
    查看端口是否已经被使用
    @port: 需要查询的端口
    @head: HASH链表的头节点
*/
static _inline int __port_used(unsigned short port, struct hlist_head *head)
{
    struct hlist_node *node;
    struct sock *sk;
    hlist_for_each_sock(sk, node, head)
        // 匹配的源端口
        if (sk->sk_sport == _htons(port))
            return 1;
    return 0;
}

/*
    查看端口是否已经被使用
    @port: 需要查询的端口
*/
static _inline int port_used(unsigned short port)
{
    return __port_used(port, udp_slot_head(port));
}

/*
    在当前最佳槽中获取一个端口号
*/
static _inline unsigned short udp_get_best_port(void)
{
    unsigned short port = udp_table.best_slot + BEST_PORT_MIN;
    struct hash_slot *best = udp_best_slot();

    if (best->used) {
        while (port < UDP_PORT_MAX) {
            if (!__port_used(port, &best->head))
                break;
            port += UDP_HASH_SIZE;
        }
        if (port >= UDP_PORT_MAX)
            return 0;
    }
    best->used++;
    return port;
}

/*
    动态更新最佳槽的索引值
*/
static _inline void udp_update_best(int hash)
{
    /*
        更新准则
        1. 没有改变过
        2. best_update += best->used - slot->used;
    */
    if (udp_table.best_slot != hash) {
        if (udp_hash_slot(hash)->used < udp_best_slot()->used) {
            udp_table.best_slot = hash;
        }
    }
}

/*
    如果当前最佳槽中无法获取最佳端口
    则重新选取一个最佳槽
*/
static int udp_get_port_slow(void)
{
    int best_slot = udp_table.best_slot;
    int best_used = udp_best_slot()->used;
    int i;
    // 找到一个引用计数最小的槽
    for (i = 0;i < UDP_HASH_SIZE; i++) {
        if (udp_hash_slot(i)->used < best_used) {
            best_used = udp_hash_slot(i)->used;
            best_slot = i;
        }
    }
    if (best_slot == udp_table.best_slot)
        return 0;
    udp_table.best_slot = best_slot;
    udp_table.best_update = UDP_BEST_UPDATE;
    return udp_get_best_port();
}

/*
    获取一个可用端口号
*/
static unsigned short udp_get_port(void)
{
    struct hash_slot *best = udp_best_slot();
    unsigned short port;
    /*
        先尝试从当前最佳槽中获取一个可用端口
        如果获取到的端口为0
        则重新分配一个最佳槽,并从重新分配的槽中获取一个可用端口
    */
    port = udp_get_best_port();
    if (port == 0)
        return udp_get_port_slow();
    /*
        如果计数器为0
        则更新计数器,并重新设置最佳槽
    */
    if (--udp_table.best_update <= 0) {
        int i;
        udp_table.best_update = UDP_BEST_UPDATE;
        for (i = 0; i < UDP_HASH_SIZE; i++) {
            if (udp_table.slot[i].used < best->used) {
                udp_table.best_slot = i;
                break;
            }
        }
    }
    return _htons(port);
}

/*
    设置udp源端口
    @sk: udp sock
    @nport: 将要设置的端口
*/
static int udp_set_sport(struct sock *sk, unsigned short nport)
{
    int hash, err = -1;
    udp_hash_table_lock();
    // 获取一个可用的源端口
    if ((nport && port_used(_ntohs(nport))) || 
        (!nport && !(nport = udp_get_port())))
        goto unlock;
    err = 0;
    // 与UDP掩码做&运算,获取端口hash值
    hash = _ntohs(nport) & UDP_HASH_MASK;
    udp_update_best(hash);
    sk->hash = hash;
    sk->sk_sport = nport;
    if (sk->sk_ops->hash)
        sk->sk_ops->hash(sk);
unlock:
    udp_hash_table_unlock();
    return err;
}

/*
    取消UDP源端口的使用
    @sk: udp sock
*/
static void udp_unset_sport(struct sock *sk)
{
    struct hash_slot *slot = udp_hash_slot(sk->hash);
    // 释放端口
    slot->used--;
    udp_update_best(sk->hash);
}

/*
    取消udp sock 在hash表中的绑定
    @sk: udp sock
*/
static void udp_unhash(struct sock *sk)
{
    // 先释放端口
    udp_unset_sport(sk);
    // 再从对应槽的hash链表中删除
    sock_del_hash(sk);
}

/*
    将udp sock加入对应槽的hash链表
    @sk: udp sock
*/
static int udp_hash(struct sock *sk)
{
    sock_add_hash(sk, udp_hash_head(sk->hash));
    return 0;
}

/*
    发送udp报文
    @sk: udp sock
    @pkb: udp 报文
*/
static int udp_send_pkb(struct sock *sk, struct pkbuf *pkb)
{
    ip_send_out(pkb);
    return pkb->pk_len - ETH_HDR_SZ - IP_HDR_SZ - UDP_HDR_SZ;
}

/*
    初始化udp pkb包
    @sk: udp sock
    @pkb: pkb包
    @buf: udp载荷
    @size: udp载荷的长度
    @skaddr: 目的地址和目的端口
*/
static int udp_init_pkb(struct sock *sk, struct pkbuf *pkb,
        void *buf, int size, struct sock_addr *skaddr)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct udp *udp_hdr = (struct udp *)ip_hdr->ip_data;
    ip_hdr->ip_hlen = IP_HDR_SZ >> 2;
    ip_hdr->ip_ver = IP_VERSION_4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = _htons(pkb->pk_len - ETH_HDR_SZ);
    ip_hdr->ip_id = _htons(udp_id);
    ip_hdr->ip_fragoff = 0;
    ip_hdr->ip_ttl = UDP_DEFAULT_TTL;
    ip_hdr->ip_pro = sk->protocol;
    ip_hdr->ip_dst = skaddr->dst_addr;
    if (rt_output(pkb) < 0)
        return -1;
    udp_hdr->src = sk->sk_sport;
    udp_hdr->dst = skaddr->dst_port;
    udp_hdr->length = _htons(size + UDP_HDR_SZ);
    memcpy(udp_hdr->data, buf, size);
    udpdbg(IPFMT":%d" "->" IPFMT":%d(proto %d)",
            ipfmt(ip_hdr->ip_src), _ntohs(udp_hdr->src),
            ipfmt(ip_hdr->ip_dst), _ntohs(udp_hdr->dst),
            ip_hdr->ip_pro);
    udp_set_checksum(ip_hdr, udp_hdr);
    return 0;
}

/*
    发送udp 载荷
    @sk: udp sock
    @size: udp 载荷大小
    @skaddr: 发送的目的IP地址和目的端口
*/
static int udp_send_buf(struct sock *sk, void *buf, int size,
                struct sock_addr *skaddr)
{
    struct sock_addr sk_addr;
    struct pkbuf *pkb;
    
    if (size <= 0 || size > UDP_MAX_BUFSZ)
        return -1;
    if (skaddr) {
        sk_addr.dst_addr = skaddr->dst_addr;
        sk_addr.dst_port = skaddr->dst_port;
    } else if (sk->sk_dport) {
        sk_addr.dst_addr = sk->sk_daddr;
        sk_addr.dst_port = sk->sk_dport;
    }

    if (!sk_addr.dst_addr || !sk_addr.dst_port)
        return -1;
    if (!sk->sk_sport && sock_autobind(sk) < 0)
        return -1;
    
    pkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + UDP_HDR_SZ + size);
    if (udp_init_pkb(sk, pkb, buf, size, &sk_addr) < 0) {
        free_pkb(pkb);
        return -1;
    }
    if (sk->sk_ops->send_pkb)
        return sk->sk_ops->send_pkb(sk, pkb);
    else
        return udp_send_pkb(sk, pkb);
}

/*
    udp sock的操作函数的定义
*/
static struct sock_ops udp_ops = {
    .recv_notify = sock_recv_notify,
    .recv = sock_recv_pkb,
    .send_buf = udp_send_buf,
    .send_pkb = udp_send_pkb,
    .hash = udp_hash,
    .unhash = udp_unhash,
    .set_port = udp_set_sport,
    .close = sock_close,
};

/*
    通过源端口查找sock
    @nport: 源端口
*/
struct sock *udp_lookup_sock(unsigned short nport)
{
    struct hlist_head *head = udp_slot_head(_ntohs(nport));
    struct hlist_node *node;
    struct sock *sk;
    if (hlist_empty(head))
        return NULL;
    hlist_for_each_sock(sk, node, head)
        if (sk->sk_sport == nport) {
            return get_sock(sk);
        }
    return NULL;
}

/*
    udp 组件初始化
*/
void udp_init(void)
{
    struct hash_slot *slot;
    int i;
    for (slot = udp_hash_slot(i = 0);i < UDP_HASH_SIZE; i++, slot++) {
        hlist_head_init(&slot->head);
        slot->used = 0;
    }
    udp_table.best_slot = 0;
    udp_table.best_update = UDP_BEST_UPDATE;
    pthread_mutex_init(&udp_table.mutex, NULL);
    udp_id = 0;
}

/*
    申请一个udp sock
    @protocol: IP_P_UDP
*/
struct sock *udp_alloc_sock(int protocol)
{
    struct udp_sock *udp_sk;
    if (protocol && protocol != IP_P_UDP)
        return NULL;
    udp_sk = xzalloc(sizeof(*udp_sk));
    alloc_socks++;
    udp_sk->sk.sk_ops = &udp_ops;
    udp_id++;
    return &udp_sk->sk;
}
