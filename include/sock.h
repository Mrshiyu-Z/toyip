#ifndef __SOCK_H__
#define __SOCK_H__

#include "netif.h"
#include "list.h"
#include "wait.h"

struct sock_addr {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned short src_port;
    unsigned short dst_port;
}__attribute__((packed));

struct sock;
struct sock_ops {
    void (*recv_notify)(struct sock *);
    void (*send_notify)(struct sock *);
    int (*send_pkb)(struct sock *, struct pkbuf *);
    int (*send_buf)(struct sock *, void *, int, struct sock_addr *);
    struct pkbuf *(*recv)(struct sock *);
    int (*recv_buf)(struct sock *, char *, int);
    int (*hash)(struct sock *);
    void (*unhash)(struct sock *);
    int (*bind)(struct sock *, struct sock_addr *);
    int (*connect)(struct sock *, struct sock_addr *);
    int (*set_port)(struct sock *, unsigned short);
    int (*close)(struct sock *);
    int (*listen)(struct sock *, int);
    struct sock *(*accept)(struct sock *);
};

struct sock {
    unsigned char protocol;         // 协议类型
    struct sock_addr sk_addr;       // 源地址/目的地址/源端口/目的端口
    struct socket *sock;
    struct sock_ops *sk_ops;        // SOCK的操作函数
    struct rtentry *sk_dst;         // SOCK的路由
    struct list_head recv_queue;    // SOCK的接收队列,队列上是pkb报文
    struct tcpip_wait *recv_wait;   // 
    unsigned int hash;             
    struct hlist_node hash_list;    // HASH节点,用于挂在HASH链表上 
    int refcnt;                     // 引用计数
}__attribute__((packed));

#define sk_saddr sk_addr.src_addr
#define sk_daddr sk_addr.dst_addr
#define sk_sport sk_addr.src_port
#define sk_dport sk_addr.dst_port

#define hlist_for_each_sock(sk, node, head) \
    hlist_for_each_entry(sk, node, head, hash_list)

extern void sock_add_hash(struct sock *sk, struct hlist_head *head);
extern void sock_del_hash(struct sock *sk);

extern struct sock *get_sock(struct sock *sk);
extern void free_sock(struct sock *sk);

extern void sock_recv_notify(struct sock *sk);
extern struct pkbuf *sock_recv_pkb(struct sock *sk);
extern int sock_close(struct sock *sk);
extern int sock_autobind(struct sock *sk);

extern int alloc_socks;
extern int free_socks;
#endif