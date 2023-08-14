#ifndef __TCP_H__
#define __TCP_H__

#include "sock.h"
#include "list.h"
#include "tcp_timer.h"

#define TCP_DEFAULT_WINDOW  4096   /* TCP默认窗口大小 */
#define TCP_DEFAULT_TTL     64     /* TCP报文默认生存时间 */

#define TCP_LITTLE_ENDIAN  /* TCP大小端标志 */

struct tcp {
    unsigned short src;               /* 源端口 */
    unsigned short dst;               /* 目的端口 */
    unsigned int seq;                 /* 序列号 */
    unsigned int ackn;                /* 确认号 */
#ifdef TCP_LITTLE_ENDIAN
    unsigned short reserved:4,        /* 保留位 */
            doff:4,                   /* data offset(TCP头部长度),因为TCP Option的存在,所以这个是可变的*/
            fin:1,                    /* 结束标志 */
            syn:1,                    /* 用于初始化一个连接的序列号 */
            rst:1,                    /* 重置连接 */
            psh:1,                    /* 推送,置为1时,接收方优先处理此报文 */
            ack:1,                    /* ack==1时,ackn有效 */
            urg:1,                    /* urg==1时,urgptr有效 */
            ece:1,                    /* ecn==1时,通知对方从对方到这边的网络有阻塞 */
            cwr:1;                    /* cwr==1时,通知对方已将拥塞窗口减小 */
#else
    unsigned short doff:4,
            reserved:4,
			cwr:1,
			ece:1,
			urg:1,
			ack:1,
			psh:1,
			rst:1,
			syn:1,
			fin:1;
#endif
    unsigned short window;             /* 窗口大小 */
    unsigned short checksum;           /* 校验和 */
    unsigned short urgptr;             /* 应急指针 */
    unsigned char data[0];
}__attribute__((packed));

#define pkb2tcp(pkb)  ((struct tcp *)((pkb)->pk_data + ETH_HDR_SZ + IP_HDR_SZ))
#define ip2tcp(ip)    ((struct tcp *)ipdata(ip))
#define TCP_HDR_SZ    (sizeof(struct tcp))
#define TCP_HDR_DOFF  (TCP_HDR_SZ >> 2)
#define tcphlen(tcp)  ((tcp)->doff << 2)
#define tcptext(tcp)  ((unsigned char *)(tcp) + tcphlen(tcp))

enum tcp_state {
    TCP_CLOSE = 1,            /* 关闭 */
    TCP_LISTEN,               /* 监听 */
    TCP_SYN_RECV,             /* 被动方SYN已收到,并发送SYN+ACK后 */
    TCP_SYN_SENT,             /* 主动方SYN已发送 */
    TCP_ESTABLISHED,          /* 连接已建立 */
    TCP_CLOSE_WAIT,           /* 被动方已收到对方发来的FIN */
    TCP_LAST_ACK,             /* 被动方已发送fin报文,等待最后一个ack */
    TCP_FIN_WAIT1,            /* 主动方已发送fin报文,等待对方发送最后一个数据包 */
    TCP_FIN_WAIT2,            /* 主动方发送fin之后,收到data和ack */
    TCP_CLOSING,              /* 双方都主动发送fin报文 */
    TCP_TIME_WAIT,            /* 主动方发送最后一个ack后的状态 */
    TCP_MAX_STATE
};

struct tcp_sock {
    struct sock sk;   /* tcp sock */
    struct hlist_node bhash_list;
    unsigned int bhash;
    int accept_backlog;
    int backlog;
    struct list_head listen_queue;  /* listen sock accept的握手阶段的tcp sock 队列 */
    struct list_head accept_queue;  /* listen sock accept的且已成功建立连接的tcp sock 队列 */
    struct list_head list;  /* 用于链接到上面两个队列的node */
    struct tcp_timer timewait;
    struct tcpip_wait *wait_accept;
    struct tcpip_wait *wait_connect;
    struct tcp_sock *parent; /* 当tcp_sock是child_tcp_sock,parent指向listen_tcp_sock */
    unsigned int flags;
    struct cbuf *rcv_buf;
    struct list_head rcv_reass; /* 已接收,但未组装的tcp片段 */
    unsigned int snd_una;  /* send unacknowledged 已发送但未收到ack的seq */
    unsigned int snd_nxt;  /* send next seq */
    unsigned int snd_wnd;
    unsigned int snd_up;
    unsigned int snd_wl1;  /* send seq for last window update 最后一次窗口更新时的seq */
    unsigned int snd_wl2;  /* send ack for last window update 最后一次窗口更新时的ack */
    unsigned int iss;      /* init send seq num 初始发送序列号 */
    unsigned int rcv_nxt;  /* recv next seq 期望的下一个序列号*/
    unsigned int rcv_wnd;  
    unsigned int rcv_up;
    unsigned int irs;      /* init recv seq num 初始接收序列号 */
    unsigned int state;
};

#define tcpsk(sk)           ((struct tcp_sock *)sk)
#define TCP_MAX_BACKLOG     128
#define TCP_DEAD_PARENT     ((struct tcp_sock *)0xffffdaed)

/*
    tcp flags
    对应tcp_sock->flags
*/
#define TCP_F_PUSH          0x00000001
#define TCP_F_ACKNOW        0x00000002
#define TCP_F_ACKDELAY      0x00000004

/*
    tcp分片
*/
struct tcp_segment {
    unsigned int seq;         /* 序列号 */
    unsigned int ack;         /* 确认号 */
    unsigned int lastseq;     /* data部分最后一个字节的序列号 */
    unsigned int len;         /* 序列号位置 */
    unsigned int dlen;        /* 数据长度 */
    unsigned int wnd;         /* 窗口大小 */
    unsigned int up;          /* 紧急指针 */
    unsigned int prc;
    unsigned char *text;      /* 数据部分 */
    struct ip *ip_hdr;        /* ip指针 */
    struct tcp *tcp_hdr;      /* tcp指针 */
};

/*
    判断服务端listen状态accept 队列是否已满
*/
static _inline int tcp_accept_queue_full(struct tcp_sock *tsk)
{
    return (tsk->accept_backlog >= tsk->backlog);
}

/*
    将被动创建的tcp sock链接到listen sock上
*/
static _inline void tcp_accept_enqueue(struct tcp_sock *tsk)
{
    if (!list_empty(&tsk->list))
        list_del(&tsk->list);
    /* 将accept创建的tcp_sock连接到listen tcp_sock上 */
    list_add(&tsk->list, &tsk->parent->accept_queue);
    tsk->accept_backlog++;
}

static _inline struct tcp_sock *tcp_accept_dequeue(struct tcp_sock *tsk)
{
    struct tcp_sock *newtsk;
    newtsk = list_first_entry(&tsk->accept_queue, struct tcp_sock, list);
    list_del_init(&newtsk->list);
    tsk->accept_backlog--;
    return newtsk;
}

/* tcp_in.c */
extern void tcp_in(struct pkbuf *pkb);

/* tcp_sock.c */
extern struct sock *tcp_alloc_sock(int);
extern int tcp_hash(struct sock *);
extern void tcp_unhash(struct sock *sk);
extern void tcp_unbhash(struct tcp_sock *tsk);
extern struct sock *tcp_lookup_sock(unsigned int, unsigned int,unsigned int, unsigned int);
extern struct tcp_sock *get_tcp_sock(struct tcp_sock *);
extern struct sock *tcp_alloc_sock(int);
extern void tcp_init(void);

/* tcp_state.c */
extern unsigned int alloc_new_iss(void);
extern void tcp_process(struct pkbuf *, struct tcp_segment *, struct sock *);

/* tcp_out.c */
extern void tcp_send_out(struct tcp_sock *, struct pkbuf *, struct tcp_segment *);
extern void tcp_send_reset(struct tcp_sock *, struct tcp_segment *);
extern void tcp_send_ack(struct tcp_sock *, struct tcp_segment *);
extern void tcp_send_synack(struct tcp_sock *, struct tcp_segment *);
extern void tcp_send_syn(struct tcp_sock *, struct tcp_segment *);
extern void tcp_send_fin(struct tcp_sock *);

/* tcp_reass.c */
extern void tcp_free_reass_head(struct tcp_sock *);
extern void tcp_segment_reass(struct tcp_sock *, struct tcp_segment *, struct pkbuf *);

/* tcp_text.c */
extern void tcp_free_buf(struct tcp_sock *);
extern int tcp_write_buf(struct tcp_sock *, void *, unsigned int );
extern void tcp_recv_text(struct tcp_sock *, struct tcp_segment *, struct pkbuf *);
extern int tcp_send_text(struct tcp_sock *, void *, int );

extern int tcp_id;
extern const char *tcp_state_string[];

#define for_each_tcp_sock(tsk, node, head) \
    hlist_for_each_entry(tsk, node, head, bhash_list)

#define ADJACENT_SEGMENT_HEAD(nseq) \
    do{ \
        if ((nseq) > seg->seq) { \
            if (seg->dlen <= (nseq) - seg->seq) \
                goto out; \
            seg->dlen -= (nseq) - seg->seq; \
            seg->text += (nseq) - seg->seq; \
            seg->seq = (nseq); \
        } \
    } while(0)

static _inline void tcp_set_state(struct tcp_sock *tsk, enum tcp_state state)
{
    tcpsdbg("State from %s to %s", tcp_state_string[tsk->state],
                    tcp_state_string[state]);
    tsk->state = state;
}

#endif