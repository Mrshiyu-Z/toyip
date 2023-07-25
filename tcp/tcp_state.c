#include "arp.h"
#include "compile.h"
#include "lib.h"
#include "list.h"
#include "netif.h"
#include "sock.h"
#include "tcp.h"
#include "ip.h"
#include "tcp_timer.h"
#include "wait.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>


const char *tcp_state_string[TCP_MAX_STATE] = {
    [0] = "Unknown tcp state: 0",
    [1] = "CLOSED",
    [2] = "LISTEN",
    [3] = "SYN-RECV",
    [4] = "SYN-SENT",
    [5] = "ESTABLISHED",
    [6] = "CLOSE-WAIT",
    [7] = "LAST-ACK",
    [8] = "FIN-WAIT-1",
    [9] = "FIN-WAIT-2",
    [10] = "CLOSING",
    [11] = "TIME-WAIT",
};

static _inline void tcp_dbg_state(struct tcp_sock *tsk)
{
    if (!tsk)
        tcpsdbg("CLOSED");
    else if (tsk->state < TCP_MAX_STATE)
        tcpsdbg("%s", tcp_state_string[tsk->state]);
    else
        tcpsdbg("Unknown tcp state: %d", tsk->state);
}

unsigned int alloc_new_iss(void)
{
    static unsigned int iss = 12345678;
    if (++iss >= 0xffffffff)
        iss = 12345678;
    return iss;
}

/*
    当listen状态接收到syn包时
    此函数创建一个新的sock来处理
    @tsk: listen sock的 tcp_sock
    @seg: 收到的 tcp 片段 
*/
static struct tcp_sock *tcp_listen_child_sock(struct tcp_sock *tsk,
                        struct tcp_segment *seg)
{
    struct sock *newsk = tcp_alloc_sock(tsk->sk.protocol);
    struct tcp_sock *newtsk = tcpsk(newsk);
    tcp_set_state(newtsk, TCP_SYN_RECV);     /* 设置状态为 syn recv */
    newsk->sk_saddr = seg->ip_hdr->ip_dst;
    newsk->sk_daddr = seg->ip_hdr->ip_dst;
    newsk->sk_sport = seg->tcp_hdr->dst;
    newsk->sk_dport = seg->tcp_hdr->src;
    if (tcp_hash(&newtsk->sk) < 0) {          /* 设置 sock->hash并加入到hash链表上 */
        free(newtsk);
        return NULL;
    }

    newtsk->parent = get_tcp_sock(tsk);       /* 将tcp_sock的parent设置为listen状态的sock */
    list_add(&newtsk->list, &tsk->listen_queue);   /* 将tcp_sock添加到listen_sock的listen_queue中 */

    return get_tcp_sock(newtsk);
}

/*
    tcp listen状态处理函数
    @pkb: pkb包
    @seg: tcp分片
    @tsk: tcp sock
*/
static void tcp_listen(struct pkbuf *pkb, struct tcp_segment *seg,
            struct tcp_sock *tsk)
{
    struct tcp_sock *newtsk;
    struct tcp *tcp_hdr = seg->tcp_hdr;
    tcpsdbg("LISTEN");
    tcpsdbg("1. check rst");
    if (tcp_hdr->rst)
        goto discarded;
    tcpsdbg("2. check ack");
    if (tcp_hdr->ack) { /* listen状态收到ack包是不合理的 */
        tcp_send_reset(tsk, seg);
        goto discarded;
    }
    tcpsdbg("3. check syn");
    if (!tcp_hdr->syn) /* listen状态收到syn不为1的包是不合理的 */
        goto discarded;
    
    newtsk = tcp_listen_child_sock(tsk, seg); /* 创建一个新的tcp_sock */
    if (!newtsk) {
        tcpsdbg("cannot alloc new sock");
        goto discarded;
    }
    newtsk->irs = seg->seq;  /* 设置初始接收序列号 */
    newtsk->iss = alloc_new_iss();  /* 设置初始发送序列号 */ 
    newtsk->rcv_nxt = seg->seq + 1;   /* +1 因为这是syn报文,计数为1,所以recv next = seq + 1 */

    tcp_send_synack(newtsk, seg);  /* 给syn报文 回复 ack 报文*/
    newtsk->snd_nxt = newtsk->iss + 1;  /* send next seq == init send seq + 1 */
    newtsk->snd_una = newtsk->iss; /* 记录已发送但未收到的seq,此时等于初始序列号 */

discarded:
    free_pkb(pkb);
}

static void tcp_closed(struct tcp_sock *tsk, struct pkbuf *pkb,
            struct tcp_segment *seg)
{
    tcpsdbg("CLOSED");
    if (!tsk)
        tcp_send_reset(tsk, seg);
    free_pkb(pkb);
}

/*
    处理处于SYN_SENT状态的sock
    @pkb: pkb
    @seg: pkb中的tcp片段
    @tsk: tcp_sock
*/
static void tcp_synsent(struct pkbuf *pkb, struct tcp_segment *seg,
            struct tcp_sock *tsk)
{
    struct tcp *tcp_hdr = seg->tcp_hdr;
    tcpsdbg("SYN-SENT");
    tcpsdbg("1. check ack");
    if (tcp_hdr->ack) {
        /* 如果ack小于等于init send seq 或者 大于 send next */
        if (seg->ack <= tsk->iss || seg->ack > tsk->snd_nxt) {
            goto discarded;
            tcp_send_reset(tsk, seg);
        }
    }
    tcpsdbg("2. check rst");
    if (tcp_hdr->rst) {
        if (tcp_hdr->ack) {
            tcpsdbg("Error:connection reset");
            tcp_set_state(tsk, TCP_CLOSE);
            if (tsk->wait_connect)
                wake_up(tsk->wait_connect);
            else
                tcpsdbg("No thread waiting for connection");
        }
        goto discarded;
    }
    tcpsdbg("3. No check the security and precedence");
    tcpsdbg("4. check syn");
    if (tcp_hdr->syn) {
        tsk->irs = seg->seq;   /* 初始接收序列号 */
        tsk->rcv_nxt = seg->seq + 1;  /* 应该接收的下一个序列号 */
        if (tcp_hdr->ack)
            tsk->snd_una = seg->ack; /* 发送的seq的ack */
        if (tsk->snd_una > tsk->iss) { /*  */
            tcp_set_state(tsk, TCP_ESTABLISHED);
            tsk->snd_wnd = seg->wnd;
            tsk->snd_wl1 = seg->seq;
            tsk->snd_wl2 = seg->ack;
            tcp_send_ack(tsk, seg);
            tcpsdbg("Active three-way handshake successes!(SND.WIN:%d)", tsk->snd_wnd);
            wake_up(tsk->wait_connect);
        } else {
            tcp_set_state(tsk, TCP_SYN_RECV);
            tcp_send_synack(tsk, seg);
            tcpsdbg("Simultaneous open(SYN-SENT => SYN-RECV)");
            return;
        }
    }
    tcpsdbg("5. drop the segment");
discarded:
    free_pkb(pkb);
}

static int tcp_synrecv_ack(struct tcp_sock *tsk)
{
    if (tsk->parent->state != TCP_LISTEN)
        return -1;
    if (tcp_accept_queue_full(tsk->parent))
        return -1;
    tcp_accept_enqueue(tsk);
    tcpsdbg("Passive three-way handshake successes!");
    wake_up(tsk->parent->wait_accept);
    return 0;
}

static int seq_check(struct tcp_segment *seg, struct tcp_sock *tsk)
{
    unsigned int rcv_end = tsk->rcv_nxt + (tsk->rcv_wnd ?: 1);
    if (seg->seq < rcv_end && tsk->rcv_nxt <= seg->lastseq)
        return 0;
    tcpsdbg("rcv_nxt:%u <= seq:%u < rcv_end:%u",
        tsk->rcv_nxt, seg->seq, rcv_end);
    return -1;
}

static _inline void __tcp_update_window(struct tcp_sock *tsk,
                    struct tcp_segment *seg)
{
    tsk->snd_wnd = seg->wnd;
    tsk->snd_wl1 = seg->seq;
    tsk->snd_wl2 = seg->ack;
}

static _inline void tcp_update_window(struct tcp_sock *tsk,
                    struct  tcp_segment *seg)
{
    if ((tsk->snd_una <= seg->ack && seg->ack <= tsk->snd_nxt) &&
        (tsk->snd_wl1 < seg->seq ||
        (tsk->snd_wl1 == seg->seq && tsk->snd_wl2 <= seg->ack)))
        __tcp_update_window(tsk, seg);
}

/*
    @pkb: pkb数据包
    @seg: tcp分片
    @sk: tcp sock
*/
void tcp_process(struct pkbuf *pkb, struct tcp_segment *seg, struct sock *sk)
{
    struct tcp_sock *tsk = tcpsk(sk);
    struct tcp *tcp_hdr = seg->tcp_hdr;
    tcp_dbg_state(tsk);
    /* 下列判断是基于sock已存在的情况 */
    if (!tsk || tsk->state == TCP_CLOSE)
        return tcp_closed(tsk, pkb, seg);
    if (tsk->state == TCP_LISTEN)
        return tcp_listen(pkb, seg, tsk);
    if (tsk->state == TCP_SYN_SENT)
        return tcp_synsent(pkb, seg, tsk);
    if (tsk->state >= TCP_MAX_STATE)
        goto drop;
    
    tcpsdbg("1. check seq");
    if (seq_check(seg, tsk) < 0) {
        if (!tcp_hdr->rst)
            tsk->flags |= TCP_F_ACKNOW;
        goto drop;
    }

    tcpsdbg("2. check rst");
    if (tcp_hdr->rst) {
        switch (tsk->state) {
            case TCP_SYN_RECV:
                if (tsk->parent) {
                    tcp_unhash(&tsk->sk);
                } else {
                    if (tsk->wait_connect)
                        wake_up(tsk->wait_connect);
                }
                break;
            case TCP_ESTABLISHED:
            case TCP_FIN_WAIT1:
            case TCP_FIN_WAIT2:
            case TCP_CLOSE_WAIT:
                break;
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_TIME_WAIT:
                break;
        }
        tcp_set_state(tsk, TCP_CLOSE);
        tcp_unhash(&tsk->sk);
        tcp_unbhash(tsk);
        goto drop;
    }
    tcpsdbg("3. No check security and precedence");
    tcpsdbg("4. check syn");
    if (tcp_hdr->syn) {
        tcp_send_reset(tsk, seg);
        if (tsk->state == TCP_SYN_RECV && tsk->parent)
            tcp_unhash(&tsk->sk);
        tcp_set_state(tsk, TCP_CLOSE);
        free_sock(&tsk->sk);
    }
    tcpsdbg("5. check ack");
    if (!tcp_hdr->ack)
        goto drop;
    switch (tsk->state) {
        case TCP_SYN_RECV:
            if (tsk->snd_una <= seg->ack && seg->ack <= tsk->snd_nxt) {
                if (tcp_synrecv_ack(tsk) < 0) {
                    tcpsdbg("drop");
                    goto drop;
                }
                tsk->snd_una = seg->ack;
                __tcp_update_window(tsk, seg);
                tcp_set_state(tsk, TCP_ESTABLISHED);
            } else {
                tcp_send_reset(tsk, seg);
                goto drop;
            }
            break;
        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
        case TCP_LAST_ACK:
        case TCP_FIN_WAIT1:
        case TCP_CLOSING:
            tcpsdbg("SND.UNA %u < SEG.ACK %u <= SND.NXT %u",
                tsk->snd_una, seg->ack, tsk->snd_nxt);
            if (tsk->snd_una < seg->ack && seg->ack <= tsk->snd_nxt) {
                tsk->snd_una = seg->ack;
                if (tsk->state == TCP_FIN_WAIT1) {
                    tcp_set_state(tsk, TCP_FIN_WAIT2);
                } else if (tsk->state == TCP_CLOSING) {
                    tcp_set_timewait_timer(tsk);
                    goto drop;
                } else if (tsk->state == TCP_LAST_ACK) {
                    tcp_set_state(tsk, TCP_CLOSE);
                    tcp_unhash(&tsk->sk);
                    tcp_unbhash(tsk);
                    goto drop;
                }
            } else if (seg->ack > tsk->snd_nxt) {
                goto drop;
            } else if (seg->ack <= tsk->snd_una) {
                
            }
            tcp_update_window(tsk, seg);
        case TCP_FIN_WAIT2:
            break;
        case TCP_TIME_WAIT:
            break;
    }
    tcpsdbg("6. check urg");
    if (tcp_hdr->urg) {
        switch (tsk->state) {
            case TCP_ESTABLISHED:
            case TCP_FIN_WAIT1:
            case TCP_FIN_WAIT2:
                break;
            case TCP_CLOSE_WAIT:
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_TIME_WAIT:
                break;
            case TCP_SYN_RECV:
                break;
        }
    }
    tcpsdbg("7. segment text");
    switch (tsk->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
            if (tcp_hdr->psh || seg->dlen > 0)
                tcp_recv_text(tsk, seg, pkb);
            break;
    }
    tcpsdbg("8. check fin");
    if (tcp_hdr->fin) {
        switch (tsk->state) {
            case TCP_SYN_RECV:
            case TCP_ESTABLISHED:
                tcp_set_state(tsk, TCP_CLOSE_WAIT);
                tsk->flags |= TCP_F_PUSH;
                tsk->sk.sk_ops->recv_notify(&tsk->sk);
                break;
            case TCP_FIN_WAIT1:
                tcp_set_state(tsk, TCP_CLOSING);
                break;
            case TCP_CLOSE_WAIT:
            case TCP_CLOSING:
            case TCP_LAST_ACK:
                break;
            case TCP_TIME_WAIT:
                tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
                break;
            case TCP_FIN_WAIT2:
                tcp_set_timewait_timer(tsk);
                break;
        }
        tsk->rcv_nxt = seg->seq + 1;
        tsk->flags |= TCP_F_ACKNOW;
    }
drop:
    if (tsk->flags & (TCP_F_ACKNOW|TCP_F_ACKDELAY))
        tcp_send_ack(tsk, seg);
    free_pkb(pkb);
}