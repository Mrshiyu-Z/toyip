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

static struct tcp_sock *tcp_listen_child_sock(struct tcp_sock *tsk,
                        struct tcp_segment *seg)
{
    struct sock *newsk = tcp_alloc_sock(tsk->sk.protocol);
    struct tcp_sock *newtsk = tcpsk(newsk);
    tcp_set_state(newtsk, TCP_SYN_RECV);
    newsk->sk_saddr = seg->ip_hdr->ip_dst;
    newsk->sk_daddr = seg->ip_hdr->ip_dst;
    newsk->sk_sport = seg->tcp_hdr->dst;
    newsk->sk_dport = seg->tcp_hdr->src;

    if (tcp_hash(&newtsk->sk) < 0) {
        free(newtsk);
        return NULL;
    }

    newtsk->parent = get_tcp_sock(tsk);
    list_add(&newtsk->list, &tsk->listen_queue);

    return get_tcp_sock(newtsk);
}

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
    if (tcp_hdr->ack) {
        tcp_send_reset(tsk, seg);
        goto discarded;
    }
    tcpsdbg("3. check syn");
    if (!tcp_hdr->syn)
        goto discarded;
    
    newtsk = tcp_listen_child_sock(tsk, seg);
    if (!newtsk) {
        tcpsdbg("cannot alloc new sock");
        goto discarded;
    }
    newtsk->irs = seg->seq;
    newtsk->iss = alloc_new_iss();
    newtsk->rcv_nxt = seg->seq + 1;

    tcp_send_synack(newtsk, seg);
    newtsk->snd_nxt = newtsk->iss + 1;
    newtsk->snd_una = newtsk->iss;

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

static void tcp_synsent(struct pkbuf *pkb, struct tcp_segment *seg,
            struct tcp_sock *tsk)
{
    struct tcp *tcp_hdr = seg->tcp_hdr;
    tcpsdbg("SYN-SENT");
    tcpsdbg("1. check ack");
    if (tcp_hdr->ack) {
        if (seg->ack <= tsk->iss || seg->ack > tsk->snd_nxt) {
            tcp_send_reset(tsk, seg);
            goto discarded;
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
        tsk->irs = seg->seq;
        tsk->rcv_nxt = seg->seq + 1;
        if (tcp_hdr->ack)
            tsk->snd_una = seg->ack;
        if (tsk->snd_una > tsk->iss) {
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

void tcp_process(struct pkbuf *pkb, struct tcp_segment *seg, struct sock *sk)
{
    struct tcp_sock *tsk = tcpsk(sk);
    struct tcp *tcp_hdr = seg->tcp_hdr;
    tcp_dbg_state(tsk);
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