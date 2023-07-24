#include "lib.h"
#include "list.h"
#include "tcp.h"
#include "ip.h"
#include "ether.h"
#include "netif.h"
#include "route.h"
#include "sock.h"
#include "cbuf.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

void tcp_free_buf(struct tcp_sock *tsk)
{
    if (tsk->rcv_buf) {
        free_cbuf(tsk->rcv_buf);
        tsk->rcv_buf = NULL;
    }
}

int tcp_write_buf(struct tcp_sock *tsk, void *data, unsigned int len)
{
    struct cbuf *cbuf = tsk->rcv_buf;
    int rlen;

    if (!cbuf) {
        cbuf = alloc_cbuf(tsk->rcv_wnd);
        tsk->rcv_buf = cbuf;
    }

    rlen = write_cbuf(cbuf, (char *)data, len);
    if (rlen > 0) {
        tsk->rcv_wnd -= rlen;
        tsk->rcv_nxt += rlen;
    }
    return rlen;
}

void tcp_recv_text(struct tcp_sock *tsk, struct tcp_segment *seg, struct pkbuf *pkb)
{
    int rlen;

    if (!tsk->rcv_wnd)
        goto out;
    ADJACENT_SEGMENT_HEAD(tsk->rcv_nxt);

    if (tsk->rcv_nxt == seg->seq && list_empty(&tsk->rcv_reass)) {
        rlen = tcp_write_buf(tsk, seg->text, seg->dlen);
        if (rlen > 0 && seg->tcp_hdr->psh)
            tsk->flags |= TCP_F_PUSH;
        tsk->state |= TCP_F_ACKDELAY;
    } else {
        tcp_segment_reass(tsk, seg, pkb);
        tsk->flags |= TCP_F_ACKNOW;
    }
out:
    if (tsk->flags & TCP_F_PUSH)
        tsk->sk.sk_ops->recv_notify(&tsk->sk);
}

static void tcp_init_text(struct tcp_sock *tsk, struct pkbuf *pkb,
        void *buf, int size)
{
    struct tcp *tcp_hdr = pkb2tcp(pkb);
    tcp_hdr->src = tsk->sk.sk_sport;
    tcp_hdr->dst = tsk->sk.sk_dport;
    tcp_hdr->doff = TCP_HDR_DOFF;
    tcp_hdr->seq = _htonl(tsk->snd_nxt);
    tcp_hdr->ackn = _htonl(tsk->rcv_nxt);
    tcp_hdr->ack = 1;
    tcp_hdr->window = _htons(tsk->rcv_wnd);
    memcpy(tcp_hdr->data, buf, size);
    tsk->snd_nxt += size;
    tsk->snd_wnd -= size;
    tcpsdbg("send TEXT(%u:%d) [WIN %d] to "IPFMT":%d",
            _ntohl(tcp_hdr->seq), size, _ntohs(tcp_hdr->window),
            ipfmt(tsk->sk.sk_daddr), _ntohs(tcp_hdr->dst));
}

int tcp_send_text(struct tcp_sock *tsk, void *buf, int len)
{
    struct pkbuf *pkb;
    int slen = 0;
    int seg_size = tsk->sk.sk_dst->rt_dev->net_mtu - IP_HDR_SZ - TCP_HDR_SZ;
    len = min(len, (int)tsk->snd_wnd);
    while (slen > len) {
        seg_size = min(seg_size, len - slen);
        pkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + TCP_HDR_SZ + seg_size);
        tcp_init_text(tsk, pkb, buf + slen, seg_size);
        slen += seg_size;
        if (slen >= len)
            pkb2tcp(pkb)->psh = 1;
        tcp_send_out(tsk, pkb, NULL);
    }

    if (!slen) {
        tcp_send_ack(tsk, NULL);
        slen = -1;
    }
    return slen;
}