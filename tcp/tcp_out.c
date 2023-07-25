#include "ether.h"
#include "lib.h"
#include "list.h"
#include "netif.h"
#include "route.h"
#include "ip.h"
#include "tcp.h"


static int tcp_init_pkb(struct tcp_sock *tsk, struct pkbuf *pkb,
            unsigned int saddr, unsigned int daddr)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    ip_hdr->ip_hlen = IP_HDR_SZ >> 2;
    ip_hdr->ip_ver = IP_VERSION_4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = _htons(pkb->pk_len - ETH_HDR_SZ);
    ip_hdr->ip_id = _htons(tcp_id);
    ip_hdr->ip_fragoff = 0;
    ip_hdr->ip_ttl = TCP_DEFAULT_TTL;
    ip_hdr->ip_pro = IP_P_TCP;
    ip_hdr->ip_dst = daddr;

    if (tsk && tsk->sk.sk_dst) {
        pkb->pk_rtdst = tsk->sk.sk_dst;
    } else {
        if (rt_output(pkb) < 0)
            return -1;
        if (tsk)
            tsk->sk.sk_dst = pkb->pk_rtdst;
    }
    ip_hdr->ip_src = saddr;
    return 0;
}

/*
    将tcp报文发送给IP层
    @tsk: tcp_sock
    @pkb: 要发送的pkb
    @seg: tcp 片段
*/
void tcp_send_out(struct tcp_sock *tsk, struct pkbuf *pkb, struct tcp_segment *seg)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct tcp *tcp_hdr = (struct tcp *)ip_hdr->ip_data;
    unsigned int  saddr, daddr;

    if (seg) {
        daddr = seg->ip_hdr->ip_src;
        saddr = seg->ip_hdr->ip_dst;
    } else if (tsk) {
        daddr = tsk->sk.sk_daddr;
        saddr = tsk->sk.sk_saddr;
    } else
        assert(0);
    
    if (tcp_init_pkb(tsk, pkb, saddr, daddr) < 0) {
        free_pkb(pkb);
        return;
    }
    tcp_set_checksum(ip_hdr, tcp_hdr);
    ip_send_out(pkb);
}

void tcp_send_reset(struct tcp_sock *tsk, struct tcp_segment *seg)
{
    struct tcp *otcp, *tcp_hdr = seg->tcp_hdr;
    struct pkbuf *opkb;

    if (tcp_hdr->rst)
        return;
    opkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + TCP_HDR_SZ);

    otcp = (struct tcp *)pkb2ip(opkb)->ip_data;
    otcp->src = tcp_hdr->dst;
    otcp->dst = tcp_hdr->src;
    if (tcp_hdr->ack) {
        otcp->seq = tcp_hdr->ackn;
    } else {
        otcp->ackn = _htonl(seg->seq + seg->len);
        otcp->ack = 1;
    }
    otcp->doff = TCP_HDR_DOFF;
    otcp->rst = 1;
    tcpdbg("send RESET from "IPFMT":%d to "IPFMT"%d",
            ipfmt(seg->ip_hdr->ip_dst), _ntohs(otcp->src),
            ipfmt(seg->ip_hdr->ip_src), _ntohs(otcp->dst));
    tcp_send_out(NULL, opkb, seg);
}

void tcp_send_ack(struct tcp_sock *tsk, struct tcp_segment *seg)
{
    struct tcp *otcp, *tcp_hdr = seg->tcp_hdr;
    struct pkbuf *opkb;

    if (tcp_hdr->rst)
        return;
    opkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + TCP_HDR_SZ);

    otcp = (struct tcp *)pkb2ip(opkb)->ip_data;
    otcp->src = tcp_hdr->dst;
    otcp->dst = tcp_hdr->src;
    otcp->doff = TCP_HDR_DOFF;
    otcp->seq = _htonl(tsk->snd_nxt);
    otcp->ackn = _htonl(tsk->rcv_nxt);
    otcp->ack = 1;
    otcp->ackn = _htons(tsk->rcv_wnd);
    tcpdbg("send ACK(%u) [WIN %d] to "IPFMT":%d",
            _ntohl(otcp->ackn), _ntohs(otcp->window),
            ipfmt(seg->ip_hdr->ip_src), _ntohs(otcp->dst));
    tcp_send_out(tsk, opkb, seg);
}

/*
    给syn报文回复ack报文
    @tsk: 为syn报文创建的tcp_sock
    @eg: syn报文的tcp片段
*/
void tcp_send_synack(struct tcp_sock *tsk, struct tcp_segment *seg)
{
    struct tcp *otcp, *tcp_hdr = seg->tcp_hdr;
    struct pkbuf *opkb;
    if (tcp_hdr->rst)
        return;
    opkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + TCP_HDR_SZ);  /* 创建将要发送的pkb */

    otcp = (struct tcp *)pkb2ip(opkb)->ip_data;
    otcp->src = tcp_hdr->dst;
    otcp->dst = tcp_hdr->src;
    otcp->doff = TCP_HDR_DOFF;
    otcp->seq = _htonl(tsk->iss);
    otcp->ackn = _htonl(tsk->rcv_nxt);   /* rcv_nxt = seq + 1 */
    otcp->syn = 1;
    otcp->ack = 1;
    otcp->window = _htons(tsk->rcv_wnd);  /* tsk->rcv_wnd == TCP_DEFAULT_WINDOW */
    tcpdbg("send SYN(%u)/ACK(%u) [WIN %d] to "IPFMT":%d",
            _ntohl(otcp->seq), _ntohs(otcp->window),
            _ntohl(otcp->ackn), ipfmt(seg->ip_hdr->ip_dst),
            _ntohs(otcp->dst));
    tcp_send_out(tsk, opkb, seg);
}

void tcp_send_syn(struct tcp_sock *tsk, struct tcp_segment *seg)
{
    struct tcp *otcp;
    struct pkbuf *opkb;

    opkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + TCP_HDR_SZ);
    otcp = (struct tcp *)pkb2ip(opkb)->ip_data;
    otcp->src = tsk->sk.sk_sport;
    otcp->dst = tsk->sk.sk_dport;
    otcp->doff = TCP_HDR_DOFF;
    otcp->seq = _htonl(tsk->iss);
    otcp->syn = 1;
    otcp->window = _htons(tsk->rcv_wnd);
    tcpdbg("send SYN(%u) [WIN %d] to "IPFMT":%d",
            _ntohl(otcp->seq), _ntohs(otcp->window),
            ipfmt(tsk->sk.sk_daddr), _ntohs(otcp->dst));
    tcp_send_out(tsk, opkb, seg);
}

void tcp_send_fin(struct tcp_sock *tsk)
{
    struct tcp *otcp;
    struct pkbuf *opkb;

    opkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + TCP_HDR_SZ);
    otcp = (struct tcp *)pkb2ip(opkb)->ip_data;
    otcp->src = tsk->sk.sk_sport;
    otcp->dst = tsk->sk.sk_dport;
    otcp->doff = TCP_HDR_DOFF;
    otcp->seq = _htonl(tsk->snd_nxt);
    otcp->window = _htons(tsk->rcv_wnd);
    otcp->fin = 1;

    otcp->ack = 1;
    otcp->ackn = _htonl(tsk->rcv_nxt);
    tcpdbg("send FIN(%u)/ACK(%u) [WIN %d] to "IPFMT":%d",
            _ntohl(otcp->seq), _ntohl(otcp->ackn),
            _ntohs(otcp->window), ipfmt(tsk->sk.sk_daddr),
            _ntohs(otcp->dst));
    tcp_send_out(tsk, opkb, NULL);
}