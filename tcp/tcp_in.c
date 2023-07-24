#include "arp.h"
#include "lib.h"
#include "netif.h"
#include "sock.h"
#include "tcp.h"
#include "ip.h"

static char *tcp_control_sring(struct tcp *tcp_hdr)
{
    static char ss[32];
    char *ssp = ss;
    if (tcp_hdr->fin) {
        strcpy(ssp, "FIN|");
        ssp += 4;
    }
    if (tcp_hdr->syn) {
        strcpy(ssp, "SYN|");
        ssp += 4;
    }
    if (tcp_hdr->rst) {
        strcpy(ssp, "RST|");
        ssp += 4;
    }
    if (tcp_hdr->psh) {
        strcpy(ssp, "PSH|");
        ssp += 4;
    }
    if (tcp_hdr->ack) {
        strcpy(ssp, "ACK|");
        ssp += 4;
    }
    if (tcp_hdr->urg) {
        strcpy(ssp, "URG|");
        ssp += 4;
    }
    if (ssp == ss)
        ssp[0] = '\0';
    else
        ssp[-1] = '\0';
    return ss;
}

static void tcp_segment_init(struct tcp_segment *seg, struct ip *ip_hdr, struct tcp *tcp_hdr)
{
    seg->seq = _ntohl(tcp_hdr->seq);
    seg->dlen = ipdlen(ip_hdr) - tcphlen(tcp_hdr);
    seg->len = seg->dlen + tcp_hdr->syn + tcp_hdr->fin;
    seg->text = tcptext(tcp_hdr);
    seg->lastseq = seg->len ? (seg->seq + seg->len - 1 ) : seg->seq;
    seg->ack = tcp_hdr->ack ? _ntohl(tcp_hdr->ackn) : 0;
    seg->wnd = _ntohs(tcp_hdr->window);
    seg->up = _ntohs(tcp_hdr->urgptr);
    seg->prc = 0;
    seg->ip_hdr = ip_hdr;
    seg->tcp_hdr = tcp_hdr;
    tcpdbg("from "IPFMT":%d" " to " IPFMT ":%d"
        "\tseq:%u(%d:%d) ack:%u %s",
            ipfmt(ip_hdr->ip_src), _ntohs(tcp_hdr->src),
            ipfmt(ip_hdr->ip_dst), _ntohs(tcp_hdr->dst),
            _ntohl(tcp_hdr->seq), seg->dlen, seg->len,
            _ntohl(tcp_hdr->ackn), tcp_control_sring(tcp_hdr));
}

/*
    tcp报文接收
    @pkb: pkb包
    @ip_hdr: ip 报文
    @tcp_hdr: tcp 报文
*/
static void tcp_recv(struct pkbuf *pkb, struct ip *ip_hdr, struct tcp *tcp_hdr)
{
    struct tcp_segment seg;
    struct sock *sk;
    tcp_segment_init(&seg, ip_hdr, tcp_hdr);
    sk = tcp_lookup_sock(ip_hdr->ip_src, ip_hdr->ip_dst, tcp_hdr->src, tcp_hdr->dst);
    tcp_process(pkb, &seg, sk);
    if (sk)
        free_sock(sk);
}

/*
    tcp入口
    @pkb: pkb数据包
*/
void tcp_in(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct tcp *tcp_hdr = ip2tcp(ip_hdr);
    int tcp_len = ipdlen(ip_hdr);

    tcpdbg("%d bytes, real %d bytes",tcp_len, tcphlen(tcp_hdr));
    /* 检查tcp报文长度 */
    if (tcp_len < TCP_HDR_SZ || tcp_len < tcphlen(tcp_hdr)) {
        tcpdbg("tcp length it too small");
        goto drop_pkb;
    }
    /* 检查tcp checksum */
    if (tcp_chksum(ip_hdr->ip_src, ip_hdr->ip_dst,
            tcp_len, (unsigned short *)tcp_hdr) != 0) {
            tcpdbg("tcp packet checksum corrupts");
            goto drop_pkb;
        }
    return tcp_recv(pkb, ip_hdr, tcp_hdr);
drop_pkb:
    free_pkb(pkb);
}
