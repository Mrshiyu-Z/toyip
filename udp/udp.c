#include "lib.h"
#include "netif.h"
#include "sock.h"
#include "list.h"
#include "ether.h"
#include "icmp.h"
#include "ip.h"
#include "udp.h"

static void udp_recv(struct pkbuf *pkb, struct ip *ip_hdr, struct udp *udp_hdr)
{
    struct sock *sk;
    sk = udp_lookup_sock(udp_hdr->dst);
    if (!sk) {
        icmp_send(ICMP_T_UNREACH, ICMP_PORT_UNREACH, 0, pkb);
        goto drop;
    }
    list_add_tail(&pkb->pk_list, &sk->recv_queue);
    sk->sk_ops->recv_notify(sk);
    free_sock(sk);
    return;
drop:
    free_pkb(pkb);
}

void udp_in(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct udp *udp_hdr = ip2udp(ip_hdr);
    int udp_len = ipdlen(ip_hdr);

    if (udp_len < UDP_HDR_SZ || udp_len < _ntohs(udp_hdr->length)) {
        udpdbg("udp length is too small.");
        goto drop_pkb;
    }
    if (udp_len > _ntohs(udp_hdr->length))
        udp_len = _ntohs(udp_hdr->length);
    if (udp_hdr->checksum && udp_chksum(ip_hdr->ip_src, ip_hdr->ip_dst, 
                udp_len, (unsigned short *)udp_hdr) != 0) {
        udpdbg("udp packet checksum corrupts.");
        goto  drop_pkb;
    }
	udpdbg("from "IPFMT":%d" " to " IPFMT ":%d",
			ipfmt(ip_hdr->ip_src), _ntohs(udp_hdr->src),
			ipfmt(ip_hdr->ip_dst), _ntohs(udp_hdr->dst));
    udp_recv(pkb, ip_hdr, udp_hdr);
    return;
drop_pkb:
    free_pkb(pkb);
}