#include "netif.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "route.h"
#include "lib.h"

void ip_forward(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct rtentry *rt = pkb->pk_rtdst;
    struct netdev *in_dev = pkb->pk_indev;
    unsigned int dst;
    ipdbg(IPFMT " -> " IPFMT "(%d/%d bytes) forwarding",
                ipfmt(ip_hdr->ip_src), ipfmt(ip_hdr->ip_dst),
                iphlen(ip_hdr), _ntohs(ip_hdr->ip_len));
    if (ip_hdr->ip_ttl <= 1) {
        icmp_send(ICMP_T_TIMXCEED, ICMP_EXC_TTL, 0, pkb);
        goto drop_pkb;
    }

    ip_hdr->ip_ttl--;
    ip_set_checksum(ip_hdr);

    if ((rt->rt_flags & RT_DEFAULT) || rt->rt_metric > 0)
        dst = rt->rt_gateway;
    else
        dst = ip_hdr->ip_dst;
    ipdbg("forward to next-hop "IPFMT, ipfmt(dst));
    if (in_dev == rt->rt_dev) {
        struct rtentry *srt = rt_lookup(ip_hdr->ip_src);
        if (srt && srt->rt_metric == 0 && 
            equsubnet(srt->rt_netmask, ip_hdr->ip_src, dst)) {
            if (srt->rt_dev != in_dev) {
                ipdbg("Two NIC are connected to the same LAN");
            }
            icmp_send(ICMP_T_REDIRECT, ICMP_REDIRECT_HOST, dst, pkb);
        }
    }
    if (_ntohs(ip_hdr->ip_len) > rt->rt_dev->net_mtu) {
        if (ip_hdr->ip_fragoff & _htons(IP_FRAG_DF)) {
            icmp_send(ICMP_T_UNREACH, ICMP_FRAG_NEEDED, 0, pkb);
            goto drop_pkb;
        }
        ip_send_frag(rt->rt_dev, pkb);
    } else {
        ip_send_frag(rt->rt_dev, pkb);
    }
    return;
drop_pkb:
    free_pkb(pkb);
}