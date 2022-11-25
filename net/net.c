#include "net.h"
#include "eth.h"
#include "arp.h"
#include "lib.h"
#include "ip.h"

void free_pkg(struct pkg_buf *pkg)
{
    free(pkg);
}

void net_in(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    if (!eth){
        return;
    }
    pkg->pkg_type = htons(eth->ethertype);
    struct ip_hdr *ip = pkg_2_iphdr(pkg);
    switch (pkg->pkg_type)
    {
        case ETH_TYPE_ARP:
            arp_in(pkg);
            break;
        case ETH_TYPE_IP:
            ip_recv_route(pkg);
            break;
        default:
            perror("unsupported ethertype");
            free_pkg(pkg);
            break;
    }
}

void net_out(struct pkg_buf *pkg,unsigned char *dmac, unsigned short eth_type)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    memcpy(eth->dmac, dmac, 6);
    cp_mac_lo(eth->smac);
    eth->ethertype = htons(eth_type);
    eth_out(pkg);
}

void net_timer(void)
{
    while (1)
    {
        sleep(1);
        arp_timer(1);
        // ip_frag_timer(1);
    }
}