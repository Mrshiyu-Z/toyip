#include "net.h"
#include "eth.h"
#include "arp.h"
#include "lib.h"
#include "ip.h"


void net_in(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    if (!eth){
        return;
    }
    // printf("net_in: eth->type = %x\n", eth->ethertype);
    pkg->pkg_type = htons(eth->ethertype);
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
            free(pkg);
            break;
    }
}

void net_out(struct pkg_buf *pkg,unsigned char *dmac, unsigned short eth_type)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    memcpy(eth->dmac, dmac, 6);
    cp_mac_lo(eth->smac);
    eth->ethertype = htons(eth_type);
    // printf_eth(eth);
    // printf("----------------------\n");
    eth_out(pkg);
}