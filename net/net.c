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
    unsigned short eth_type = htons(eth->ethertype);
    switch (eth_type)
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

void net_out(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    if (!eth){
        return;
    }
    if (eth->ethertype != ntohs(ETH_TYPE_ARP)){
        eth->ethertype = ntohs(ETH_TYPE_ARP);
    }
    memcpy(eth->dmac, eth->smac, ETH_MAC_LEN);
    cp_mac_lo(eth->smac);
    eth_tx(pkg);
}