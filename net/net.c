#include "net.h"
#include "eth.h"
#include "arp.h"

void net_in(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    if (!eth){
        return;
    }
    switch (eth->ethertype)
    {
        case ETH_TYPE_ARP:
            break;
        case ETH_TYPE_IP:
            break;
        default:
            break;
    }
}