#include "net.h"
#include "eth.h"
#include "arp.h"
#include "lib.h"

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
            printf("ip in");
            break;
        default:
            free(pkg);
            break;
    }
}