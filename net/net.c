#include <net/if.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/if_tun.h>

#include "netif.h"
#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "lib.h"
#include "netcfg.h"

/*
    解析收到的以太网帧
    @dev:   网络设备
    @pkb:   收到的以太网帧
*/
static struct ether *eth_init(struct netdev *dev, struct pkbuf *pkb)
{
    struct ether *ehdr = (struct ether *)pkb->pk_data;
    if (pkb->pk_len < ETH_HRD_SZ)
    {
        free_pkb(pkb);
        dbg("received packet is too small:%d bytes", pkb->pk_len);
        return NULL;
    }
    /* 判断是否为组播帧 */
    if (is_eth_multicast(ehdr->eth_dst))
    {
        /* 判断是否为广播帧 */
        if (is_eth_broadcast(ehdr->eth_dst))
            pkb->pk_type = PKT_BROADCAST;
        else
            pkb->pk_type = PKT_MULTICAST;
    } else if (!hwacmp(ehdr->eth_dst, dev->net_hwaddr))
    {
        pkb->pk_type = PKT_LOCALHOST;
    } else
    {
        pkb->pk_type = PKT_OTHERHOST;
    }
    pkb->pk_protocol = _ntohs(ehdr->eth_pro);
    return ehdr;
}

/*
    网络层入口
    @dev:   网络设备
    @pkb:   收到的以太网帧
*/
void net_in(struct netdev *dev, struct pkbuf *pkb)
{
    struct ether *ehdr = eth_init(dev, pkb);
    if (!ehdr)
        return;
    l2dbg(MACFMT " -> " MACFMT "(%s)",
                macfmt(ehdr->eth_src), 
                macfmt(ehdr->eth_dst),
                ethpro(pkb->pk_protocol));
    pkb->pk_indev = dev;
    switch (pkb->pk_protocol)
    {
        case ETH_P_IP:
            ip_in(dev, pkb);
            break;
        case ETH_P_ARP:
            arp_in(dev, pkb);
            break;
        case ETH_P_RARP:
            // rarp_in(dev, pkb);
            break;
        default:
            l2dbg("drop unkown-type packet");
            free_pkb(pkb);
            break;
    }
}

/*
    定时器线程
*/
void net_timer(void)
{
    while(1) {
        sleep(1);
        arp_timer(1);
    }
}