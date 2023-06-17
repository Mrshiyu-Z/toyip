#include "list.h"
#include "netif.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "lib.h"
#include "route.h"

/*
    网络层发送给物理层
    @dev: 指定从哪个网络接口发送出去
    @pkb: 发送的数据包
*/
void ip_send_dev(struct netdev *dev, struct pkbuf *pkb)
{
    struct arpentry *ae;
    unsigned int dst;
    struct rtentry *rt = pkb->pk_rtdst;
    // 查看是否是本地路由
    if ( rt->rt_flags & RT_LOCALHOST ){
        ipdbg("To loopback");
        netdev_tx(dev, pkb, pkb->pk_len - ETH_HRD_SZ, 
                    ETH_P_IP, dev->net_hwaddr);
        return;
    }
    // 是否是默认路由,或者路由跳数大于1
    if ((rt->rt_flags & RT_DEFAULT) || rt->rt_metric > 0)
        dst = rt->rt_gateway;
    else
        dst = pkb2ip(pkb)->ip_dst;
    // 利用arp寻找目的IP的mac地址
    ae = arp_lookup(ETH_P_IP, dst);
    if (!ae) {
        arpdbg("not found arp cache");
        ae = arp_alloc();
        if (!ae) {
            ipdbg("arp cache is full");
            free_pkb(pkb);
            return;
        }
        ae->ae_ipaddr = dst;
        ae->ae_dev = dev;
        list_add_tail(&pkb->pk_list, &ae->ae_list);
        arp_request(ae);
    } else if (ae->ae_state == ARP_WAITING) {
        arpdbg("arp entry is waiting");
        list_add_tail(&pkb->pk_list, &ae->ae_list);
    } else {
        netdev_tx(dev, pkb, pkb->pk_len - ETH_HRD_SZ,
                    ETH_P_IP, ae->ae_hwaddr);
    }
}

void ip_send_out(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    pkb->pk_protocol = ETH_P_IP;
    if (!pkb->pk_rtdst && rt_output(pkb) < 0) {
        free_pkb(pkb);
        return;
    }
    ip_set_checksum(ip_hdr);
    ipdbg(IPFMT " -> " IPFMT "(%d/%d bytes)",
            ipfmt(ip_hdr->ip_src), ipfmt(ip_hdr->ip_dst),
            iphlen(ip_hdr), _ntohs(ip_hdr->ip_len));
    // 如果报文长度大于mtu
    if (_ntohs(ip_hdr->ip_len) > pkb->pk_rtdst->rt_dev->net_mtu)
        ip_send_frag(pkb->pk_rtdst->rt_dev, pkb);
    else
        ip_send_dev(pkb->pk_rtdst->rt_dev, pkb);
    
}