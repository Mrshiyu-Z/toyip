#include "netif.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "lib.h"

/*
    发送ARP请求报文
    @ae:    ARP缓存条目
*/
void arp_request(struct arpentry *ae)
{
    struct pkbuf *pkb;
    struct ether *ethhdr;
    struct arp *arphdr;

    pkb = alloc_pkb(ETH_HRD_SZ + ARP_HDR_SZ);
    ethhdr = (struct ether *)pkb->pk_data;
    arphdr = (struct arp *)ethhdr->eth_data;
    /* 给ARP报文赋一些正常的初始值 */
    arphdr->arp_hrd = _htons(ARP_HDR_ETHER);
    arphdr->arp_pro = _htons(ETH_P_IP);
    arphdr->arp_hlen = ETH_ALEN;
    arphdr->arp_plen = IP_ALEN;
    arphdr->arp_pro = _htons(ARP_OP_REQUEST);
    /* 
        给ARP报文中的地址赋值 
        目的MAC地址为广播地址
    */
    arphdr->arp_src_ip = ae->ae_dev->net_ipaddr;
    hwcpy(arphdr->arp_src_hw, ae->ae_dev->net_hwaddr);
    arphdr->arp_dst_ip = ae->ae_ipaddr;
    hwcpy(arphdr->arp_dst_hw, BRD_HWADDR);
    dbg(IPFMT"("MACFMT") -> "IPFMT"(request)",
        ipfmt(arphdr->arp_src_ip), 
        macfmt(arphdr->arp_src_hw),
        ipfmt(arphdr->arp_dst_ip));
    netdev_tx(ae->ae_dev, pkb, pkb->pk_len - ETH_HRD_SZ, ETH_P_ARP, BRD_HWADDR);
}

/*
    发送ARP应答报文
    @dev:   网络设备
    @pkb:   接收到的数据包
*/
void arp_reply(struct netdev *dev, struct pkbuf *pkb)
{
    struct ether *ethhdr = (struct ether *)pkb->pk_data;
    struct arp *arphdr = (struct arp *)ethhdr->eth_data;
    dbg("replying arp request");
    arphdr->arp_op = ARP_OP_REPLY;
    hwcpy(arphdr->arp_dst_hw, arphdr->arp_src_hw);
    arphdr->arp_dst_ip = arphdr->arp_src_ip;
    hwcpy(arphdr->arp_src_hw, dev->net_hwaddr);
    arphdr->arp_src_ip = dev->net_ipaddr;
    arp_ntoh(arphdr);
    netdev_tx(dev, pkb, ARP_HDR_SZ, ETH_P_ARP, ethhdr->eth_src);
}

/*
    arp报文处理
    @dev:   网络设备
    @pkb:   接收到的数据包
*/
void arp_recv(struct netdev *dev, struct pkbuf *pkb)
{
    struct ether *ehdr = (struct ether *)pkb->pk_data;
    struct arp *arphdr = (struct arp *)ehdr->eth_data;
    struct arpentry *ae;
    dbg(IPFMT " -> " IPFMT, ipfmt(arphdr->arp_src_ip), ipfmt(arphdr->arp_dst_ip));

    /* 如果目的IP地址是多播地址,丢弃 */
    if (MULTICAST(arphdr->arp_dst_ip))
    {
        dbg("arp packet is multicast.");
        goto free_pkb;
    }

    /* 如果目的IP不是我们的网口IP,丢弃 */
    if ( arphdr->arp_dst_ip != dev->net_ipaddr )
    {
        dbg("arp packet is not for us.");
        goto free_pkb;
    }
    ae = arp_lookup(arphdr->arp_pro, arphdr->arp_src_ip);
    if (ae) 
    {
        /* 如果找到了条目, 则更新老的条目的mac地址 */
        hwcpy(ae->ae_hwaddr, arphdr->arp_src_hw);
        /* 处理reply报文 */
        if (ae->ae_state == ARP_WAITING )
            arp_queue_send(ae);
        ae->ae_state = ARP_RESOLVED;
        ae->ae_ttl = ARP_TIMEOUT;
    } else if (arphdr->arp_op == ARP_OP_REQUEST)
    {
        /* 如果是请求报文,就将请求方的ip和mac地址缓存 */
        arp_insert(dev, arphdr->arp_pro, arphdr->arp_src_ip, arphdr->arp_src_hw);
    }
    /* 如果是ARP请求报文,则发送ARP应答报文 */
    if (arphdr->arp_op == ARP_OP_REQUEST)
    {
        arp_reply(dev, pkb);
        return;
    }

free_pkb:
    free_pkb(pkb);
}

/*
    ARP报文入口
    @dev:   网络设备
    @pkb:   接收到的数据包
*/
void arp_in(struct netdev *dev, struct pkbuf *pkb)
{
    struct ether *ehdr = (struct ether *)pkb->pk_data;
    struct arp *arphdr = (struct arp *)ehdr->eth_data;
    /* 如果不是本机的ARP报文,则丢弃 */
    if (pkb->pk_type == PKT_OTHERHOST )
    {
        dbg("arp(l2) packet is not for us.");
        goto err_free_pkb;
    }

    /* 如果报文长度不够 */
    if ( pkb->pk_len < ETH_HRD_SZ + ARP_HDR_SZ)
    {
        dbg("arp packet is too small.");
        goto err_free_pkb;
    }
    /* 判断以太网源地址和arp源地址是否相同 */
    if (hwacmp(arphdr->arp_src_hw, ehdr->eth_src) != 0)
    {
        dbg("sender hardware address error.");
        goto err_free_pkb;
    }
    arp_hton(arphdr);
    arp_recv(dev, pkb);

err_free_pkb:
    free_pkb(pkb);
}