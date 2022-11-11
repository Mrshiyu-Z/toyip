#include "lib.h"
#include "net.h"
#include "eth.h"
#include "arp.h"
#include "ip.h"

static unsigned char mac_multicast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void printf_arp(struct arp_hdr *arp)
{
    printf("arp->hlen = %d\n", arp->hlen);
    printf("arp->plen = %d\n", arp->plen);
    printf("arp->htype = %d\n", htons(arp->htype));
    printf("arp->ptype = %d\n", arp->ptype);
    printf("arp->opcode = %d\n", htons(arp->opcode));
    printf("arp->smac = %02x:%02x:%02x:%02x:%02x:%02x\n", arp->smac[0], arp->smac[1], arp->smac[2], arp->smac[3], arp->smac[4], arp->smac[5]);
    printf("arp->dmac = %02x:%02x:%02x:%02x:%02x:%02x\n", arp->dmac[0], arp->dmac[1], arp->dmac[2], arp->dmac[3], arp->dmac[4], arp->dmac[5]);
    printf("arp->sip = %d.%d.%d.%d\n", arp->sip[0], arp->sip[1], arp->sip[2], arp->sip[3]);
    printf("arp->dip = %d.%d.%d.%d\n", arp->dip[0], arp->dip[1], arp->dip[2], arp->dip[3]);
}

void arp_in(struct pkg_buf *pkg)
{
    printf("arp in\n");
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    // printf_arp(arp);
    if (pkg->pkg_len < ETH_HDR_LEN + ARP_HDR_LEN){     //确认报文长度
        printf("arp_in: pkg_len error\n");
        goto err_free_pkg;
    }
    if ((memcmp(arp->smac, eth->smac, ETH_MAC_LEN) != 0)){    //确认源mac地址
        printf("arp_in: memcpy error\n");
        goto err_free_pkg;
    }
    if (htons(arp->htype) != ARP_ETH_TYPE || htons(arp->ptype) != ETH_TYPE_IP || 
        arp->hlen != ETH_MAC_LEN || arp->plen != IP_ADDR_LEN){          //确认arp报文格式
            printf("unsupported L2/L3 protocol\n");
            goto err_free_pkg;
    }
    if (htons(arp->opcode) != ARP_REQ && htons(arp->opcode) != ARP_REP){    //确认arp报文类型是否为请求或响应
        printf("unsupported opcode\n");
        goto err_free_pkg;
    }
    arp_recv(pkg);      //处理arp报文
    return;
err_free_pkg:
    perror("arp_in: error\n");
    free(pkg);
}

void arp_send_request(struct arp_cache *ac)
{
    printf("arp_send_request\n");
    struct pkg_buf *pkg = pkg_alloc(ETH_HDR_LEN + ARP_HDR_LEN);
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    /* 给arp头部赋值 */ 
    arp->htype = htons(ARP_ETH_TYPE);                
    arp->ptype = htons(ETH_TYPE_IP);
    arp->hlen = ETH_MAC_LEN;
    arp->plen = IP_ADDR_LEN;
    arp->opcode = htons(ARP_REQ);
    cp_ip_lo(arp->sip);
    cp_mac_lo(arp->smac);
    memcpy(arp->dmac, mac_multicast, ETH_MAC_LEN);   //目的地址为组播地址
    memcpy(arp->dip, ac->ip, IP_ADDR_LEN);
    // printf_arp(arp);                              //打印arp头部
    net_out(pkg, mac_multicast,ETH_TYPE_ARP);
}

void arp_recv(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    if (htons(arp->htype) != 1){               //如果不是以太网
        perror("arp_recv: hwtype error\n");
        goto free_pkg;
    }
    if (htons(arp->ptype) != 0x0800){          //如果不是IPV4
        perror("arp_recv: protype error\n");
        goto free_pkg;
    }
    if(arp->hlen != 6 || arp->plen != 4){       //如果以太网长度或IPV4长度不是6和4,目前网络层只考虑IPV4
        perror("arp_recv: hlen/plen error\n");
        goto free_pkg;
    }
    // struct arp_cache *a
    if (check_ip_lo(arp->dip)){
        switch (htons(arp->opcode))
        {
        case 1:    //ARP请求
            arp_reply(pkg);
            break;
        case 2:    //ARP应答
            arp_reply_handle(pkg);
            break;
        default:
            perror("arp_recv: opcode error\n");
            goto free_pkg;
            break;
        }
        return;
    }
free_pkg:
    free(pkg);
}

void arp_reply(struct pkg_buf *pkg)     //回复ARP请求
{
    printf("arp reply\n");
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    arp->opcode = htons(ARP_REP);
    memcpy(arp->dmac, arp->smac, ETH_MAC_LEN);
    if (check_ip_lo(arp->dip))
    {
        cp_mac_lo(arp->smac);
        memcpy(arp->dip, arp->sip, IP_ADDR_LEN);
        cp_ip_lo(arp->sip);
    }else{
        free(pkg);
        return;
    }
    net_out(pkg, arp->dmac, ETH_TYPE_ARP);
}

void arp_reply_handle(struct pkg_buf *pkg)   //处理ARP应答
{
    printf("arp reply handle\n");
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    struct arp_cache *ac = arp_cache_lookup(arp->sip);
    if(ac)
    {
        memcpy(ac->mac, arp->smac, ETH_MAC_LEN);
        if (ac->state == ARP_PENDDING)
        {
            arp_queue_send(ac);
        }
        ac->state = ARP_RESOLVED;
        ac->ttl = ARP_TIMEOUT;
    }else
    {
        arp_insert(arp->sip, arp->smac);
    }
}