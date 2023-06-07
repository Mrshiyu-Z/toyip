#ifndef __ARP_H__
#define __ARP_H__

#include "ether.h"
#include "ip.h"
#include "list.h"
#include "netif.h"

/*
    ARP帧头部
*/
struct arp
{
    unsigned short arp_hrd;                  /* 硬件类型 */
    unsigned short arp_pro;                  /* 协议类型 */
    unsigned char arp_hlen;                  /* 硬件地址长度 */
    unsigned char arp_plen;                  /* 协议地址长度 */
    unsigned short arp_op;                   /* ARP操作类型 */
    unsigned char arp_src_hw[ETH_ALEN];      /* 源MAC地址 */
    unsigned int arp_src_ip;                 /* 源IP地址 */
    unsigned char arp_dst_hw[ETH_ALEN];      /* 目的MAC地址 */
    unsigned int arp_dst_ip;                 /* 目的IP地址 */
}__attribute__((packed));

#define ARP_HDR_SZ sizeof(struct arp)   /* ARP帧头部大小 */

#define ARP_HDR_ETHER    1             /* 以太网帧类型,对应arp_hrd */
#define ARP_PRO_IP       0x0800        /* IPV4协议类型,对应arp_pro */
#define ARP_PRO_IPV6     0x86dd        /* IPV6协议类型,对应arp_pro */
#define ARP_OP_REQUEST   1             /* ARP请求操作类型,对应arp_op */
#define ARP_OP_REPLY     2             /* ARP应答操作类型,对应arp_op */

#define BRD_HWADDR ((unsigned char *)"\xff\xff\xff\xff\xff\xff")  /* 广播MAC地址 */

/*
    ARP缓存条目
*/
struct arpentry
{
    struct list_head ae_list;             /* ARP缓存链表 */
    struct netdev *ae_dev;                /* 网络设备 */
    int ae_retry;                         /* arp请求重试次数 */
    int ae_ttl;                           /* ARP超时时间 */
    unsigned int ae_state;                /* ARP条目状态 */
    unsigned short ae_pro;                /* ARP支持的三层协议 */
    unsigned int ae_ipaddr;               /* ARP缓存的三层IP地址 */
    unsigned char ae_hwaddr[ETH_ALEN];    /* ARP缓存的二层MAC地址 */
}__attribute__((packed));

#define ARP_CACHE_SZ   20               /* ARP缓存最大条目数量 */
#define ARP_TIMEOUT    600              /* ARP超时时间,对应ar_ttl */
#define ARP_WAITTIME	1               /* ARP等待时间 */

#define ARP_REQ_RETRY	3               /* ARP请求重试次数 */

/* ARP条目状态,对应ae_state */
#define ARP_FREE	    1               /* 释放 */
#define ARP_WAITING	    2               /* 已发送请求,等待回应 */
#define ARP_RESOLVED	3               /* 已缓存,在有效期内 */

static inline void arp_hton(struct arp *arphdr)
{
    arphdr->arp_hrd = _htons(arphdr->arp_hrd);
    arphdr->arp_pro = _htons(arphdr->arp_pro);
    arphdr->arp_op = _htons(arphdr->arp_op);
}
#define arp_ntoh(arphdr) arp_hton(arphdr)

extern void arp_timer(int delay);
extern void arp_cache_init(void);

extern struct arpentry *arp_alloc(void);
extern struct arpentry *arp_lookup(unsigned short pro, unsigned int ipaddr);
extern int arp_insert(struct netdev *dev, unsigned short pro,unsigned int ipaddr, unsigned char *hwaddr);

extern void arp_queue_send(struct arpentry *ae);
extern void arp_queue_drop(struct arpentry *ae);
extern void arp_request(struct arpentry *ae);
extern void arp_in(struct netdev *dev, struct pkbuf *pkb);
#endif