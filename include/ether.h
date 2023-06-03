#ifndef __ETHER_H__
#define __ETHER_H__

#include <string.h>

#define ETH_HRD_SZ sizeof(struct ether)     /* 以太网帧头部长度 */
#define ETH_ALEN   6                        /* MAC地址长度 */

/*
    以太网协议类型,对应struct ether的eth_pro字段
*/
#define ETH_P_IP   0x0800                   /* IP协议类型 */
#define ETH_P_ARP  0x0806                   /* ARP协议类型 */
#define ETH_P_RARP 0x8035                   /* RARP协议类型 */

struct ether
{
    unsigned char eth_dst[6];   /* 目的mac地址 */
    unsigned char eth_src[6];   /* 源mac地址 */
    unsigned short eth_pro;     /* 协议类型 */
    unsigned char eth_data[0];  /* 数据 */
}__attribute__((packed));

/*
    复制MAC地址
    @dst:   MAC复制的目的地址
    @src:   MAC复制的源地址
*/
static inline void hwcpy(void *dst, void *src)
{
    memcpy(dst, src, ETH_ALEN);
}

#endif