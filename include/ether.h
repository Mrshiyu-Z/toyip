#ifndef __ETHER_H__
#define __ETHER_H__

#include <string.h>

#define ETH_HDR_SZ sizeof(struct ether)     /* 以太网帧头部长度 */
#define ETH_ALEN   6                        /* MAC地址长度 */

/*
    以太网协议类型,对应struct ether的eth_pro字段
*/
#define ETH_P_IP   0x0800                   /* IP协议类型 */
#define ETH_P_ARP  0x0806                   /* ARP协议类型 */
#define ETH_P_RARP 0x8035                   /* RARP协议类型 */

/*
    以太网帧头部
*/
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

/*
    比较MAC地址
    @hw1:   MAC地址1
    @hw2:   MAC地址2    
*/
static inline int hwacmp(void *hw1, void *hw2)
{
    return memcmp(hw1, hw2, ETH_ALEN);
}

/*
    设置MAC地址
    @dst:   MAC地址
    @val:   MAC地址的值
*/
static inline void hwaset(void *dst, int val)
{
    memset(dst, val, ETH_ALEN);
}

#define macfmt(ha) (ha)[0], (ha)[1], (ha)[2], (ha)[3], (ha)[4], (ha)[5]
#define MACFMT "%02x:%02x:%02x:%02x:%02x:%02x"

/*
    以太网协议类型
    @proto: 协议类型
*/
static inline char *ethpro(unsigned short proto)
{
    if (proto == ETH_P_IP)
        return "IP";
    else if (proto == ETH_P_ARP)
        return "ARP";
    else if (proto == ETH_P_RARP)
        return "RARP";
    else
        return "OTHER";
}

/*
    判断是否为组播地址
    @mac:   MAC地址
*/
static inline int is_eth_multicast(unsigned char *mac)
{
    return (mac[0] & 0x01);
}

/*
    判断是否为广播地址
    @mac:   MAC地址
*/
static inline int is_eth_broadcast(unsigned char *mac)
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff;
}

#endif