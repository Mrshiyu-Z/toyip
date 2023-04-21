#ifndef __ETHER_H__
#define __ETHER_H__

#include <string.h>

struct ether
{
    unsigned char eth_dst[6];   /* 目的mac地址 */
    unsigned char eth_src[6];   /* 源mac地址 */
    unsigned short eth_pro;     /* 协议类型 */
    unsigned char eth_data[0];  /* 数据 */
}__attribute__((packed));

#endif