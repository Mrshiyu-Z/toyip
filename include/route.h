#ifndef __ROUTE_H__
#define __ROUTE_H__

#include "netif.h"

struct rtentry {
    struct list_head rt_list;
    unsigned int rt_net;      // 网络层地址
    unsigned int rt_netmask;  // 网络层掩码
    unsigned int rt_gateway;  // 网关地址
    unsigned int rt_flags;    // 路由标志
    int rt_metric;            // 路由度量
    struct netdev *rt_dev;    // 路由设备
};

/* 路由标志,对应rt_flags */
#define RT_NONE         0x00000000
#define RT_LOCALHOST	0x00000001
#define RT_DEFAULT	    0x00000002

extern struct rtentry *rt_lookup(unsigned int ip_addr);
extern void rt_add(unsigned int net, unsigned int netmask, unsigned int gw,
            int metric, unsigned int flags, struct netdev *dev);
extern void rt_init(void);
extern int rt_output(struct pkbuf *pkb);
extern int rt_input(struct pkbuf *pkb);
extern void rt_traverse(void);

#endif