#include "compile.h"
#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "lib.h"
#include "route.h"
#include "list.h"

#include "netcfg.h"
#include <stdio.h>

static LIST_HEAD(rt_head);

/*
    查找路由表项
    @ip_addr: 网络层地址
*/
struct rtentry *rt_lookup(unsigned int ip_addr)
{
    struct rtentry *rt;
    /* 寻找和ip_addr相同的路由表项,主要比对网络地址 */
    list_for_each_entry(rt, &rt_head, rt_list) {
        if ((rt->rt_netmask & ip_addr) == 
            (rt->rt_netmask & rt->rt_net)) {
            return rt;
        }
    }
    return NULL;
}

/*
    申请一个路由表项
    @net: 网络层地址
    @netmask: 网络层掩码
    @gw: 网关地址
    @metric: 路由度量
    @flags: 路由标志
    @dev: 路由设备
*/
struct rtentry *rt_alloc(unsigned int net, unsigned int netmask,
    unsigned int gw, int metric, unsigned int flags, struct netdev *dev)
{
    struct rtentry *rt;
    rt = malloc(sizeof(*rt));
    rt->rt_net = net;
    rt->rt_netmask = netmask;
    rt->rt_gateway = gw;
    rt->rt_metric = metric;
    rt->rt_flags = flags;
    rt->rt_dev = dev;
    list_init(&rt->rt_list);
    return rt;
}

/*
    添加一个路由表项
    @net: 网络层地址
    @netmask: 网络层掩码
    @gw: 网关地址
    @metric: 路由度量
    @flags: 路由标志
    @dev: 路由设备
*/
void rt_add(unsigned int net, unsigned int netmask, unsigned int gw,
            int metric, unsigned int flags, struct netdev *dev)
{
    struct rtentry *rt, *rte;
    struct list_head *l;
    rt = rt_alloc(net, netmask, gw, metric, flags, dev);
    l = &rt_head;
    /* 
        插入时按照网络地址大小降序插入
        查找时从网络地址最大的开始查找
        表示从"网络范围"小的优先查找
    */
    list_for_each_entry(rte, &rt_head, rt_list) {
        if (rt->rt_netmask >= rte->rt_netmask) {
            l = &rte->rt_list;
            break;
        }
    }
    list_add_tail(&rt->rt_list, l);
}

/*
    路由表初始化,添加四条路由
*/
void rt_init(void)
{
    /* 回环路由,当目标IP为127.0.0.1时使用这条路由 */
    rt_add(LOCALNET(loop), loop->net_mask, 0, 0, RT_LOCALHOST, loop);
    /* 本地主机路由,当目标IP为本机IP时使用这条路由 */
    rt_add(veth->net_ipaddr, 0xffffffff, 0, 0, RT_LOCALHOST, loop);
    /* 
        本地网络路由,当目标IP与本机IP是同一个子网时使用这条路由
        表示某些数据包可以不经过网关,直接从这个接口就可以发送给目标主机
    */
    rt_add(LOCALNET(veth), veth->net_mask, 0, 0, RT_NONE, veth);
    /* 默认路由,当不满足上面的路由表项时,走这条路由 */
    rt_add(0, 0, tap->dev.net_ipaddr, 0, RT_DEFAULT, veth);
    dbg("route table init");
}

/*
    查找入方向的数据包的目的IP,本机是否有路由能够到达
*/
int rt_input(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct rtentry *rt = rt_lookup(ip_hdr->ip_dst);
    if (!rt) {
        ip_hton(ip_hdr);
        // icmp_send(ICMP_T_DESTUNREACH, ICMP_NET_UNREACH, 0, pkb);
        free_pkb(pkb);
        return -1;
    }
	pkb->pk_rtdst = rt;
	return 0;
}

int rt_output(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct rtentry *rt = rt_lookup(ip_hdr->ip_dst);
    if (!rt) {
        ipdbg("No route entry to "IPFMT, ipfmt(ip_hdr->ip_dst));
        return -1;
    }
    pkb->pk_rtdst = rt;
    ip_hdr->ip_src = rt->rt_dev->net_ipaddr;
    ipdbg("Find route entry from "IPFMT " to "IPFMT,
            ipfmt(ip_hdr->ip_src), ipfmt(ip_hdr->ip_dst));
    return 0;
}

void rt_traverse(void)
{
    struct rtentry *rt;
    if (list_empty(&rt_head)) {
        return;
    }
    printf("Destination     Gateway         Genmask          Metric Iface\n");
    list_for_each_entry(rt, &rt_head, rt_list) {
        if (rt->rt_flags & RT_LOCALHOST) {
            continue;
        }
        if (rt->rt_flags & RT_DEFAULT) {
            printf("default        ");
        } else {
            printfs(16, IPFMT, ipfmt(rt->rt_net));
        }
        if (rt->rt_gateway == 0) {
            printf("*               ");
        } else {
            printfs(16, IPFMT, ipfmt(rt->rt_gateway));
        }
        printfs(16, IPFMT, ipfmt(rt->rt_netmask));
        printf("%-7d", rt->rt_metric);
        printf("%s\n", rt->rt_dev->net_name);
    }
}
