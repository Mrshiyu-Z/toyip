#include "netif.h"
#include "lib.h"
#include "list.h"

/* 本地网络设备链表 */
struct list_head netdev_list;

extern void veth_init(void);
extern void veth_exit(void);
extern void veth_epoll(void);

/*
    分配并初始化网络设备
    @devstr:    网络设备的名称
    @netops:    网络设备的操作函数
*/
struct netdev *netdev_alloc(char *devstr, struct netdev_ops *netops)
{
    struct netdev *dev = NULL;
    /* 为网络设备分配内存 */
    dev = xzalloc(sizeof(*dev));
    /* 将网络设备添加到链表中(尾插) */
    list_add_tail(&dev->net_list, &netdev_list);
    /* 设置网络设备的名称 */
    dev->net_name[NETDEV_NAME_LEN - 1] = '\0';
    strncpy((char *)dev->net_name, devstr, NETDEV_NAME_LEN - 1);
    /* 设置网络设备的操作函数 */
    dev->net_ops = netops;
    /* 如果netops不为空且具有init函数,则调用网络设备的初始化函数 */
    if (netops && netops->init)
        netops->init(dev);
    return dev;
}

void netdev_interrupt(void)
{
    veth_epoll();
}

/*
    初始化网络设备
*/
void netdev_init(void)
{
    list_init(&netdev_list);
    veth_init();
}