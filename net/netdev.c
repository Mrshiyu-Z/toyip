#include "netif.h"
#include "ether.h"
#include "lib.h"
#include "list.h"
#include "netcfg.h"

/* 本地网络设备链表 */
struct list_head netdev_list;

extern void veth_init(void);
extern void veth_exit(void);
extern void veth_epoll(void);

extern void loop_init(void);
extern void loop_exit(void);

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

/*
    释放dev设备
    @dev: 要释放dev设备
*/
void netdev_free(struct netdev *dev)
{
    if (dev->net_ops && dev->net_ops->exit)
        dev->net_ops->exit(dev);
    list_del(&dev->net_list);
    free(dev);
}

/*
    虚拟网络设备的中断处理函数
*/
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
    loop_init();
    veth_init();
}

/*
    发送网络数据包
    @dev:   网络设备
    @pkb:   待发送的网络数据包
    @len:   待发送的网络数据包的长度
    @proto: 待发送的网络数据包的协议类型(指在以太网层的协议类型)
    @dst:   待发送的网络数据包的目的MAC地址
*/  
void netdev_tx(struct netdev *dev, struct pkbuf *pkb, int len,
        unsigned short proto, unsigned char *dst)
{
    struct ether *ehdr = (struct ether *)pkb->pk_data;
    ehdr->eth_pro = _htons(proto);
    hwcpy(ehdr->eth_dst, dst);
    hwcpy(ehdr->eth_src, dev->net_hwaddr);

    l2dbg(MACFMT " -> " MACFMT "(%s)",
            macfmt(ehdr->eth_src),
            macfmt(ehdr->eth_dst),
            ethpro(proto));
    pkb->pk_len = len + ETH_HDR_SZ;
    dev->net_ops->xmit(dev,pkb);
    free_pkb(pkb);
}

int local_address(unsigned int addr)
{
    struct netdev *dev;
    if (!addr) {
        return 1;
    }
    if (LOCALNET(loop) == (loop->net_mask & addr)) {
        return 1;
    }
    list_for_each_entry(dev, &netdev_list, net_list) {
        if (dev->net_ipaddr == addr) {
            return 1;
        }
    }
	return 0;
}
