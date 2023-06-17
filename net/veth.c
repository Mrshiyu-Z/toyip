#include "netif.h"
#include "ether.h"
#include "ip.h"
#include "lib.h"
#include "list.h"
#include "netcfg.h"
#include "tap.h"

struct tapdev *tap;
struct netdev *veth;

/*
    初始化tap设备
*/
static int tap_dev_init(void)
{
    tap = xmalloc(sizeof(*tap));                              // 申请tap设备结构体
    tap->fd = alloc_tap("tap0");                              // 申请tap设备
    if (tap->fd < 0)
        goto free_tap;
    if (setperist_tap(tap->fd) < 0)
        goto close_tap;
    set_tap();                                                // 设置tap设备
    getname_tap(tap->fd, tap->dev.net_name);                  // 获取tap设备的名称
    getmtu_tap(tap->dev.net_name, &tap->dev.net_mtu);         // 获取tap设备的MTU
    gethwaddr_tap(tap->fd, tap->dev.net_hwaddr);              // 获取tap设备的MAC地址
    setipaddr_tap(tap->dev.net_name, FAKE_TAP_ADDR);          // 设置tap设备的IP地址
    getipaddr_tap(tap->dev.net_name, &tap->dev.net_ipaddr);   // 获取tap设备的IP地址
    setnetmask_tap(tap->dev.net_name, FAKE_TAP_NETMASK);      // 设置tap设备的子网掩码
    setup_tap(tap->dev.net_name);                             // 设置tap设备的UP状态
    unset_tap();                                              // 关闭tap设备
    list_init(&tap->dev.net_list);                            // 初始化tap设备的链表
    return 0;
close_tap:
    close(tap->fd);
free_tap:
    free(tap);
    return -1;
}

/*
    初始化虚拟网卡
    @dev:   虚拟网卡的结构体
*/
static int veth_dev_init(struct netdev *dev)
{
    if (tap_dev_init() < 0)
        perrx("Cannot init tap device");
    dev->net_mtu = tap->dev.net_mtu;
    dev->net_ipaddr = FAKE_IPADDR;
    dev->net_mask = FAKE_TAP_NETMASK;
    hwcpy(dev->net_hwaddr, FAKE_HW_ADDR);
    dbg("%s ip address: " IPFMT, dev->net_name, ipfmt(dev->net_ipaddr));
    dbg("%s hw address: " MACFMT, dev->net_name, macfmt(dev->net_hwaddr));
    return 0;
}

/*
    删除tap设备
    @tap_fd:    tap设备的文件描述符
*/
static void veth_dev_exit(struct netdev *dev)
{
	if (dev != veth)
		perrx("Net Device Error");
	delete_tap(tap->fd);
}

/*
    发送数据包
    @dev:   虚拟网卡的结构体
    @pkb:   数据包
*/
static int veth_xmit(struct netdev *dev, struct pkbuf *pkb)
{
    int l = 0;
    l = write(tap->fd, pkb->pk_data, pkb->pk_len);
    if (l != pkb->pk_len)
    {
        devdbg("write net dev");
        dev->net_stats.tx_errors++;
    } else {
        dev->net_stats.tx_packets++;
        dev->net_stats.tx_bytes += l;
        devdbg("write net dev size: %d\n", l);
    }
    return l;
}

/*
    虚拟网卡的操作函数
*/
static struct netdev_ops veth_ops = {
    .init = veth_dev_init,
    .exit = veth_dev_exit,
    .xmit = veth_xmit,
};

/*
    从虚拟网卡接收数据包
    @pkb:   数据包
*/
static int veth_recv(struct pkbuf *pkb)
{
    int l;
    l = read(tap->fd, pkb->pk_data, pkb->pk_len);
    if (l <= 0){
        devdbg("veth read net dev");
        veth->net_stats.rx_errors++;
    } else {
        devdbg("veth read net dev size: %d\n", l);
        veth->net_stats.rx_packets++;
        veth->net_stats.rx_bytes += l;
        pkb->pk_len = l;
    }
    return l;
}

/*
    处理虚拟网卡的接收事件
*/
void veth_rx(void)
{
    struct pkbuf *pkb = alloc_netdev_pkb(veth);
    if (veth_recv(pkb) > 0)
        net_in(veth, pkb);
    else
        free_pkb(pkb);
}

/*
    虚拟网卡的epoll
*/
void veth_epoll(void)
{
    int epoll_fd = epoll_create(1);
    if (epoll_fd < 0)
        perrx("epoll_create");
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = tap->fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tap->fd, &ev) < 0)
        perrx("epoll_ctl");
    struct epoll_event event;
    while(1)
    {
        int n = epoll_wait(epoll_fd, &event, 1, -1);
        if (n < 0)
            perrx("epoll_wait");
        if (event.events & EPOLLIN)
            veth_rx();
    }
}

void veth_init(void)
{
    veth = netdev_alloc("veth", &veth_ops);
}

void veth_exut(void)
{
    netdev_free(veth);
}