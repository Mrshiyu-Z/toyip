#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/if_tun.h>

#include "netif.h"
#include "ether.h"
#include "lib.h"
#include "ip.h"
#include "tap.h"

static int skfd;

/*
    申请一个tap设备
    @dev:   tap设备的名称
*/
int alloc_tap(char *dev)
{
    struct ifreq ifr = {0};
    int tap_fd;

    tap_fd = open(TAP_DEV, O_RDWR);
    if (tap_fd < 0) {
        perror("open");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    /*
        创建一个tap设备
        如果已经创建了,就只绑定到这个设备上
    */
    if (ioctl(tap_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl");
        close(tap_fd);
        return -1;
    }

    return tap_fd;
}

/*
    获取tap设备的名称
    @tap_fd:    tap设备的文件描述符
    @name:      tap设备的名称
*/
void getname_tap(int tap_fd, unsigned char *name)
{
    struct ifreq ifr = {0};
    if (ioctl(tap_fd, TUNGETIFF, (void *)&ifr) < 0)
        perrx("ioctl SIOCGIFHWADDR");
    strcpy((char *)name, ifr.ifr_name);
    dbg("net device: %s", name);
}

/*
    获取tap设备的MTU
    @name:  tap设备的名称
    @mtu:   tap设备的MTU
*/
void getmtu_tap(unsigned char *name, int *mtu)
{
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, (char *)name);
    if (ioctl(skfd, SIOCGIFMTU, (void *)&ifr) < 0)
    {
        close(skfd);
        perrx("ioctl SIOCGIFHWADDR");
    }
    *mtu = ifr.ifr_mtu;
    dbg("mtu: %d", ifr.ifr_mtu);
}

/*
    获取tap设备的MAC地址
    @tap_fd:    tap设备的文件描述符
    @ha:        tap设备的MAC地址
*/
void gethwaddr_tap(int tap_fd, unsigned char *ha)
{
    struct ifreq ifr;
    memset(&ifr, 0x0, sizeof(ifr));
    if (ioctl(tap_fd, SIOCGIFHWADDR, (void *)&ifr) < 0)
        perrx("ioctl SIOCGIFHWADDR")
    hwcpy(ha, ifr.ifr_hwaddr.sa_data);
    dbg("hwaddr: %02x:%02x:%02x:%02x:%02x:%02x",
        ha[0], ha[1], ha[2], ha[3], ha[4], ha[5]);
}

/*
    获取tap设备的IP地址
    @name:      tap设备的名称
    @ipaddr:    tap设备的IP地址
*/
void getipaddr_tap(unsigned char *name, unsigned int *ipaddr)
{
    struct ifreq ifr;
    struct sockaddr_in *saddr;
    memset(&ifr, 0x0, sizeof(ifr));
    strcpy(ifr.ifr_name, (char *)name);
    if (ioctl(skfd, SIOCGIFADDR, (void *)&ifr) < 0)
    {
        close(skfd);
        perrx("ioctl SIOCGIFADDR");
    }
    saddr = (struct sockaddr_in *)&ifr.ifr_addr;
    *ipaddr = saddr->sin_addr.s_addr;
    dbg("get IPaddr: "IPFMT, ipfmt(*ipaddr));
}

/*
    设置tap设备启动标志
    @name:      tap设备的名称
*/
void setup_tap(unsigned char *name)
{
    setflags_tap(name, IFF_UP | IFF_RUNNING, 1);
    dbg("ifup %s", name);
}

/*
    设置tap设备关闭标志
    @name:      tap设备的名称
*/
void setdown_tap(unsigned char *name)
{
    setflags_tap(name, IFF_UP | IFF_RUNNING, 0);
    dbg("ifdown %s", name);
}

/*
    将tap设备永久化
    @fd:    tap设备的文件描述符
*/
int setperist_tap(int fd)
{
    if (!errno && ioctl(fd, TUNSETPERSIST, 1) < 0) {
        perror("ioctl TUNSETPERSIST");
        return -1;
    }
    return 0;
}

/*
    设置tap设备的IP地址
    @name:      tap设备的名称
    @ipaddr:    tap设备的IP地址
*/
void setipaddr_tap(unsigned char *name, unsigned int ipaddr)
{
    struct ifreq ifr;
    struct sockaddr_in *saddr;
    memset(&ifr, 0x0, sizeof(ifr));
    strcpy(ifr.ifr_name, (char *)name);
    saddr = (struct sockaddr_int *)&ifr.ifr_addr;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = ipaddr;
    if (ioctl(skfd, SIOCSIFADDR, (void *)&ifr) < 0)
    {
        close(skfd);
        perrx("ioctl SIOCSIFADDR");
    }
    dbg("set IPaddr: "IPFMT, ipfmt(ipaddr));
}

/*
    设置tap设备的子网掩码
    @name:      tap设备的名称
    @netmask:   tap设备的子网掩码
*/
void setnetmask_tap(unsigned char *name, unsigned int netmask)
{
    struct ifreq ifr;
    struct sockaddr_in *saddr;
    memset(&ifr, 0x0, sizeof(ifr));
	strcpy(ifr.ifr_name, (char *)name);
	saddr = (struct sockaddr_in *)&ifr.ifr_netmask;
	saddr->sin_family = AF_INET;
	saddr->sin_addr.s_addr = netmask;
	if (ioctl(skfd, SIOCSIFNETMASK, (void *)&ifr) < 0) {
		close(skfd);
		perrx("socket SIOCSIFNETMASK");
	}
	dbg("set Netmask: "IPFMT, ipfmt(netmask));   
}

/*
    设置tap设备的标志位
    @name:      tap设备的名称
    @flags:     tap设备的标志位
    @set:       是否设置标志位
    标志位举例(包括但不仅限于):
        IFF_UP:     接口是否启动
        IFF_BROADCAST:  广播地址是否有效
        IFF_DEBUG:  调试标志
        IFF_LOOPBACK:   是否是环回接口
        IFF_POINTOPOINT:    是否是点对点接口
        IFF_RUNNING:    接口是否正在运行
        IFF_NOARP:  是否不使用ARP协议
*/
void setflags_tap(unsigned char *name, unsigned short flags, int set)
{
    struct ifreq ifr;
    memset(&ifr, 0x0, sizeof(ifr));
    if (ioctl(skfd, SIOCGIFFLAGS, (void *)&ifr) < 0) {
		close(skfd);
		perrx("socket SIOCGIFFLAGS");
	}
	if (set)
		ifr.ifr_flags |= flags;
	else
		ifr.ifr_flags &= ~flags & 0xffff;
	if (ioctl(skfd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
		close(skfd);
		perrx("socket SIOCGIFFLAGS");
	}
}

void delete_tap(int tapfd)
{
	if (ioctl(tapfd, TUNSETPERSIST, 0) < 0)
		return;
	close(tapfd); 
}

/*
    设置tap设备的套接字
*/
void set_tap(void)
{
    skfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (skfd < 0)
        perrx("socket PF_INET");
}

/*
    关闭tap设备的套接字
*/
void unset_tap(void)
{
    close(skfd);
}