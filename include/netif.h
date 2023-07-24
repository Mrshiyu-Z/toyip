#ifndef __NETIF_H__
#define __NETIF_H__

#define NETDEV_MAC_LEN 6
#define NETDEV_NAME_LEN 16

#include "compile.h"
#include "list.h"

struct pkbuf;
struct netdev;

struct netstats {                 // 网络设备的统计信息
    unsigned int rx_packets;      // 接收包的数量
    unsigned int tx_packets;      // 发送包的数量
    unsigned int rx_bytes;        // 接收字节的数量
    unsigned int tx_bytes;        // 发送字节的数量
    unsigned int rx_errors;       // 接收错误的数量
    unsigned int tx_errors;       // 发送错误的数量
};

struct netdev_ops {                                  // 网络设备操作函数
    int (*xmit)(struct netdev *, struct pkbuf *);    // 发送数据包
    int (*init)(struct netdev *);                    // 初始化网络设备
    void (*exit)(struct netdev *);                   // 退出网络设备
};

struct netdev {                                 // 网络设备结构
    int net_mtu;                                // 网络设备的最大传输单元
    unsigned int net_ipaddr;                    // 网络设备的IP地址
    unsigned int net_mask;                      // 网络设备的子网掩码
    unsigned char net_hwaddr[NETDEV_MAC_LEN];   // 网络设备的MAC地址
    unsigned char net_name[NETDEV_NAME_LEN];    // 网络设备的名称
    struct netdev_ops *net_ops;                 // 网络设备的操作函数
    struct netstats net_stats;                  // 网络设备的统计信息
    struct list_head net_list;                  // 用于将网络设备添加到链表中
};
#define LOCALNET(dev) ((dev)->net_ipaddr & (dev)->net_mask)

struct tapdev {             // tap设备结构
    struct netdev dev;      // 网络设备结构
    int fd;                 // tap设备的文件描述符
};

struct pkbuf {                          // 网络包结构
    struct list_head pk_list;           // 用于将网络包添加到链表中
    unsigned short pk_protocol;         // 网络包的协议类型
    unsigned short pk_type;             // 网络包的类型
    int pk_len;                         // 网络包的长度
    int pk_refcnt;                      // 网络包的引用计数
    struct netdev *pk_indev;            // 网络包的入口设备
    struct rtentry *pk_rtdst;           // 网络包的路由
    // struct sock *pk_sk;
    unsigned char pk_data[0];           // 网络包的数据
}__attribute__((packed));

/*
    定义数据包硬件地址类型
*/
#define PKT_NONE 0
#define PKT_LOCALHOST	1
#define PKT_OTHERHOST	2
#define PKT_MULTICAST	3
#define PKT_BROADCAST	4

/*
   网络字节序转换为主机字节序 
*/
static _inline unsigned short _htons(unsigned short host)
{
    return (host >> 8) | ((host << 8) & 0xff00);
}

#define _ntohs(net) _htons(net)

static _inline unsigned int _htonl(unsigned int host)
{
    return ((host & 0x000000ff) << 24) |
        ((host & 0x0000ff00) << 8) |
        ((host & 0x00ff0000) >> 8) |
        ((host & 0xff000000) >> 24);
}
#define _ntohl(net) _htonl(net)

extern struct tapdev *tap;
extern struct netdev *veth;
extern struct netdev *loop;

extern void netdev_init(void);
extern struct netdev *netdev_alloc(char *devstr, struct netdev_ops *netops);
extern void netdev_free(struct netdev *dev);
extern void netdev_interrupt(void);
void netdev_tx(struct netdev *dev, struct pkbuf *pkb, int len,
        unsigned short proto, unsigned char *dst);

extern void net_in(struct netdev *dev, struct pkbuf *pkb);
extern void net_timer(void);

extern struct pkbuf *alloc_pkb(int size);
extern struct pkbuf *alloc_netdev_pkb(struct netdev *nd);
extern void pkb_trim(struct pkbuf *pkb, int len);
extern void free_pkb(struct pkbuf *pkb);
extern void get_pkb(struct pkbuf *pkb);

extern void netdev_init(void);
#endif