#ifndef __NET_H
#define __NET_H
#include "list.h"

struct pkg_buf
{
    struct list_head list;
    int pkg_len;
    unsigned short pkg_pro; //以太帧类型
    unsigned short pkg_type; //传输类型,localhost,其他接口,组播,广播
    unsigned char data[0];
}__attribute__((packed));

/* pkg_type */
#define LOCALHOST 0x0001 //本地
#define OTHERHOST 0x0002 //其他接口
#define MULTICAST 0x0003 //组播
#define BROADCAST 0x0004 //广播

#define MTU_SIZE 1500

extern void eth_init(void);    //初始化以太网套接字
extern int eth_recv(struct pkg_buf *pkg);  //接收以太网数据包
extern void eth_rx(void); 
extern void eth_in(void);
void eth_tx(struct pkg_buf *pkg);
void net_in(struct pkg_buf *pkg);
void net_out(struct pkg_buf *pkg);
extern struct pkg_buf *pkg_alloc(int size); //分配一个包

#endif