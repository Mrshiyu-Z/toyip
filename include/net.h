#ifndef __NET_H
#define __NET_H
#include "list.h"

struct pkg_buf
{
    struct list_head list;
    unsigned short pkg_pro; //以太帧类型
    unsigned short pkg_type; //传输类型,localhost,其他接口,组播,广播
    int pkg_len;
    unsigned char data[0];
}__attribute__((packed));

/* pkg_type */
#define LOCALHOST 0x0001 //本地
#define OTHERHOST 0x0002 //其他接口
#define MULTICAST 0x0003 //组播
#define BROADCAST 0x0004 //广播

#define MTU_SIZE 1500

extern void net_init(void);
extern void net_rx(void);
extern void net_in(void);
extern struct pkg_buf *pkg_alloc(int size); //分配一个包

#endif