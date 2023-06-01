#ifndef __SOCK_H__
#define __SOCK_H__

#include "netif.h"
#include "list.h"

struct sock_addr {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned short src_port;
    unsigned short dst_port;
}__attribute__((packed));

struct sock;

struct sock {
    unsigned char protocol;    // 协议类型
    struct sock_addr sk_addr;  // 源地址和目的地址和端口
    struct socket *sock;
}

#endif