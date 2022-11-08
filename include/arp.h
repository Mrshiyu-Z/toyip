#ifndef __ARP_H
#define __ARP_H

#include "eth.h"

extern void fake_ip(unsigned char *ip);
extern void fake_hw(unsigned char *mac);
extern void arp_reply(struct eth_hdr *hdr, int tap_fd);

struct arp_hdr{            //arp头
    unsigned short htype;  //链路层类型 1以太网
    unsigned short ptype;  //网络层类型,IPV4 0X0800
    unsigned char hlen;    //链路层地址长度
    unsigned char plen;    //网络层地址长度
    unsigned short opcode; //操作码 1请求 2应答
    unsigned char smac[6]; //源MAC地址
    unsigned char sip[4];  //源IP地址
    unsigned char dmac[6]; //目的MAC地址
    unsigned char dip[4];  //目的IP地址
}__attribute__((packed));

#endif