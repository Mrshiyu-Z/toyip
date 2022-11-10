#ifndef __ARP_H
#define __ARP_H

#include "list.h"

#define ARP_CACHE_SIZE 20 //ARP缓存个数
#define ARP_FREE 1        //ARP缓存空闲
#define ARP_PENDDING 2    //ARP缓存等待
#define ARP_RESOLVED 3    //ARP缓存已解析

#define ARP_RETRY 4       //ARP重试次数
#define ARP_TIMEOUT 600   //ARP超时时间

#define ARP_ETH_TYPE 1    //ARP以太网类型,1表示以太网

#define ARP_REQ 1         //ARP请求
#define ARP_REP 2         //ARP应答

#define ARP_HDR_LEN 28    //ARP头部长度

void arp_in(struct pkg_buf *pkg);   //ARP输入
void arp_recv(struct pkg_buf *pkg); //ARP接收
void arp_reply(struct pkg_buf *pkg); //ARP应答

struct arp_hdr{
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

struct arp_cache{
    struct list_head list;
    unsigned int state;     //状态：FREE(已超时)PENDING(已发送请求,但未应答)RESOLVED(已应答)
    int retry;              //重试次数
    int ttl;                //生存时间
    unsigned char ip[4];    //IP地址
    unsigned char mac[6];   //MAC地址
};

#endif