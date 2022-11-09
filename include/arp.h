#ifndef __ARP_H
#define __ARP_H

#define ARP_CACHE_SIZE 20
#define ARP_FREE 1
#define ARP_PENDDING 2
#define ARP_RESOLVED 3

#define ARP_RETRY 4
#define ARP_TIMEOUT 600

extern void fake_ip(unsigned char *ip);
extern void fake_hw(unsigned char *mac);
extern void arp_reply(struct eth_hdr *hdr, int tap_fd);
extern void arp_handle(struct eth_hdr *hdr, int tap_fd);
static inline void arp_cache_lock(void);

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