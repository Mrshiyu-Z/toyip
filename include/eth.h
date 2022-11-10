#ifndef __ETH_H
#define __ETH_H

struct eth_hdr{               //以太网帧头
    unsigned char dmac[6];    //目的mac地址
    unsigned char smac[6];    //源MAC地址
    unsigned short ethertype; //帧类型
    unsigned char data[];
}__attribute__((packed));

//ethertype 帧类型
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP 0x0800

//eth首部长度
#define ETH_HDR_LEN 14

//MAC地址长度
#define ETH_MAC_LEN 6

void eth_out(struct pkg_buf *pkg);
inline void cp_mac_lo(unsigned char *mac);

#endif