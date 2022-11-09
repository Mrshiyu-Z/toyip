#ifndef __ETH_H
#define __ETH_H

struct eth_hdr{               //以太网帧头
    unsigned char dmac[6];    //目的mac地址
    unsigned char smac[6];    //源MAC地址
    unsigned short ethertype; //帧类型
    unsigned char data[];
}__attribute__((packed));

#define FAKE_MAC_ADDR "\x00\x34\x45\x67\x89\xab"

//ethertype 帧类型
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP 0x0800

//eth首部长度
#define ETH_HDR_LEN 14

//MAC地址长度
#define ETH_MAC_LEN 6

void cp_mac_lo(unsigned char *mac); //复制本地MAC地址

#endif