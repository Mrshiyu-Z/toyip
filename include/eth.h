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

void cp_mac_lo(unsigned char *mac)
{
    mac[0] = 0x00;mac[1] = 0x34;
    mac[2] = 0x45;mac[3] = 0x67;
    mac[4] = 0x89;mac[5] = 0xab;
}

#endif