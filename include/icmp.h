#ifndef __ICMP_H
#define __ICMP_H

#include "eth.h"

extern void icmp_reply(struct eth_hdr *hdr, int tap_fd);
extern unsigned short checksum(unsigned char *buf, int count);

struct icmp_hdr{
    unsigned char type;
    unsigned char code;
    unsigned short csum;
    unsigned char data[];
}__attribute__((packed));

struct icmp_v4_echo{
    unsigned short id;
    unsigned short seq;
    unsigned char data[];
}__attribute__((packed));

#endif