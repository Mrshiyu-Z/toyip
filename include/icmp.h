#ifndef __ICMP_H
#define __ICMP_H

extern void icmp_in(struct pkg_buf *pkg);
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