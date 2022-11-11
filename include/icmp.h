#ifndef __ICMP_H
#define __ICMP_H

#define ICMP_HDR_LEN 8
#define ICMP_ECHO 8
#define ICMP_ECHO_REPLY 0

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

extern void icmp_in(struct pkg_buf *pkg);
extern void icmp_echo(unsigned char *ip);

#endif