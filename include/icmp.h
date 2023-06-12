#ifndef __ICMP_H__
#define __ICMP_H__

struct icmp 
{
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short icmp_cksum;
    union {
        struct {
            unsigned short id;
            unsigned short seq;
        }echo;
        unsigned int gw;
        unsigned int pad;
    }icmp_hun;
    unsigned char icmp_data[0];
}__attribute__((packed));

#define icmp_id      icmp_hun.echo.id
#define icmp_seq     icmp_hun.echo.seq
#define icmp_undata  icmp_hun.pad
#define icmp_gw      icmp_hun.gw

#define ICMP_HDR_SZ  sizeof(struct icmp)

#endif