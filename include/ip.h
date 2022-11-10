#ifndef __IP_H
#define __IP_H

#define IP_ADDR_LEN 4

struct ip_hdr{
    unsigned char ip_ver:4;
    unsigned char ip_hlen:4;           //ip头长度和版本 8
    unsigned char ip_tos;              //服务类型 8
    unsigned short ip_len;             //总长度 16
    unsigned short ip_id;              //标识 16
    unsigned short ip_offlags;         //偏移
    unsigned char ip_ttl;              //生存时间
    unsigned char ip_p;                //协议
    unsigned short ip_sum;             //校验和
    unsigned char ip_src[4];           //源IP地址
    unsigned char ip_dst[4];           //目的IP地址
    unsigned char payload[0];
}__attribute__((packed));

static inline void cp_ip_lo(unsigned char *ip)
{
    ip[0] = 10;ip[1] = 0;
    ip[2] = 0;ip[3] = 1;
}

static inline int check_ip_lo(unsigned char *ip)
{
    if (ip[0] == 10 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1){
        return 1;
    }
    else
        return 0;
}

#endif