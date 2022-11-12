#ifndef __IP_H
#define __IP_H

#define IP_ADDR_LEN 4    //IP地址长度
#define IP_VER_4 4       //ipv4版本号
#define IP_HDR_LEN 20    //IP头部长度
#define IP_TTL_ 64        //IP生存时间

#define IP_PROTO_ICMP 1  //ICMP协议号
#define IP_PROTO_TCP 6   //TCP协议号
#define IP_PROTO_UDP 17  //UDP协议号

struct ip_hdr{
    // unsigned char ip;
    unsigned char ip_hlen:4;   
    unsigned char ip_ver:4;            //ip头长度和版本 8
    unsigned char ip_tos;              //服务类型 8
    unsigned short ip_len;             //总长度 16
    unsigned short ip_id;              //标识 16
    unsigned short ip_offlags;         //偏移
    unsigned char ip_ttl;              //生存时间
    unsigned char ip_proto;            //上层协议
    unsigned short ip_sum;             //校验和
    unsigned char ip_src[4];           //源IP地址
    unsigned char ip_dst[4];           //目的IP地址
    unsigned char data[0];
}__attribute__((packed));

extern void ip_recv_route(struct pkg_buf *pkg);
void ip_send_info(struct pkg_buf *pkg, unsigned char ip_tos,unsigned short ip_len, 
        unsigned char ip_proto, unsigned char ip_dst[4]);
extern unsigned short checksum(unsigned char *buf, int count);
extern inline int check_ip_lo(unsigned char *ip);
extern inline void cp_ip_lo(unsigned char *ip);
extern void print_ip(struct ip_hdr *ip);

#endif