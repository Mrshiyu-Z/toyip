#ifndef __IP_H
#define __IP_H

#include "eth.h"

struct ip_hdr{
    /* 实际上ip_ver在ip_hlen前面,因为字节序问题,这里为了方便,这样排 */
    unsigned char ip_hlen:4;   
    unsigned char ip_ver:4;            //ip头长度和版本 8
    unsigned char ip_tos;              //服务类型 8
    unsigned short ip_len;             //总长度,data长度由这个长度-头部长度hlen*4
    unsigned short ip_id;              //标识,用于分片，同一个ID的分片属于同一个数据包
    unsigned short ip_offlags;         //偏移
    unsigned char ip_ttl;              //生存时间
    unsigned char ip_proto;            //上层协议
    unsigned short ip_sum;             //校验和
    unsigned char ip_src[4];           //源IP地址
    unsigned char ip_dst[4];           //目的IP地址
    unsigned char data[0];
}__attribute__((packed));

#define IP_ADDR_LEN 4    //IP地址长度
#define IP_VER_4 4       //ipv4版本号
#define IP_HDR_LEN 20    //IP头部长度
#define IP_TTL_ 64        //IP生存时间

#define IP_PROTO_ICMP 1  //ICMP协议号
#define IP_PROTO_TCP 6   //TCP协议号
#define IP_PROTO_UDP 17  //UDP协议号

#define ip_ver(ip) ((ip)->ip_ver)
#define ip_hlen(ip) ((ip)->ip_hlen << 2)
#define ip_dlen(ip) ((ip)->ip_len - ip_hlen(ip))
#define ip_data(ip) ((unsigned char *)(ip) + iphlen(ip))
#define ip_df(ip) ((htons((ip)->ip_offlags) & IP_FLAG_DF) >> 14)
#define ip_mf(ip) ((htons((ip)->ip_offlags) & IP_FLAG_MF) >> 13)   //0:最后一片,1:不是最后一片
#define ip_off(ip) ((htons((ip)->ip_offlags) & IP_FRAGOFF_MASK) * 8)
#define pkg_2_iphdr(pkg) ((struct ip_hdr *)(pkg->data + ETH_HDR_LEN))

//ip_fragoff 与下面的值相&之后的结果
#define IP_FLAG_DF 0x4000  //1表示不分片,0表示分片
#define IP_FLAG_MF 0x2000  //1表示后面还有分片,0表示这是最后一个分片
#define IP_FRAGOFF_MASK 0x1fff  //分片偏移掩码

extern void ip_recv_route(struct pkg_buf *pkg);
void ip_send_info(struct pkg_buf *pkg, unsigned char ip_tos,unsigned short ip_len, 
        unsigned char ip_proto, unsigned char ip_dst[4]);
extern unsigned short checksum(unsigned char *buf, int count);
extern void ip_set_checksum(struct ip_hdr *ip);
extern inline int check_ip_lo(unsigned char *ip);
extern inline void cp_ip_lo(unsigned char *ip);
extern void print_ip(struct ip_hdr *ip);

struct fragment {
    unsigned short frag_id;  //等同IP报文的ID,相同ID被视为同一个报文的分片
    unsigned char frag_src[4]; //等同IP报文的源IP地址
    unsigned char frag_dst[4]; //等同IP报文的目的IP地址
    unsigned char frag_proto;  //等同IP报文的上层协议
    unsigned char frag_hlen;   //等同IP报文的头部长度
    unsigned int frag_rec_size; //已经收到的分片大小
    unsigned int frag_size;  //等同IP报文的总长度(不包含IP报头)
    int frag_ttl;
    unsigned int frag_flags;  // 分片标记
    struct list_head frag_list;  //分片链表,连接不同IP报文的分片头节点
    struct list_head frag_pkg; //分片队列,连接同一个IP报文的分片
}__attribute__((packed));

//frag_ttl 取值
#define FRAG_TIME_OUT 60  //分片超时时间
//frag_flags 取值
#define FRAG_COMPLETE 0X00000001  //分片已经完整
#define FRAG_FIRST 0X00000002     //分片是第一个分片
#define FRAG_LAST 0X00000004      //分片是最后一个分片
#define FRAG_FL_IN 0x00000006     //分片列表的第一个分片和最后一个分片都已到达

extern void ip_frag_timer(int delay);
extern void ip_send_frag(struct pkg_buf *pkg);   //IP分片发送
extern struct pkg_buf *ip_reass(struct pkg_buf *pkg);   //接收IP分片
#endif