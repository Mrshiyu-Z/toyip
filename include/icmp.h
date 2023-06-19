#ifndef __ICMP_H__
#define __ICMP_H__

#include "netif.h"
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
#define ip2icmp(ip)  ((struct icmp *)ipdata(ip))

/* icmp type 字段取值范围 */
#define ICMP_T_ECHOREPLY      0   // 回显应答
#define ICMP_T_DUMMY_1        1   // 保留
#define ICMP_T_DUMMY_2        2   // 保留
#define ICMP_T_UNREACH        3   // 目标不可达
#define ICMP_T_SOURCEQUENCH   4   // 源抑制
#define ICMP_T_REDIRECT       5   // 重定向
#define ICMP_T_DUMMY_6        6   // 保留
#define ICMP_T_DUMMY_7        7   // 保留
#define ICMP_T_ECHO           8   // 请求
#define ICMP_T_ROUTERADVERT   9   // 路由器通告
#define ICMP_T_ROUTERSOLICIT  10  // 路由器请求
#define ICMP_T_TIMXCEED       11  // 超时
#define ICMP_T_PARAMPROB      12  // 参数问题
#define ICMP_T_TSTAMP         13  // 时间戳请求
#define ICMP_T_TSTAMPREPLY    14  // 时间戳应答
#define ICMP_T_IREQ           15  // 信息请求
#define ICMP_T_IREQREPLY      16  // 信息应答
#define ICMP_T_AMREQ          17  // 地址掩码请求
#define ICMP_T_AMREQREPLY     18  // 地址掩码应答
#define ICMP_T_MAXNUM         18  // 最大值

#define ICMP_REDIRECT_NET     0   // 网络重定向
#define ICMP_REDIRECT_HOST    1   // 主机重定向
#define ICMP_REDIRECT_TOSNET  2   // 服务类型和网络重定向
#define ICMP_REDIRECT_TOSHOST 3   // 服务类型和主机重定向

#define ICMP_EXC_TTL		0
#define ICMP_EXC_FRAGTIME	1

struct icmp_desc {
    int error;
    char *info;
    void (*handler)(struct icmp_desc *, struct pkbuf *);
};

#define ICMP_DESC_DUMMY_ENTRY \
{ \
    .error = 1, \
    .info = NULL, \
    .handler = icmp_drop_reply, \
}

#define icmp_type_error(type) icmp_table[type].error
#define icmp_error(icmp_hdr) icmp_type_error((icmp_hdr)->icmp_type)

struct pkbuf;
extern void icmp_send(unsigned char type, unsigned char code,
        unsigned int data, struct pkbuf *pkb_in);
extern void icmp_in(struct pkbuf *pkb);

#endif