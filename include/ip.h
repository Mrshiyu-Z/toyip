#ifndef __IP_H__
#define __IP_H__

#include "netif.h"
#include "ether.h"
#include "list.h"

#define IP_ALEN   4                /* IP地址长度 */

#define IP_VERSION_4   4           /* IP协议版本号 */

#define IP_FRAG_RS     0x8000	   /* IP数据包的标志位: 0表示不分片,1表示分片 */
#define IP_FRAG_DF     0x4000	   /* IP数据包的标志位: 0表示可以分片,1表示不分片 */
#define IP_FRAG_MF     0x2000	   /* IP数据包的标志位: 0表示最后一个分片,1表示还有分片 */
#define IP_FRAG_OFF    0x1fff	   /* IP数据包的标志位: 分片偏移量 */
#define IP_FRAG_MASK   (IP_FRAG_OFF | IP_FRAG_MF)  /* IP数据包的标志位掩码 */

#define IP_P_IP  	0           /* IP协议类型 */
#define IP_P_ICMP   1           /* ICMP协议类型 */
#define IP_P_IGMP   2           /* IGMP协议类型 */
#define IP_P_TCP    6           /* TCP协议类型 */
#define IP_P_UDP    17          /* UDP协议类型 */
#define IP_P_OSPF	89          /* OSPF协议类型 */
#define IP_P_RAW	255         /* RAW协议类型 */
#define IP_P_MAX	256	        /* 最大协议类型 */

/*
	IP首部
	为了保证IP首部的长度为20字节,所以使用了__attribute__((packed))属性
	因为大小端问题,这里交换了ip_hlen和ip_ver的位置,方便使用
*/
struct ip
{
	unsigned char ip_hlen:4;	    /* IP首部长度 */
	unsigned char ip_ver:4;		    /* IP协议版本号 */
	unsigned char ip_tos;		    /* IP服务类型 */
	unsigned short ip_len;		    /* IP数据包长度 */
	unsigned short ip_id;		    /* IP数据包标识 */
	unsigned short ip_fragoff;		/* IP数据包的偏移量 */
	unsigned char ip_ttl;		    /* IP数据包的生存时间 */
	unsigned char ip_pro;	        /* IP数据包的协议类型 */
	unsigned short ip_sum;		    /* IP数据包的校验和 */
	unsigned int ip_src;		    /* IP数据包的源IP地址 */
	unsigned int ip_dst;		    /* IP数据包的目的IP地址 */
	unsigned char ip_data[0];	    /* IP数据包的数据 */
}__attribute__((packed));

#define IP_HDR_SZ   sizeof(struct ip)

/*
	为了方便,定义一些快速取ip首部字段的宏
*/
#define ipver(ip)      ((ip)->ip_ver)                                     // IP协议版本号
#define iphlen(ip)     ((ip)->ip_hlen << 2)                               // IP首部长度
#define ipdlen(ip)     ((ip)->ip_len - iphlen(ip))                        // IP数据包长度
#define ipndlen(nip)   (_ntohs((nip)->ip_len) - iphlen(nip))              // IP数据包长度(网络字节序)
#define ipdata(ip)     ((unsigned char *)(ip) + iphlen(ip))               // IP数据包数据
#define ipoff(ip)      (((ip)->ip_fragoff & IP_FRAG_OFF) * 8)             // IP数据包偏移量
#define pkb2ip(pkb)    ((struct ip *)((pkb)->pk_data + ETH_HRD_SZ))       // 从pkb中取出ip首部

#define IPFMT     "%d.%d.%d.%d"
#define ipfmt(ip)\
	(ip) & 0xff, ((ip) >> 8) & 0xff, ((ip) >> 16) & 0xff, ((ip) >> 24) & 0xff

static inline void ip_ntoh(struct ip *iphdr)
{
	iphdr->ip_len = _ntohs(iphdr->ip_len);
	iphdr->ip_id = _ntohs(iphdr->ip_id);
	iphdr->ip_fragoff = _ntohs(iphdr->ip_fragoff);
}
#define ip_hton(ip) ip_ntoh(ip)

/*
	IP分片
*/
struct ip_frag
{
	unsigned short frag_id;		  /* 分片标识,对应ip_id */
	unsigned int frag_src;		  /* 分片的源IP地址 */
	unsigned int frag_dst;		  /* 分片的目的IP地址 */
	unsigned short frag_pro;	  /* 分片的协议类型,对应ip_pro */
	unsigned int frag_hlen;		  /* 分片的IP首部长度 */
	unsigned int frag_rsize;	  /* 已经收到的分片的数据长度 */
	unsigned int frag_size;		  /* 所有分片的数据长度(不包含IP头部) */
	int frag_ttl;				  /* 分片的生存时间 */
	unsigned int frag_flags;	  /* 分片的标志位 */
	struct list_head frag_list;	  /* 分片链表 */
	struct list_head frag_pkb;    /* 分片的pkb链表 */
};

#define FRAG_COMPLETE   0x00000001  /* 分片已经接收完毕 */
#define FRAG_FIRST_IN	0x00000002  /* 分片是第一个到达的分片 */
#define FRAG_LAST_IN	0x00000004  /* 分片是最后一个到达的分片 */
#define FRAG_FL_IN      0x00000006  /* 分片已经重组完毕 */

#define FRAG_TIME       30 	        /* 分片重组的超时时间 */
#define frag_head_pkb(frag) \
	list_first_entry(&(frag)->frag_pkb, struct pkbuf, pk_list)
/* 
	判断IP是否为多播地址
	判定方法:
		判定最高位是否为1110
*/
#define MULTICAST(netip) ((0x000000f0 & (netip)) == 0x000000e0)

/*
	判断IP是否为广播地址
	判定方法:
		判定最高位是否为1或0
*/
#define BROADCAST(netip) (((0xff000000 & (netip)) == 0xff000000) ||\
				((0xff000000 & (netip)) == 0x00000000))

/*
	查看两个IP是否是同一个子网(equivalent subnet)
	@mask: 子网掩码
	@ip1: 第一个IP
	@ip2: 第二个IP
*/
static inline int equsubnet(unsigned int mask, unsigned int ip1, unsigned int ip2)
{
	return ((mask & ip1) == (mask & ip2));
}

extern struct pkbuf *ip_reass(struct pkbuf *pkb);
extern void ip_send_dev(struct netdev *dev, struct pkbuf *pkb);
extern void ip_send_out(struct pkbuf *pkb);
extern void ip_send_frag(struct netdev *dev, struct pkbuf *pkb);
extern void ip_in(struct netdev *dev, struct pkbuf *pkb);
extern void ip_send_info(struct pkbuf *pkb, unsigned char tos, unsigned short len,
            unsigned char ttl, unsigned char ip_pro, unsigned int dst);
extern void ip_timer(int delay);

#endif