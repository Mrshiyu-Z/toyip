#include "lib.h"
#include "net.h"
#include "eth.h"
#include "icmp.h"
#include "ip.h"

void ip_recv_local(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    //unsigned short ip_offlags = htons(ip->ip_offlags);
    unsigned short ip_sum = ip->ip_sum;
    // struct icmp_hdr *icmp = (struct icmp_hdr *)ip->data;
    ip->ip_sum = 0;
    if (ip_sum != ip_checksum(ip)){  //检查校验和是否正确
        perror("ip checksum error");
        free_pkg(pkg);
        return;
    }
    /* 处理分片 */
    if (htons(ip->ip_offlags) & (IP_FRAGOFF_MASK | IP_FLAG_MF)) //判断是否分片,根据是否存在偏移量或MF位
    {
        if (htons(ip->ip_offlags) & IP_FLAG_DF)
        {
            //如果DF位为1,表示不分片,则丢弃
            perror("ip recv local: DF bit set");
            free_pkg(pkg);
            return;
        }
        pkg = ip_reass(pkg);
        if(!pkg){
            return;
        }
        ip = pkg_2_iphdr(pkg);
    }
    switch (ip->ip_proto)
    {
        case IP_PROTO_ICMP:
            icmp_in(pkg);
            break;
        case IP_PROTO_TCP:
            break;
        case IP_PROTO_UDP:
            break;
        default:
            free(pkg);
            break;
    }
}

void ip_recv_route(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    if (check_ip_lo(ip->ip_dst)){
        ip_recv_local(pkg);
    }else
    {
        printf("dst not is local\n");
        free_pkg(pkg);
    }
    
}

inline int check_ip_lo(unsigned char *ip)
{
    if (ip[0] == 10 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1)
        return 1;
    else
        return 0;
}