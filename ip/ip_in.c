#include "lib.h"
#include "net.h"
#include "eth.h"
#include "icmp.h"
#include "ip.h"


unsigned short ip_checksum(struct ip_hdr *ip)
{
    return checksum((unsigned char *)ip, ip->ip_hlen*4);
}

void ip_recv_local(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    unsigned short ip_offlags = htons(ip->ip_offlags);
    unsigned short ip_sum = ip->ip_sum;
    ip->ip_sum = 0;
    if (ip_sum != ip_checksum(ip)){  //检查校验和是否正确
        perror("ip checksum error");
        goto free_pkg;
        return;
    }
    if (ip_offlags>>13 == 0x02)    //不分片
    {
        if (ip->ip_proto == 0x01)  //ICMP
        {
            icmp_in(pkg);
            return;
        }
    }
    // printf("ip_offlags: %o\n", ip_offlags>>13);
    // printf("ip_offlags: %o\n", ip_offlags & 0x1fff);
    // printf("ip->ip_proto: %d\n", ip->ip_proto);
free_pkg:
    free(pkg);
    return;
}

void ip_recv_route(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    if (check_ip_lo(ip->ip_dst)){
        ip_recv_local(pkg);
    }
}

inline int check_ip_lo(unsigned char *ip)
{
    if (ip[0] == 10 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1)
        return 1;
    else
        return 0;
}