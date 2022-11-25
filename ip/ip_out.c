#include "lib.h"
#include "list.h"
#include "net.h"
#include "eth.h"
#include "ip.h"
#include "arp.h"

void print_ip(struct ip_hdr *ip)
{
    printf("ip_v: %d\n", ip_ver(ip));
    printf("ip_hlen: %d\n", ip_hlen(ip));
    printf("ip_tos: %d\n", ip->ip_tos);
    printf("ip_len: %d\n", htons(ip->ip_len));
    printf("ip_id: %d\n", htons(ip->ip_id));
    printf("ip_df: %x\n", ip_df(ip));
    printf("ip_mf: %x\n", ip_mf(ip));
    printf("ip_off: %x\n", ip_off(ip));
    printf("ip_ttl: %d\n", ip->ip_ttl);
    printf("ip_proto: %d\n", ip->ip_proto);
    printf("ip_csum: %d\n", ip->ip_sum);
    printf("ip_src: %d.%d.%d.%d\n", ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);
    printf("ip_dst: %d.%d.%d.%d\n", ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);
    printf("-------------------------------\n");
}

inline void cp_ip_lo(unsigned char *ip)
{
    ip[0] = 10;ip[1] = 0;
    ip[2] = 0;ip[3] = 1;
}

void ip_set_checksum(struct ip_hdr *ip)
{
    ip->ip_sum = 0;
    ip->ip_sum = checksum((unsigned char *)ip, ip->ip_hlen*4);
}

void ip_send_dev(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)(eth->data);
    struct arp_cache *ac = arp_cache_lookup_resolved(ip->ip_dst);
    if (ac == NULL)
    {
        ac = arp_alloc();
        if (ac == NULL)
        {
            perror("arp_alloc error");
            free(pkg);
            return;
        }
        memcpy(ac->ip, ip->ip_dst, 4);
        list_add_node(&pkg->list, &ac->list);   //将数据包加入到ARP缓存队列中
        ac->state = ARP_PENDDING;
        arp_send_request(ac);
    }else{
        net_out(pkg, ac->mac, ETH_TYPE_IP);
    }
}

void ip_send_out(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    
    pkg->pkg_pro = ETH_TYPE_IP;
    ip_set_checksum(ip);
    if(htons(ip->ip_len) > MTU_SIZE)
    {
        ip_send_frag(pkg);
    }else
    {
        ip_send_dev(pkg);
    }
}

unsigned short ip_id = 0;
void ip_send_info(struct pkg_buf *pkg, unsigned char ip_tos,unsigned short ip_len, 
        unsigned char ip_proto, unsigned char *ip_dst)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    ip->ip_ver = IP_VER_4;
    ip->ip_hlen = IP_HDR_LEN/4;
    ip->ip_tos = ip_tos;
    ip->ip_len = htons(ip_len);
    ip->ip_id = htons(++ip_id);
    ip->ip_offlags = htons(0x4000);     //不分片
    ip->ip_ttl = IP_TTL_;
    ip->ip_proto = ip_proto;
    memcpy(ip->ip_dst, ip_dst, 4); 
    cp_ip_lo(ip->ip_src);        //源IP地址设置为本机IP地址
    ip_send_out(pkg);
}