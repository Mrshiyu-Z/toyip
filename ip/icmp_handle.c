#include "ip.h"
#include "lib.h"
#include "arp.h"
#include "icmp.h"

#define DF 0x02
#define MF 0x01

// void icmp_reply(struct eth_hdr *hdr, int tap_fd)
// {
//     struct ip_hdr *ip_p = (struct ip_hdr *)hdr->data;
//     struct icmp_hdr *icmp_p = (struct icmp_hdr *)ip_p->payload;
//     printf("ICMP request: from %d.%d.%d.%d to %d.%d.%d.%d\n", ip_p->ip_src[0], ip_p->ip_src[1], ip_p->ip_src[2], ip_p->ip_src[3], ip_p->ip_dst[0], ip_p->ip_dst[1], ip_p->ip_dst[2], ip_p->ip_dst[3]);
//     // 交换mac地址
//     memcpy(hdr->dmac, hdr->smac, 6);
//     fake_hw(hdr->smac);
//     // 交换IP地址
//     memcpy(ip_p->ip_dst, ip_p->ip_src, 4);
//     fake_ip(ip_p->ip_src);
//     //IP校验和
//     ip_p->ip_sum = 0;
//     ip_p->ip_sum = checksum((unsigned char *)ip_p, sizeof(*ip_p));
//     //ICMP校验和
//     short ip_len = htons(ip_p->ip_len);
//     icmp_p->csum = 0;
//     icmp_p->type = 0;
//     icmp_p->csum = checksum((unsigned char *)ip_p->payload, ip_len - (ip_p->ip_hlen * 4));
//     //发送
//     write(tap_fd, hdr, ntohs(ip_p->ip_len) + sizeof(*hdr));
//     struct icmp_v4_echo *icmp_echo = (struct icmp_v4_echo *)icmp_p->data;
//     printf("ICMP reply id: %d seq: %d\n",htons(icmp_echo->id), htons(icmp_echo->seq));

//     // printf("Type: %d, Code: %d \n", icmp_p->type, icmp_p->code);
//     // printf("csum: %d ", icmp_p->csum);
//     // icmp_p->csum = 0;
//     // unsigned short ip_len = htons(ip_hdr->ip_len);
//     // printf("icmp_type: %d, icmp_code: %d\n", icmp_p->type, icmp_p->code);
//     // printf("icmp_csum: %d\n", icmp_p->csum);
//     // printf("csum: %d\n",checksum((unsigned short *)ip_hdr->payload, ip_len - (ip_hdr->ip_hlen * 4)));

//     // printf("icmp packet\n");
//     // printf("ip_hlen: %d\n", htons(ip_hdr->ip_hlen));
//     // printf("ip_ver: %d\n", ip_hdr->ip_ver);
//     // printf("ip_tos: %d\n", ip_hdr->ip_tos);
//     // printf("ip_len: %d\n", htons(ip_hdr->ip_len));
//     // printf("ip_id: %d\n", htons(ip_hdr->ip_id));
//     // short ip_offset = htons(ip_hdr->ip_offlags);
//     // printf("ip_flags: %d\n", ip_offset>>13);
//     // printf("ip_offset: %d\n", ip_offset & 0x1fff);
//     // printf("ip_ttl: %d\n", ip_hdr->ip_ttl);
//     // printf("ip_p: %d\n", ip_hdr->ip_p);
//     // printf("ip_sum: %d\n", ip_hdr->ip_sum);
//     // printf("ip_src: %d.%d.%d.%d\n", ip_hdr->ip_src[0], ip_hdr->ip_src[1], ip_hdr->ip_src[2], ip_hdr->ip_src[3]);
//     // printf("ip_dst: %d.%d.%d.%d\n", ip_hdr->ip_dst[0], ip_hdr->ip_dst[1], ip_hdr->ip_dst[2], ip_hdr->ip_dst[3]);
//     printf("-------------------------------------\n");
// }

unsigned short checksum(unsigned char *buf, int count)
{
    unsigned int sum = 0;
    while (count > 1)
    {
        sum += *(unsigned short *)buf++;
        count -= 2;
    }
    if (count > 0)
    {
        sum += *(unsigned char *)buf;
    }
    while(sum >> 16)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return ~sum;
}