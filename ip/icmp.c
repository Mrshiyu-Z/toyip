#include "lib.h"
#include "net.h"
#include "eth.h"
#include "ip.h"
#include "icmp.h"

#define DF 0x02
#define MF 0x01

void print_icmp(struct icmp_hdr *icmp)
{
    printf("icmp_type: %x\n", icmp->type);
    printf("icmp_code: %x\n", icmp->code);
    printf("icmp_csum: %d\n", icmp->csum);
}

unsigned short icmp_id = 1;
void icmp_echo(unsigned char *ip){
    struct pkg_buf *pkg = pkg_alloc(ICMP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN);
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)eth->data;
    struct icmp_hdr *icmp = (struct icmp_hdr *)ip_hdr->data;
    struct icmp_v4_echo *echo_icmp = (struct icmp_v4_echo *)icmp->data;
    echo_icmp->id = icmp_id;
    echo_icmp->seq = icmp_id;
    icmp_id++;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp_set_checksum(ip_hdr, icmp);
    memcpy(ip_hdr->ip_dst, ip, 4);
    pkg->pkg_pro = htons(ETH_TYPE_ARP);
    ip_send_info(pkg, 0, ICMP_HDR_LEN + IP_HDR_LEN, IP_PROTO_ICMP, ip);
}

void icmp_echo_reply(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    struct icmp_hdr *icmp = (struct icmp_hdr *)ip->data;
    icmp->type = 0;
    icmp_set_checksum(ip, icmp);
    ip_send_info(pkg, 0, htons(ip->ip_len), IP_PROTO_ICMP, ip->ip_src);
    return;
}

void icmp_in(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    struct icmp_hdr *icmp = (struct icmp_hdr *)ip->data;
    if (icmp->type != 0 && icmp->type != 8){
        perror("icmp type error");
        goto free_pkg;
    }
    unsigned short icmp_sum = icmp->csum;
    icmp->csum = 0;
    if (icmp_sum != icmp_checksum(ip)){
        perror("icmp checksum error");
        goto free_pkg;
        return;
    }
    if (htons(icmp->type) == 0){
        printf("icmp echo reply from %d.%d.%d.%d\n", ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);
    }else{
        icmp_echo_reply(pkg);
    }
    return;
free_pkg:
    free(pkg);
}

