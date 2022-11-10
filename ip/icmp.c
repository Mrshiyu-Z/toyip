#include "lib.h"
#include "net.h"
#include "eth.h"
#include "ip.h"
#include "icmp.h"

#define DF 0x02
#define MF 0x01

unsigned short icmp_checksum(struct ip_hdr *ip)
{
    return checksum((unsigned char *)ip->data, htons(ip->ip_len) - ip->ip_hlen*4);
}

void icmp_set_checksum(struct ip_hdr *ip, struct icmp_hdr *icmp)
{
    icmp->csum = 0;
    icmp->csum = checksum((unsigned char *)ip->data, htons(ip->ip_len)-ip->ip_hlen*4);
}

void icmp_echo_reply(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    struct icmp_hdr *icmp = (struct icmp_hdr *)ip->data;
    icmp->type = 0;
    icmp_set_checksum(ip, icmp);
    ip_send_out(pkg);
    return;
}

void icmp_in(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    struct icmp_hdr *icmp = (struct icmp_hdr *)ip->data;
    if (icmp->type != 8){
        perror("icmp type error");
        goto free_pkg;
        return;
    }
    unsigned short icmp_sum = icmp->csum;
    icmp->csum = 0;
    if (icmp_sum != icmp_checksum(ip)){
        perror("icmp checksum error");
        goto free_pkg;
        return;
    }
    icmp_echo_reply(pkg);
    return;
free_pkg:
    free(pkg);
}

