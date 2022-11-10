#include "lib.h"
#include "net.h"
#include "eth.h"
#include "ip.h"

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

void ip_send_out(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct ip_hdr *ip = (struct ip_hdr *)eth->data;
    ip->ip_ttl -= 1;
    memcpy(ip->ip_dst, ip->ip_src, 4);
    cp_ip_lo(ip->ip_src);
    ip_set_checksum(ip);
    eth_out(pkg);
    return;
}