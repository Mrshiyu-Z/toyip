#include "net.h"
#include "ip.h"
#include "lib.h"

unsigned short checksum(unsigned char *buf, int count){
    unsigned int sum = 0;
    unsigned short *pkg = (unsigned short *)buf;
    while (count > 1)
    {
        sum += *pkg++;
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

void ip_set_checksum(struct ip_hdr *ip){
    ip->ip_sum = 0;
    ip->ip_sum = checksum((unsigned char *)ip, ip->ip_hlen*4);
}