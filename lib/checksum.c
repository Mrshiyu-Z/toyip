#include "lib.h"
#include "netif.h"
#include "ip.h"

static _inline unsigned int sum(unsigned short *data, int size, 
        unsigned int origsum)
{
	while (size > 1) {
		origsum += *data++;
		size -= 2;
	}
	if (size)
		origsum += _ntohs(((*(unsigned char *)data) & 0xff) << 8);
	return origsum;   
}

static _inline unsigned short checksum(unsigned short *data, int size,
                    unsigned int origsum)
{
	origsum = sum(data, size, origsum);
	origsum = (origsum & 0xffff) + (origsum >> 16);
	origsum = (origsum & 0xffff) + (origsum >> 16);
	return (~origsum & 0xffff);   
}

unsigned short ip_chksum(unsigned short *data, int size)
{
    return checksum(data, size, 0);
}

void ip_set_checksum(struct ip *ip_hdr)
{
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = ip_chksum((unsigned short *)ip_hdr, iphlen(ip_hdr));
}

unsigned short icmp_chksum(unsigned short *data, int size)
{
	return checksum(data, size, 0);
}