#include "compile.h"
#include "lib.h"
#include "netif.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"

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

static _inline unsigned short tcp_udp_chksum(unsigned int src, unsigned int dst,
		unsigned short proto, unsigned short len, unsigned short *data) 
{
	unsigned int sum;
	sum = _htons(proto) + _htons(len);
	sum += src;
	sum += dst;
	return checksum(data, len, sum);
}

unsigned short tcp_chksum(unsigned int src, unsigned int dst,
		unsigned short len, unsigned short *data)
{
	return tcp_udp_chksum(src, dst, IP_P_TCP, len, data);
}

unsigned short udp_chksum(unsigned int src, unsigned int dst,
		unsigned short len, unsigned short *data)
{
	return tcp_udp_chksum(src, dst, IP_P_UDP, len, data);
}

void udp_set_checksum(struct ip *ip_hdr, struct udp *udp_hdr)
{
	udp_hdr->checksum = 0;
	udp_hdr->checksum = tcp_udp_chksum(ip_hdr->ip_src, ip_hdr->ip_dst,
		 IP_P_UDP, _ntohs(udp_hdr->length), (unsigned short *)udp_hdr);
	if (!udp_hdr->checksum)
		udp_hdr->checksum = 0xffff;
}

void tcp_set_checksum(struct ip *ip_hdr, struct tcp *tcp_hdr)
{
	tcp_hdr->checksum = 0;
	tcp_hdr->checksum = tcp_udp_chksum(ip_hdr->ip_src, ip_hdr->ip_dst,
		 IP_P_TCP, ipndlen(ip_hdr), (unsigned short *)tcp_hdr);
}