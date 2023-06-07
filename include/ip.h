#ifndef __IP_H__
#define __IP_H__

#define IP_ALEN   4                /* IP地址长度 */
#define IPFMT     "%d.%d.%d.%d"
#define ipfmt(ip)\
	(ip) & 0xff, ((ip) >> 8) & 0xff, ((ip) >> 16) & 0xff, ((ip) >> 24) & 0xff

/* 
	判断IP是否为多播地址
	判定方法:
		判定最高位是否为1110
*/
#define MULTICAST(netip) ((0x000000f0 & (netip)) == 0x000000e0)

/*
	判断IP是否为广播地址
	判定方法:
		判定最高位是否为1或0
*/
#define BROADCAST(netip) (((0xff000000 & (netip)) == 0xff000000) ||\
				((0xff000000 & (netip)) == 0x00000000))

#endif