#ifndef __LIB_H__
#define __LIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <signal.h>
#include <bits/sigaction.h>

/* pthread */
#include <pthread.h>
extern int pthread_mutexattr_settype(pthread_mutexattr_t *, int);
typedef void *(*pfunc_t)(void *);

#define gettid() syscall(SYS_gettid)

/*
    控制是否开启debug信息的输出
*/
extern unsigned int net_debug;
#define NET_DEBUG_DEV		0x00000001
#define NET_DEBUG_L2		0x00000002
#define NET_DEBUG_ARP		0x00000004
#define NET_DEBUG_IP		0x00000008
#define NET_DEBUG_ICMP		0x00000010
#define NET_DEBUG_UDP		0x00000020
#define NET_DEBUG_TCP		0x00000040
#define NET_DEBUG_TCPSTATE  0x00000080
#define NET_DEBUG_ALL       0xffffffff


/*
    控制debug的输出颜色
*/
#define red(str) "\e[01;31m"#str"\e\[0m"
#define green(str) "\e[01;32m"#str"\e\[0m"
#define yellow(str) "\e[01;33m"#str"\e\[0m"
#define purple(str) "\e[01;35m"#str"\e\[0m"
#define grey(str) "\e[01;30m"#str"\e\[0m"
#define cambrigeblue(str) "\e[01;36m"#str"\e\[0m"
#define navyblue(str) "\e[01;34m"#str"\e\[0m"
#define blue(str) navyblue(str)

/*
    用于简化错误信息的输出
    @fmt:   输出的格式
    @args:  可变参数
*/
#define ferr(fmt, args...) fprintf(stderr, fmt, ##args)

/*
    用于格式化调试信息的输出
    @fmt:   输出的格式
    @args:  可变参数
    @(int)gettid(): 获取当前线程的ID
    @__FUNCTION__:  获取当前函数的名称
*/
#define dbg(fmt, args...) ferr("[%d]%s " fmt "\n", (int)gettid(), __FUNCTION__, ##args)
/*
    格式化输出调试信息
*/
#define devdbg(fmt, args...) \
do { \
    if (net_debug & NET_DEBUG_DEV) \
        dbg(green(dev)" "fmt, ##args); \
}while (0)

#define l2dbg(fmt, args...) \
do { \
    if (net_debug & NET_DEBUG_L2) \
        dbg(yellow(l2)" "fmt, ##args); \
}while (0)

#define arpdbg(fmt, args...)\
do {\
	if (net_debug & NET_DEBUG_ARP)\
		dbg(red(arp)" "fmt, ##args);\
} while (0)

#define ipdbg(fmt, args...)\
do {\
	if (net_debug & NET_DEBUG_IP)\
		dbg(blue(ip)" "fmt, ##args);\
} while (0)

#define icmpdbg(fmt, args...)\
do {\
	if (net_debug & NET_DEBUG_ICMP)\
		dbg(purple(icmp)" "fmt, ##args);\
} while (0)

#define udpdbg(fmt, args...)\
do {\
    if (net_debug & NET_DEBUG_UDP)\
        dbg(purple(udp)" "fmt, ##args);\
}while(0)

#define tcpdbg(fmt, args...)\
do {\
    if (net_debug & NET_DEBUG_TCP)\
        dbg(purple(tcp)" "fmt, ##args);\
}while(0)

#define tcpsdbg(fmt, args...)\
do {\
    if (net_debug & NET_DEBUG_TCPSTATE)\
        dbg(green(tcpstate)" "fmt, ##args);\
}while(0)

#define min(x,y) ({\
    typeof(x) _x = (x);\
    typeof(y) _y = (y);\
    (void) (&_x == &_y);\
    _x < _y ? _x : _y; })

extern void *xzalloc(int size);
extern void *xmalloc(int size);
extern void perrx(char *str);
extern void printfs(int mlen, const char *fmt, ...);
extern int str2ip(char *str, unsigned int *ip);

extern unsigned short ip_chksum(unsigned short *data, int size);
extern unsigned short icmp_chksum(unsigned short *data, int size);
extern unsigned short tcp_chksum(unsigned int src, unsigned dst,
		unsigned short len, unsigned short *data);
extern unsigned short udp_chksum(unsigned int src, unsigned int dst,
		unsigned short len, unsigned short *data);
struct ip;
struct udp;
struct tcp;
extern void ip_set_checksum(struct ip *ip_hdr);
extern void udp_set_checksum(struct ip *ip_hdr, struct udp *udp_hdr);
extern void tcp_set_checksum(struct ip *ip_hdr, struct tcp *tcp_hdr);

#endif