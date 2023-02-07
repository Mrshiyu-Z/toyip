#ifndef __LIB_H__
#define __LIB_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <stddef.h>
#include <linux/if.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

/*pthread*/
#include <pthread.h>

#define min(x,y) ({\
    typeof(x) _x = (x);\
    typeof(y) _y = (y);\
    (void)(&_x == &_y);\
    _x < _y ? _x : _y;})

typedef void *(*pfunc_t)(void *); //函数指针,返回一个void *类型的指针,参数是一个void *类型的指针

void net_timer(void); //定时器
void net_stack_run(void); //开启线程

extern unsigned short checksum(unsigned char *buf, int count);

struct ip_hdr;
struct icmp_hdr;
extern void ip_set_checksum(struct ip_hdr *ip);
extern unsigned short ip_checksum(struct ip_hdr *ip);
extern unsigned short icmp_checksum(struct ip_hdr *ip);
void icmp_set_checksum(struct ip_hdr *ip, struct icmp_hdr *icmp);
unsigned short tcp_checksum(struct ip_hdr *ip);

#endif