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

typedef void *(*pfunc_t)(void *); //函数指针,返回一个void *类型的指针,参数是一个void *类型的指针

void net_timer(void); //定时器
void net_stack_run(void); //开启线程

#endif