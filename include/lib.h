#ifndef __LIB_H__
#define __LIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>

/* pthread */
#include <pthread.h>

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

extern void *xzalloc(int size);
extern void *xmalloc(int size);

#endif