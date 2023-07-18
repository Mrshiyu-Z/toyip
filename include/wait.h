#ifndef __WAIT_H__
#define __WAIT_H__

#include "lib.h"
#include "compile.h"
#include "list.h"
#include <pthread.h>
#include <stdnoreturn.h>

/*
    用于模拟线程阻塞(如accept,read,recv)
*/

struct tcpip_wait {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int notified;    // 用于记录是否已经唤醒了等待在条件变量上的线程. 1 表示已经有线程被唤醒 0 表示没有线程被唤醒
    int dead;      // 用于记录线程等待状态是否已经结束. 1 结束 0 未结束
    int sleep;   // 用于记录线程是否在等待.1 等待 0 非等待
};

static _inline int wake_up(struct tcpip_wait *tw)
{
    pthread_mutex_lock(&tw->mutex);
    if (tw->dead)
        goto unlock;
    if (!tw->notified) {
        tw->notified = 1;
        if (tw->sleep)
            pthread_cond_signal(&tw->cond);
    }
unlock:
    pthread_mutex_unlock(&tw->mutex);
    return -(tw->dead);
}

static _inline int sleep_on(struct tcpip_wait *tw)
{
    pthread_mutex_lock(&tw->mutex);
    if (tw->dead)
        goto unlock;
    tw->sleep = 1;
    if (!tw->notified)
        pthread_cond_wait(&tw->cond, &tw->mutex);
    tw->notified = 0;
    tw->sleep = 0;
unlock:
    pthread_mutex_unlock(&tw->mutex);
    return -(tw->dead);
}

static _inline void wait_init(struct tcpip_wait *tw)
{
    pthread_cond_init(&tw->cond, NULL);
    pthread_mutex_init(&tw->mutex, NULL);
    tw->dead = 0;
    tw->notified = 0;
    tw->sleep = 0;
}

static _inline void wait_exit(struct tcpip_wait *tw)
{
    pthread_mutex_lock(&tw->mutex);
    if (tw->dead)
        goto unlock;
    tw->dead = 1;
    if (tw->sleep)
        pthread_cond_broadcast(&tw->cond);
unlock:
    pthread_mutex_unlock(&tw->mutex);
}

#endif