#ifndef __WAIT_H__
#define __WAIT_H__

#include "lib.h"
#include "compile.h"
#include <pthread.h>

/*
* 
*/
struct tcpip_wait {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int notified;          // 记录是否已经被唤醒
    int dead;              // 为安全退出而设置的标志
    int sleep;
};
static _inline int wake_up(struct tcpip_wait *w)
{
    pthread_mutex_lock(&w->mutex);
    if (w->dead)
        goto unlock;
    if (!w->notified) {
        w->notified = 1;
        if (w->sleep)
            pthread_cond_signal(&w->cond);
    }
unlock:
    pthread_mutex_unlock(&w->mutex);
    return -(w->dead);
}

static _inline int sleep_on(struct tcpip_wait *w)
{
    pthread_mutex_lock(&w->mutex);
    if (w->dead)
        goto unlock;
    w->sleep = 1;
    if (!w->notified) {
        pthread_cond_wait(&w->cond, &w->mutex);
        w->sleep = 0;
        w->notified = 0;
    }
unlock:
    pthread_mutex_unlock(&w->mutex);
    return -(w->dead);
}

static _inline void wait_init(struct tcpip_wait *w)
{
    pthread_mutex_init(&w->mutex, NULL);
    pthread_cond_init(&w->cond, NULL);
    w->notified = 0;
    w->dead = 0;
    w->sleep = 0;
}

static _inline void wait_exit(struct tcpip_wait *w)
{
    pthread_mutex_lock(&w->mutex);
    if (w->dead)
        goto unlock;
    w->dead = 1;
    if (w->sleep)
        pthread_cond_signal(&w->cond);
unlock:
    pthread_mutex_unlock(&w->mutex);
}

#endif