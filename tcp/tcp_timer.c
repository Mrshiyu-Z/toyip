#include "list.h"
#include "sock.h"
#include "tcp.h"
#include "lib.h"
#include "tcp_timer.h"

static struct tcp_timer_head timewait;

void tcp_timewait_timer(int delta)
{
    struct tcp_timer *t, *next, **pprev;
    struct tcp_sock *tsk;
    for (pprev = &timewait.next, t = timewait.next; t; t = next){
        next = t->next;
        t->next = NULL;
        t->timeout -= delta;
        if (t->timeout <= 0) {
            tsk = timewait2tsk(t);
            if (!tsk->parent)
                tcp_unbhash(tsk);
            tcp_unhash(&tsk->sk);
            tcp_set_state(tsk, TCP_CLOSE);
            free_sock(&tsk->sk);
            *pprev = next;
        } else {
            pprev = &t->next;
        }
    }
}

void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
    tcp_set_state(tsk, TCP_TIME_WAIT);
    tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
    tsk->timewait.next = timewait.next;
    timewait.next = &tsk->timewait;
    get_tcp_sock(tsk);
}

void tcp_timer(void)
{
    unsigned int i = 0;
    timewait.next = NULL;
    while (1) {
        usleep(TCP_TIMER_DELTA);
        i++;
        if ((i % (1000000 / TCP_TIMER_DELTA)) == 0)
            tcp_timewait_timer(1000000);
    }
}