#ifndef __TCP_TIMER_H
#define __TCP_TIMER_H

struct tcp_timer_head {
    struct tcp_timer *next;
};

struct tcp_timer {
    struct tcp_timer *next;
    int timeout;    // 微秒
};

#endif