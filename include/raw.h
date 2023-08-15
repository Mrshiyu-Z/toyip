#ifndef __RAW_H__
#define __RAW_H__

#include "socket.h"
#include "list.h"
#include "sock.h"
#include "wait.h"

struct sock;
struct raw_sock {
    struct sock sk;
    struct list_head list;
};
extern void raw_in(struct pkbuf *);
extern struct sock *raw_look_up(unsigned int, unsigned int, int);
extern struct sock *raw_lookup_sock_next(struct sock *,unsigned int, unsigned int, int);
extern void raw_init(void);
extern struct sock *raw_alloc_sock(int);


#define RAW_DEFAULT_TTL 64
#define RAW_MAX_BUFSZ   65536

#endif