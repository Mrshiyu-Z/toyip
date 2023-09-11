#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "netif.h"
#include "wait.h"

enum socket_state {
    SS_UNCONNECTED = 1,
    SS_BIND,
    SS_LISREN,
    SS_CONNECTING,
    SS_CONNECTIED,
    SS_MAX
};

enum sock_type {
    SOCK_STREAM = 1,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_MAX
};

enum socket_family {
    AF_INET = 1
};

struct socket;
struct sock_addr;
struct socket_ops {
    int (*socket)(struct socket *, int);
    int (*close)(struct socket *);
    int (*accept)(struct socket *, struct socket *, struct sock_addr *);
    int (*listen)(struct socket *, int);
    int (*bind)(struct socket *, struct sock_addr *);
    int (*connect)(struct socket *, struct sock_addr *);
    int (*read)(struct socket *, void *, int);
    int (*write)(struct socket *, void *, int);
    int (*send)(struct socket *, void *, int , struct sock_addr *);
    struct pkbuf *(*recv)(struct socket *);
};

struct socket {
    unsigned int state;               // socket的状态
    unsigned int family;              // 协议族,目前只支持IPV4:AF_INET(IPV4),AF_INET6(IPV^),
    unsigned int type;                // socket的类型,'SOCK_STREAM'流套接字(对应TCP),'SOCK_DGRAM'数据报套接字(对应UDP)
    struct tcpip_wait sleep;
    struct socket_ops *skt_ops;
    struct sock *sk;
    int refcnt;                       // 引用计数,跟踪有多少个地方正在使用或引用这个socket
};

extern struct socket *_socket(int family, int type, int protocol);
extern int _listen(struct socket *sock, int backlog);
extern void _close(struct socket *sock);
extern int _connect(struct socket *sock, struct sock_addr *sk_addr);
extern int _bind(struct socket *sock, struct sock_addr *sk_addr);
extern struct socket *_accept(struct socket *sock, struct sock_addr *sk_addr);
extern int _send(struct socket *sock, void *buf, int size, struct sock_addr *sk_addr);
extern struct pkbuf *_recv(struct socket *sock);
extern int _write(struct socket *sock, void *buf, int len);
extern int _read(struct socket *sock, void *buf, int len);
extern void socket_init(void);


#endif