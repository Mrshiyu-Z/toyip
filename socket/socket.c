#include "socket.h"
#include "inet.h"
#include "netif.h"
#include "route.h"
#include "sock.h"
#include "list.h"
#include "lib.h"
#include "wait.h"
#include <stdlib.h>
#include <unistd.h>


LIST_HEAD(listen_head)

static void __free_socket(struct socket *sock)
{
    if (sock->skt_ops) {
        sock->skt_ops->close(sock);
        sock->skt_ops = NULL;
    }
    free(sock);
}

static void free_socket(struct socket *sock)
{
    if (--sock->refcnt <= 0)
        __free_socket(sock);
}

static struct socket* get_socket(struct socket *sock)
{
    sock->refcnt++;
    return sock;
}

static struct socket *alloc_socket(int family, int type)
{
    struct socket *sock;
    sock = xzalloc(sizeof(*sock));
    sock->state = SS_UNCONNECTED;
    sock->family = family;
    sock->type = type;
    wait_init(&sock->sleep);
    sock->refcnt = 1;
    return sock;
}

struct socket *_socket(int family, int type, int protocol)
{
    struct socket *sock = NULL;
    if (family != AF_INET)
        goto out;

    sock = alloc_socket(family, type);
    if (!sock)
        goto out;
    sock->skt_ops = &inet_ops;
    if (sock->skt_ops->socket(sock, protocol) < 0) {
        free_socket(sock);
        sock = NULL;
    }

out:
    return sock;
}

int _listen(struct socket *sock, int backlog)
{
    int err = -1;
    if (!sock || backlog < 0)
        goto out;
    get_socket(sock);
    if (sock->skt_ops)
        err = sock->skt_ops->listen(sock, backlog);
    free_socket(sock);
out:
    return err;
}

void _close(struct socket *sock)
{
    if (!sock)
        return;
    wait_exit(&sock->sleep);
    free_socket(sock);
}

int _connect(struct socket *sock, struct sock_addr *sk_addr)
{
    int err = 1;
    if (!sock || !sk_addr)
        goto out;
    get_socket(sock);
    if (sock->skt_ops) {
        err = sock->skt_ops->connect(sock, sk_addr);
    }
    free_socket(sock);

out:
    return err;
}

int _bind(struct socket *sock, struct sock_addr *sk_addr)
{
    int err = -1;
    if (!sock || !sk_addr)
        goto out;
    get_socket(sock);
    if (sock->skt_ops) {
        err = sock->skt_ops->bind(sock, sk_addr);
    }
out:
    return err;
}

struct socket *_accept(struct socket *sock, struct sock_addr *sk_addr)
{
    struct socket *new_sock = NULL;
    int err = 0;
    if (!sock)
        goto out;
    new_sock = alloc_socket(sock->family, sock->type);
    if (!new_sock) {
        goto out_free;
    }
    new_sock->skt_ops = sock->skt_ops;
    if (sock->skt_ops) {
        err = sock->skt_ops->accept(sock, new_sock, sk_addr);
    }
    if (err < 0) {
        free(new_sock);
        new_sock = NULL;
    }
out_free:
    free_socket(sock);
out:
    return new_sock;
}

int _send(struct socket *sock, void *buf, int size, struct sock_addr *sk_addr)
{
    int err = -1;
    if (!sock || !buf || size <= 0 || !sk_addr)
        goto out;
    get_socket(sock);
    if (sock->skt_ops) {
        err = sock->skt_ops->send(sock, buf, size, sk_addr);
    }
    free_socket(sock);
out:
    return err;
}

struct pkbuf *_recv(struct socket *sock)
{
    struct pkbuf *pkb = NULL;
    if (!sock)
        goto out;
    get_socket(sock);
    if (sock->skt_ops)
        pkb = sock->skt_ops->recv(sock);
    free_socket(sock);
out:
    return pkb;
}

int _write(struct socket *sock, void *buf, int len)
{
    int ret = -1;
    if (!sock || !buf || len <= 0)
        goto out;
    get_socket(sock);
    if (sock->skt_ops) {
        ret = sock->skt_ops->write(sock, buf, len);
    }
    free_socket(sock);
out:
    return ret;
}


int _read(struct socket *sock, void *buf, int len)
{
    int ret = -1;
    if (!sock || !buf || len <= 0) {
        goto out;
    }
    get_socket(sock);
    if (sock->skt_ops) {
        ret = sock->skt_ops->read(sock, buf, len);
    }
    free_socket(sock);
out:
    return ret;
}

void socket_init(void)
{
    inet_init();
}


