#include "list.h"
#include "socket.h"
#include "sock.h"
#include "netif.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "raw.h"
#include "inet.h"
#include "lib.h"
#include "route.h"

static struct inet_type inet_type_table[SOCK_MAX] = {
    [0] = {},
    [SOCK_STREAM] = {
        .type = SOCK_STREAM,
        .protocol = IP_P_TCP,
        .alloc_socks = tcp_alloc_sock,
    },
    [SOCK_DGRAM] = {
        .type = SOCK_DGRAM,
        .protocol = IP_P_UDP,
        .alloc_socks = udp_alloc_sock,
    },
    [SOCK_RAW] = {
        .type = SOCK_RAW,
        .protocol = IP_P_IP,
        .alloc_socks = raw_alloc_sock,
    }
};

static int inet_socket(struct socket *sock, int protocol)
{
    struct inet_type *inet;
    struct sock *sk;
    int type;

    type = sock->type;
    if (type >= SOCK_MAX) {
        return -1;
    }
    inet = &inet_type_table[type];
    sk = inet->alloc_socks(protocol);
    if (!sk) {
        return -1;
    }
    if (!protocol) {
        protocol = inet->protocol;
    }
    sock->sk = get_sock(sk);
    list_init(&sk->recv_queue);
    hlist_node_init(&sk->hash_list);
    sk->protocol = protocol;
    sk->sock = sock;
    if (sk->hash && sk->sk_ops->hash) {
        sk->sk_ops->hash(sk);
    }
    return 0;
}

static int inet_close(struct socket *sock)
{
    struct sock *sk = sock->sk;
    int err = -1;
    if (sk) {
        err = sk->sk_ops->close(sk);
        free_sock(sk);
        sock->sk = NULL;
    }
    return err;
}

static int inet_accept(struct socket *sock,
        struct socket *new_sock, struct sock_addr *sk_addr)
{
    struct sock *sk = sock->sk;
    struct sock *new_sk;
    int err = -1;
    if (!sk) {
        goto out;
    }
    new_sk = sk->sk_ops->accept(sk);
    if (new_sk) {
        new_sock->sk = get_sock(new_sk);
        if (sk_addr) {
            sk_addr->src_addr = new_sk->sk_daddr;
            sk_addr->src_port = new_sk->sk_dport;
        }
        err = 0;
    }
out:
    return err;
}

static int inet_listen(struct socket *sock, int backlog)
{
    struct sock *sk = sock->sk;
    int err = -1;
    if (sock->type != SOCK_STREAM) {
        return -1;
    }
    if (sk) {
        err = sk->sk_ops->listen(sk, backlog);
    }
    return err;
}

static int inet_bind(struct socket *sock, struct sock_addr *sk_addr)
{
    struct sock *sk = sock->sk;
    int err = -1;
    if (sk->sk_ops->bind) {
        return sk->sk_ops->bind(sock->sk, sk_addr);
    }
    if (sk->sk_sport) {
        goto err_out;
    }
    if (!local_address(sk_addr->src_addr)) {
        goto err_out;
    }
    sk->sk_saddr = sk_addr->src_addr;
    if (sk->sk_ops->set_port) {
        err = sk->sk_ops->set_port(sk, sk_addr->src_port);
        if (err < 0) {
            sk->sk_saddr = 0;
            goto err_out;
        }
    } else {
        sk->sk_sport = sk_addr->src_port;
    }
    err = 0;
    sk->sk_daddr = 0;
    sk->sk_dport = 0;
err_out:
    return err;
}

static int inet_connect(struct socket *sock, struct sock_addr *sk_addr)
{
    struct sock *sk = sock->sk;
    int err = -1;
    if (!sk_addr->dst_port || !sk_addr->dst_addr) {
        goto out;
    }
    if (sk->sk_dport) {
        goto out;
    }
    if (!sk->sk_sport && sock_autobind(sk) < 0) {
        goto out;
    }
    {
        struct rtentry *rt = rt_lookup(sk_addr->dst_addr);
        if (!rt) {
            goto out;
        }
        sk->sk_dst = rt;
        sk->sk_saddr = sk->sk_dst->rt_dev->net_ipaddr;
    }
    if (sk->sk_ops->connect) {
        err = sk->sk_ops->connect(sk, sk_addr);
    }
out:
    return err;
}

static int inet_read(struct socket *sock, void *buf, int len)
{
    struct sock *sk = sock->sk;
    int ret = -1;
    if (sk) {
        sk->recv_wait = &sock->sleep;
        ret = sk->sk_ops->recv_buf(sock->sk, buf, len);
        sk->recv_wait = NULL;
    }
    return ret;
}

static int inet_write(struct socket *sock, void *buf, int len)
{
    struct sock *sk = sock->sk;
    int ret = -1;
    if (sk) {
        ret =sk->sk_ops->send_buf(sock->sk, buf, len, NULL);
    }
    return ret;
}

static int inet_send(struct socket *sock, void *buf, int size,
            struct sock_addr *sk_addr)
{
    struct sock *sk = sock->sk;
    if (sk) {
        return sk->sk_ops->send_buf(sock->sk, buf, size, sk_addr);
    }
    return -1;
}

static struct pkbuf *inet_recv(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct pkbuf *pkb = NULL;
    if (sk) {
        sk->recv_wait = &sock->sleep;
        pkb = sk->sk_ops->recv(sock->sk);
        sk->recv_wait = NULL;
    }
    return pkb;
}

struct socket_ops inet_ops = {
    .socket = inet_socket,
    .close = inet_close,
    .listen = inet_listen,
    .bind = inet_bind,
    .accept = inet_accept,
    .connect = inet_connect,
    .read = inet_read,
    .write = inet_write,
    .send = inet_send,
    .recv = inet_recv,
};

void inet_init(void)
{
    raw_init();
    udp_init();
    tcp_init();
}
