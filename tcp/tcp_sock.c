#include "compile.h"
#include "lib.h"
#include "list.h"
#include "sock.h"
#include "socket.h"
#include "tcp_hash.h"
#include "tcp.h"
#include "ip.h"
#include "netif.h"
#include "cbuf.h"
#include "wait.h"

static struct tcp_hash_table tcp_table;

/*
    利用四元组在已建立的连接中寻找指定sock
    @src: 源IP地址
    @dst: 目的IP地址
    @src_port: 源端口
    @dst_port: 目的端口
*/
static struct sock *tcp_lookup_sock_establish(unsigned int src, unsigned int dst,
                unsigned short src_port, unsigned short dst_port)
{
    struct hlist_head *head;
    struct hlist_node *node;
    struct sock *sk;
    head = tcp_ehash_head(tcp_ehashfn(src, dst, src_port, dst_port));
    hlist_for_each_sock(sk, node, head) {
        if (sk->sk_saddr == dst && 
            sk->sk_daddr == src && 
            sk->sk_sport == dst_port &&
            sk->sk_dport == src_port)
            return get_sock(sk);
    }
    return NULL;
}

/*
    通过addr和port在listen表中查找sock
    @addr: ip addr
    @nport: tcp port
*/
static struct sock *tcp_lookup_sock_listen(unsigned int addr, unsigned int nport)
{
    struct hlist_head *head = tcp_lhash_head(_ntohs(nport) & TCP_LHASH_MASK);
    struct hlist_node *node;
    struct sock *sk;
    hlist_for_each_sock(sk, node, head) {
        if ((!sk->sk_saddr || sk->sk_saddr == addr) && 
            sk->sk_sport == nport)
            return get_sock(sk);
    }
    return NULL;
}

struct sock *tcp_lookup_sock(unsigned int src,
                             unsigned int dst,
                             unsigned int src_port,
                             unsigned int dst_port)
{
    struct sock *sk;
    sk = tcp_lookup_sock_establish(src, dst, src_port, dst_port);
    if (!sk) /*  如果已建立连接的hash表中没找到,则在listen表中找 */
        sk = tcp_lookup_sock_listen(dst, dst_port);
    return sk;
}

static _inline int __tcp_port_used(unsigned short nport, struct hlist_head *head)
{
    struct hlist_node *node;
    struct tcp_sock *tsk;
    for_each_tcp_sock(tsk, node, head)
        if (tsk->sk.sk_sport == nport)
            return 1;
    return 0;
}

static _inline int tcp_port_used(unsigned short nport)
{
    return __tcp_port_used(nport, tcp_bhash_head(_ntohs(nport) & TCP_BHASH_MASK));
}

static unsigned short tcp_get_port(void)
{
    static unsigned short defport = TCP_BPORT_MIN;
    unsigned short nport = 0;
    if (tcp_table.bfree <= 0)
        return 0;
    while (tcp_port_used(_htons(defport))) {
        if (++defport > TCP_BPORT_MAX)
            defport = TCP_BPORT_MIN;
    }
    nport= _htons(defport);
    if (++defport > TCP_BPORT_MAX)
        defport = TCP_BPORT_MIN;
    return nport;
}

static void tcp_bhash(struct tcp_sock *tsk)
{
    get_tcp_sock(tsk);
    hlist_add_head(&tsk->bhash_list, tcp_bhash_head(tsk->bhash));
}

static int tcp_set_sport(struct sock *sk, unsigned short nport)
{
    int err = -1;
    if ((nport && tcp_port_used(nport)) ||
        (!nport && !(nport = tcp_get_port())))
        goto out;
    tcp_table.bfree--;
    sk->sk_sport = nport;
    tcpsk(sk)->bhash = _htons(nport) & TCP_BHASH_MASK;
    tcp_bhash(tcpsk(sk));
    err = 0;
out:
    return err;
}

static void tcp_unset_sport(struct sock *sk)
{
    tcp_table.bfree++;
}

/*
    从tcp_bind hash表中删除tcp_sock
*/
void tcp_unbhash(struct tcp_sock *tsk)
{
    if (!hlist_unhashed(&tsk->bhash_list)) {
        tcp_unset_sport(&tsk->sk);
        hlist_del(&tsk->bhash_list);
        free_sock(&tsk->sk);
    }
}

/*
    将sock进行hash处理
    @sk: sock套接字
*/
int tcp_hash(struct sock *sk)
{
    struct tcp_sock *tsk = tcpsk(sk);
    struct hlist_head *head;
    unsigned int hash;
    if (tsk->state == TCP_CLOSE)  /* close状态不处理 */
        return -1;
    /* 
        设置sock->hash
        获取hash链表的头节点
    */
    if (tsk->state == TCP_LISTEN) {
        sk->hash = _ntohs(sk->sk_sport) & TCP_LHASH_MASK;
        head = tcp_lhash_head(sk->hash);
    } else {
        hash = tcp_ehashfn(sk->sk_saddr, sk->sk_daddr, 
                sk->sk_sport, sk->sk_dport);
        head = tcp_ehash_head(hash);
        if (tcp_ehash_conflict(head, sk))   /* 查看是否存在重复sock */
            return -1;
        sk->hash = hash;
    }
    sock_add_hash(sk, head);  /* 将sock 加入到 hash表中 */
    return 0;
}

void tcp_unhash(struct sock *sk)
{
    sock_del_hash(sk);
    sk->hash = 0;
}

static _inline void tcp_pre_wait_connect(struct tcp_sock *tsk)
{
    tsk->wait_connect = &tsk->sk.sock->sleep;
}

static int tcp_wait_connect(struct tcp_sock *tsk)
{
    int err;
    err = sleep_on(tsk->wait_connect);
    tsk->wait_connect = NULL;
    return err;
}

static int tcp_connect(struct sock *sk, struct sock_addr *sk_addr)
{
    struct tcp_sock *tsk = tcpsk(sk);
    int err;
    if (tsk->state != TCP_CLOSE)
        return -1;
    sk->sk_daddr = sk_addr->dst_addr;
    sk->sk_dport = sk_addr->dst_port;

    tsk->state = TCP_SYN_SENT;
    // tsk->iss = alloc_new_iss();
    tsk->snd_una = tsk->iss;
    tsk->snd_nxt = tsk->iss + 1;
    if (tcp_hash(sk) < 0) {
        tsk->state = TCP_CLOSE;
        return -1;
    }

    tcp_pre_wait_connect(tsk);
    // tcp_send_syn(tsk, NULL);
    err = tcp_wait_connect(tsk);
    if (err || tsk->state != TCP_ESTABLISHED) {
        tcp_unhash(sk);
        tcp_unbhash(tsk);
        tsk->state = TCP_CLOSE;
        err = -1;
    }
    return err;
}

static int tcp_listen(struct sock *sk, int backlog)
{
    struct tcp_sock *tsk = tcpsk(sk);
    unsigned int oldstate = tsk->state;
    if (!sk->sk_sport)
        return -1;
    if (backlog > TCP_MAX_BACKLOG)
        return -1;
    if (oldstate != TCP_CLOSE && oldstate != TCP_LISTEN)
        return -1;
    tsk->backlog = backlog;
    tsk->state = TCP_LISTEN;
    if (oldstate != TCP_LISTEN && sk->sk_ops->hash)
        sk->sk_ops->hash(sk);
    return 0;
}

static int tcp_wait_accept(struct tcp_sock *tsk)
{
    int err;
    tsk->wait_accept = &tsk->sk.sock->sleep;
    err = sleep_on(tsk->wait_accept);
    tsk->wait_accept = NULL;
    return err;
}

static struct sock *tcp_accept(struct sock *sk)
{
    struct tcp_sock *tsk = tcpsk(sk);
    struct tcp_sock *newtsk = NULL;
    while (list_empty(&tsk->accept_queue)) {
        if (tcp_wait_accept(tsk) < 0) 
            goto out;   
    }
    newtsk = tcp_accept_dequeue(tsk);
    free_sock(&newtsk->sk);
    free_sock(&newtsk->parent->sk);
    newtsk->parent = TCP_DEAD_PARENT;
out:
    return newtsk ? &newtsk->sk : NULL;
}

static void tcp_clear_listen_queue(struct tcp_sock *tsk)
{
    struct tcp_sock *ltsk;
    while (!list_empty(&tsk->listen_queue)) {
        ltsk = list_first_entry(&tsk->listen_queue, struct tcp_sock, list);
        list_del_init(&ltsk->list);
        if (ltsk->state == TCP_SYN_RECV) {
            free_sock(&ltsk->parent->sk);
            ltsk->parent = NULL;
            tcp_unhash(&ltsk->sk);
            free_sock(&ltsk->sk);
        }
    }
}

static int tcp_close(struct sock *sk)
{
    struct tcp_sock *tsk = tcpsk(sk);
    switch (tsk->state) {
        case TCP_CLOSE:
            break;
        case TCP_LISTEN:
            tcp_clear_listen_queue(tsk);
            if (sk->sk_ops->unhash)
                sk->sk_ops->unhash(sk);
            tcp_unbhash(tsk);
            tsk->state = TCP_CLOSE;
            break;
        case TCP_SYN_RECV:
            break;
        case TCP_SYN_SENT:
            break;
        case TCP_ESTABLISHED:
            tsk->state = TCP_FIN_WAIT1;
            // tcp_send_fin(tsk);
            tsk->snd_nxt++;
            break;
        case TCP_CLOSE_WAIT:
            tsk->state = TCP_LAST_ACK;
            // tcp_send_fin(tsk):
            tsk->snd_nxt++;
            break;
    }
    // tcp_free_buf(tsk);
    // tcp_free_reass_head(tsk);
    return 0;
}

static int tcp_send_buf(struct sock *sk, void *buf, int len,
                struct sock_addr *saddr)
{
    struct tcp_sock *tsk = tcpsk(sk);
    int ret = -1;
    switch (tsk->state) {
        case TCP_CLOSE:
        case TCP_LISTEN:
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_LAST_ACK:
        case TCP_CLOSING:
        case TCP_TIME_WAIT:
            goto out;
        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
            break;
    }
    // ret = tcp_send_text(tsk, buf, len);
out:
    return ret;
}

static int tcp_recv_buf(struct sock *sk, char *buf, int len)
{
    struct tcp_sock *tsk = tcpsk(sk);
    int ret = -1;
    int rlen = 0;
    int curlen;

    switch (tsk->state) {
        case TCP_LISTEN:
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
        case TCP_LAST_ACK:
        case TCP_CLOSING:
        case TCP_TIME_WAIT:
        case TCP_CLOSE:
            goto out;
        case TCP_CLOSE_WAIT:
            if (!tsk->rcv_buf || !CBUFUSED(tsk->rcv_buf))
                goto out;
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
            break;
    }
    while (rlen < len) {
        curlen = read_buf(tsk->rcv_buf, buf + rlen, len - rlen);
        tsk->rcv_wnd += curlen;
        rlen += curlen;
        while (!((tsk->flags & TCP_F_PUSH) ||
            (tsk->rcv_buf && CBUFUSED(tsk->rcv_buf)) ||
            (rlen >= len))) {
            if (sleep_on(sk->recv_wait) < 0) {
                ret = (rlen > 0) ? rlen : -1;
                goto out;
            }
        }
        if ((tsk->flags & TCP_F_PUSH) &&
            !(tsk->rcv_buf && CBUFUSED(tsk->rcv_buf))) {
            tsk->flags &= ~TCP_F_PUSH;
            break;
        }
    }
    ret = rlen;
out:
    return ret;
}

static void tcp_recv_notify(struct sock *sk)
{
    if (sk->recv_wait)
        wake_up(sk->recv_wait);
}

static struct sock_ops tcp_ops = {
    .send_buf = tcp_send_buf,
    // .send_pkb = tcp_send_pkb,
    .recv_buf = tcp_recv_buf,
    .recv_notify = tcp_recv_notify,
    .listen = tcp_listen,
    .accept = tcp_accept,
    .connect = tcp_connect,
    .hash = tcp_hash,
    .unhash = tcp_unhash,
    .set_port = tcp_set_sport,
    .close = tcp_close,
};

struct tcp_sock *get_tcp_sock(struct tcp_sock *tsk)
{
    get_sock(&tsk->sk);
    return tsk;
}

int tcp_id;

/*
    为tcp sock申请一片内存
    @protocol: IP_P_TCP
*/
struct sock *tcp_alloc_sock(int protocol)
{
    struct tcp_sock *tsk;
    if (protocol && protocol != IP_P_TCP)
        return NULL;
    tsk = xzalloc(sizeof(*tsk));
    alloc_socks++;
    tsk->sk.sk_ops = &tcp_ops;
    /* 初始状态为close */
    tsk->state = TCP_CLOSE;
    tsk->rcv_wnd = TCP_DEFAULT_WINDOW;
    /* 初始化各种链表 */
    list_init(&tsk->listen_queue);
    list_init(&tsk->accept_queue);
    list_init(&tsk->list);
    list_init(&tsk->sk.recv_queue);
    list_init(&tsk->rcv_reass);
    tcp_id++;
    return &tsk->sk;
}

void tcp_init(void)
{
    int i;
    for (i = 0; i < TCP_EHASH_SIZE; i++)
        hlist_head_init(&tcp_table.etable[i]);
    for (i = 0; i < TCP_LHASH_SIZE; i++)
        hlist_head_init(&tcp_table.ltable[i]);
    tcp_table.bfree = TCP_BPORT_MAX - TCP_BPORT_MIN + 1;
    tcp_id = 0;
}