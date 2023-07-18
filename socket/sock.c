#include "netif.h"
#include "socket.h"
#include "sock.h"
#include "lib.h"
#include "list.h"
#include "wait.h"
#include <stdlib.h>

int alloc_socks = 0;
int free_socks = 0;

/*
    sock增加引用计数
    @sk: sock
*/
struct sock *get_sock(struct sock *sk)
{
    sk->refcnt++;
    return sk;
}

void free_sock(struct sock *sk)
{
    if (--sk->refcnt <= 0) {
        free_socks++;
        free(sk);
    }
}

/*
    将sock加入到hash链表
    @sk: sock
    @head: hash链表的头节点
*/
void sock_add_hash(struct sock *sk, struct hlist_head *head)
{
    get_sock(sk);
    hlist_add_head(&sk->hash_list, head);
}

/*
    从hash链表中删除sock
    @sk: sock
*/
void sock_del_hash(struct sock *sk)
{
    if (!hlist_unhashed(&sk->hash_list)) {
        hlist_del(&sk->hash_list);
        free_sock(sk);
    }
}

void sock_recv_notify(struct sock *sk)
{
    if (!list_empty(&sk->recv_queue) && sk->recv_wait)
        wake_up(sk->recv_wait);
}

/*
    
*/
struct pkbuf *sock_recv_pkb(struct sock *sk)
{
    struct pkbuf *pkb = NULL;
    while (1) {
        if (!list_empty(&sk->recv_queue)) {
            pkb = list_first_entry(&sk->recv_queue, struct pkbuf, pk_list);
            list_del_init(&pkb->pk_list);
            break;
        }
        if (sleep_on(sk->recv_wait) < 0)
            break;
    }
    return pkb;
}

int sock_close(struct sock *sk)
{
    struct pkbuf *pkb;
    sk->recv_wait = NULL;
    if (sk->sk_ops->unhash)
        sk->sk_ops->unhash(sk);
    while (!list_empty(&sk->recv_queue)) {
        pkb = list_first_entry(&sk->recv_queue, struct pkbuf, pk_list);
        list_del(&pkb->pk_list);
        free(pkb);
    }
    return 0;
}

int sock_autobind(struct sock *sk)
{
    if (sk->sk_ops->set_port)
        return sk->sk_ops->set_port(sk, 0);
    return 0;
}