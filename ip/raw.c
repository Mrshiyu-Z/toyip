#include "netif.h"
#include "sock.h"
#include "socket.h"
#include "list.h"
#include "raw.h"
#include "ip.h"

static void raw_recv(struct pkbuf *pkb, struct sock *sk)
{
    list_add_tail(&pkb->pk_list, &sk->recv_queue);
    pkb->pk_sk = sk;
    sk->sk_ops->recv_notify(sk);
}

void raw_in(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct pkbuf *raw_pkb;
    struct sock *sk;
    sk = raw_look_up(ip_hdr->ip_src, ip_hdr->ip_dst, ip_hdr->ip_pro);
    while (sk) {
        raw_pkb = copy_pkb(pkb);
        raw_recv(raw_pkb, sk);
        sk = raw_lookup_sock_next(sk, ip_hdr->ip_src, ip_hdr->ip_dst, ip_hdr->ip_pro);
    }
}
