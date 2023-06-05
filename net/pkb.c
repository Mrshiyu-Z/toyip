#include <stdio.h>
#include <ctype.h>

#include <netif.h>
#include <ether.h>
#include <lib.h>

#define MAX_PKBS 1024
int free_pkbs = 0;
int alloc_pkbs = 0;

#define pkb_safe() \
do { \
    if ((alloc_pkbs - free_pkbs ) > MAX_PKBS) { \
        dbg("oops: too many pkbuf"); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

/*
    为网络包分配内存
    @size:  分配的内存大小
*/
struct pkbuf *alloc_pkb(int size)
{
    struct pkbuf *pkb;
    pkb = xzalloc(sizeof(*pkb) + size);
    pkb->pk_len = size;
    pkb->pk_protocol = 0xffff;
    pkb->pk_type = 0;
    pkb->pk_refcnt = 1;
    pkb->pk_indev = NULL;
    list_init(&pkb->pk_list);
    alloc_pkbs++;
    pkb_safe();
    return pkb;
}

/*
    为设备分配网络包
    @nd:    网络设备
    @(nd->net_mtu + ETH_HRD_SZ):   分配的内存大小,mtu+以太网头部
*/
struct pkbuf *alloc_netdev_pkb(struct netdev *nd)
{
    return alloc_pkb(nd->net_mtu + ETH_HRD_SZ);
}

/*
    释放网络包
    @pkb:   网络包
*/
void free_pkb(struct pkbuf *pkb)
{
    if (--pkb->pk_refcnt <= 0) {
        free_pkbs++;
        free(pkb);
    }
}