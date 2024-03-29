#include "list.h"
#include <stdio.h>
#include <ctype.h>

#include <netif.h>
#include <ether.h>
#include <lib.h>
#include <string.h>

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
    重新调整pkb的内存大小
    @pkb:   网络包
    @len:   新的内存大小
*/
void pkb_trim(struct pkbuf *pkb, int len)
{
    pkb->pk_len = len;
    if (realloc(pkb, sizeof(*pkb) + len) == NULL)
    {
        perrx("realloc error");
    }
}

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
    pkb->pk_rtdst = NULL;
    list_init(&pkb->pk_list);
    alloc_pkbs++;
    pkb_safe();
    return pkb;
}

/*
    为设备分配网络包
    @nd:    网络设备
    @(nd->net_mtu + ETH_HDR_SZ):   分配的内存大小,mtu+以太网头部
*/
struct pkbuf *alloc_netdev_pkb(struct netdev *nd)
{
    return alloc_pkb(nd->net_mtu + ETH_HDR_SZ);
}

/*
    复制一个pkb
    @pkb: 复制的目标pkb
*/
struct pkbuf *copy_pkb(struct pkbuf *pkb)
{
    struct pkbuf *c_pkb;
    c_pkb = xmalloc(pkb->pk_len);
    memcpy(c_pkb, pkb, pkb->pk_len);
    c_pkb->pk_refcnt = 1;
    list_init(&c_pkb->pk_list);
    alloc_pkbs++;
    pkb_safe();
    return c_pkb;
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

/*
    表示pkb数据包被使用了一次
    @pkb: 数据包
*/
void get_pkb(struct pkbuf *pkb)
{
    pkb->pk_refcnt++;
}