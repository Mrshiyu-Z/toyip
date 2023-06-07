#include "ether.h"
#include "arp.h"
#include "lib.h"
#include "list.h"
#include "compile.h"

static struct arpentry arp_cache[ARP_CACHE_SZ];    /* ARP缓存 */

#define arp_cache_head (&arp_cache[0])
#define arp_cache_tail (&arp_cache[ARP_CACHE_SZ])

/* arp缓存的线程锁 */
pthread_mutex_t arp_cache_mutex;
/* 宏定义一个普通线程锁 */
#ifndef PTHREAD_MUTEX_NORMAL
#define PTHREAD_MUTEX_NORMAL PTHREAD_MUTEX_TIMED_NP
#endif
/*
    arp缓存线程锁的初始化
*/
static _inline void arp_cache_lock_init(void)
{
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0)
        perrx("pthread_mutexattr_init");
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL));
        perrx("pthread_mutexattr_settype");
    if (pthread_mutex_init(&arp_cache_mutex, &attr) != 0)
        perrx("pthread_mutex_init");
}

/* 加锁 */
static _inline void arp_cache_lock(void)
{
    pthread_mutex_lock(&arp_cache_mutex);
}

/* 解锁 */
static _inline void arp_cache_unlock(void)
{
    pthread_mutex_unlock(&arp_cache_mutex);
}

/*
    发送ARP缓存条目链表的等待队列中的数据包
    @ae:    ARP缓存条目
*/
void arp_queue_send(struct arpentry *ae)
{
    struct pkbuf *pkb;
    while (!list_empty(&ae->ae_list))
    {
        pkb = list_first_entry(&ae->ae_list, struct pkbuf, pk_list);
        list_del(ae->ae_list.next);
        dbg("send pending packet");
        netdev_tx(ae->ae_dev, pkb, pkb->pk_len - ETH_HRD_SZ, 
                pkb->pk_protocol, ae->ae_hwaddr);
    }
}

/*
    删除ARP缓存条目链表中的数据包
    @ae:    ARP缓存条目
*/
void arp_queue_drop(struct arpentry *ae)
{
    struct pkbuf *pkb;
    while (!list_empty(&ae->ae_list))
    {
        pkb = list_first_entry(&ae->ae_list, struct pkbuf, pk_list);
        list_del(ae->ae_list.next);
        free_pkb(pkb);
    }
}

/* 初始化ARP缓存 */
void arp_cache_init(void)
{
    int i;
    for ( i = 0; i < ARP_CACHE_SZ; i++)
    {
        arp_cache[i].ae_state = ARP_FREE;
    }
    dbg("ARP CACHE INIT");
    arp_cache_lock_init();
    dbg("ARP CACHE SEMAPHORE INIT");
}

/*
    ARP定时器,定时检查ARP缓存条目是否超时
*/
void arp_timer(int delay)
{
    struct arpentry *ae;
    arp_cache_lock();
    for (ae = arp_cache_head; ae < arp_cache_tail; ae++)
    {
        if (ae->ae_state == ARP_FREE)
            continue;
        if (ae->ae_ttl <= 0)
        {
            /* 
                如果((arp条目状态是ARP_WAITING 且 重试次数小于0)
                或 (arp条目状态是ARP_RESOLVED))
                则将ae->ae_state设置为ARP_FREE
                否则,再次重试
            */
            if ((ae->ae_state == ARP_WAITING && --(ae->ae_retry) < 0) 
                || ae->ae_state == ARP_RESOLVED)
            {
                if (ae->ae_state == ARP_WAITING)
                    arp_queue_drop(ae);
                ae->ae_state = ARP_FREE;
            } else {
                ae->ae_ttl = ARP_TIMEOUT;
                arp_cache_unlock();
                arp_request(ae);
                arp_cache_lock();
            }
        }
    }
    arp_cache_unlock();
}

struct arpentry *arp_alloc(void)
{
    static int next = 0;
    int i;
    struct arpentry *ae = NULL;
    arp_cache_lock();
    /* 在arp缓存中找到一个free的 */
    for (i = 0; i < ARP_CACHE_SZ; i++)
    {
        if (arp_cache[next].ae_state == ARP_FREE)
            break;
        next = (next + 1) % ARP_CACHE_SZ;
    }
    /* 如果没找到,表示arp缓存已经满了 */
    if (i >= ARP_CACHE_SZ)
    {
        dbg("arp cache is full");
        arp_cache_unlock();
        return NULL;
    }
    ae = &arp_cache[next];
    ae->ae_dev = NULL;
    ae->ae_retry = ARP_REQ_RETRY;
    ae->ae_ttl = ARP_TIMEOUT;
    ae->ae_pro = ETH_P_IP;
    list_init(&ae->ae_list);
    /* 下一次插入时可以直接从这次找的FREE之后的位置找 */
    next = (next + 1) % ARP_CACHE_SZ;
    arp_cache_unlock();
    return ae;
}

int arp_insert(struct netdev *dev, unsigned short pro,
        unsigned int ipaddr, unsigned char *hwaddr)
{
    struct arpentry *ae;
    ae = arp_alloc();
    if (!ae)
        return -1;
    ae->ae_dev = dev;
    ae->ae_pro = pro;
    ae->ae_ttl = ARP_TIMEOUT;
    ae->ae_ipaddr = ipaddr;
    ae->ae_state = ARP_RESOLVED;
    hwcpy(ae->ae_hwaddr, hwaddr);
    return 0;
}

/*
    在ARP缓存中查找指定的条目
    @pro:    三层协议类型
    @ipaddr: 三层IP地址
*/
struct arpentry *arp_lookup(unsigned short pro, unsigned int ipaddr)
{
    struct arpentry *ae, *ret = NULL;
    arp_cache_lock();
    dbg("pro:%d "IPFMT, pro, ipfmt(ipaddr));
    for (ae = arp_cache_head;ae < arp_cache_tail; ae++)
    {
        if (ae->ae_state == ARP_FREE)
            continue;
        else if (ae->ae_pro == pro && ae->ae_ipaddr == ipaddr) {
            ret = ae;
            break;
        }
    }
    arp_cache_unlock();
    return ret;
}

