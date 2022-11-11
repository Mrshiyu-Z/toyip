#include "lib.h"
#include "list.h"
#include "net.h"
#include "eth.h"
#include "arp.h"

static struct arp_cache arp_cache[ARP_CACHE_SIZE];

#define arp_cache_head (&arp_cache[0])
#define arp_cache_end (&arp_cache[ARP_CACHE_SIZE - 1])

pthread_mutex_t arp_cache_mutex;

static inline void arp_cache_lock(void)      //锁定arp缓存
{
    pthread_mutex_lock(&arp_cache_mutex);
}

static inline void arp_cache_unlock(void)    //释放arp缓存
{
    pthread_mutex_unlock(&arp_cache_mutex);
}

void arp_cache_init(void)                     //初始化arp缓存
{
    int i;
    if (pthread_mutex_init(&arp_cache_mutex, NULL) != 0)
    {
        perror("arp_cache_mutex init failed\n");
    }
    for ( i = 0; i < ARP_CACHE_SIZE; i++)
    {
        arp_cache[i].state = ARP_FREE;
    }
}

struct arp_cache *arp_alloc(void) //在ARP_CACHE_SIZE个 arp缓存 中 寻找 空闲的 缓存
{             
    static int next = 0;
    int i;
    struct arp_cache *ac = NULL;
    // printf("arp_alloc 39\n");
    arp_cache_lock();
    // printf("arp_alloc 41\n");
    for (i = 0; i < ARP_CACHE_SIZE;i++)
    {
        //找到一个空闲的缓存
        if (arp_cache[i].state == ARP_FREE)
            break;
        next = (next + 1)%ARP_CACHE_SIZE;
    }
    //如果没找到空闲的
    if ( i > ARP_CACHE_SIZE)
    {
        perror("arp cache is full");
        arp_cache_unlock();
        return NULL;
    }
    //找到空闲,开始初始化
    ac = &arp_cache[next];
    ac->state = ARP_PENDDING;
    ac->retry = ARP_RETRY;
    ac->ttl = ARP_TIMEOUT;
    list_init(&ac->list);
    next = (next + 1) % ARP_CACHE_SIZE; 
    arp_cache_unlock();
    return ac;
}

void arp_queue_send(struct arp_cache *ac)
{
    struct pkg_buf *pkg;
    while(!list_empty(&ac->list))
    {
        pkg = list_first_node(&ac->list, struct pkg_buf, list);
        list_del(&pkg->list);
        net_out(pkg, ac->mac, pkg->pkg_pro);
    }
}

void arp_queue_drop(struct arp_cache *ac)           //删除缓存
{
    struct pkg_buf *pkg;
    while(!list_empty(&ac->list))
    {
        pkg = list_first_node(&ac->list, struct pkg_buf, list);
        list_del(ac->list.next);   
    }
}

struct arp_cache *arp_cache_lookup(unsigned char *ip)
{
    struct arp_cache *ac;
    arp_cache_lock();
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
    {
        ac = &arp_cache[i];
        if (ac->state == ARP_FREE)
            continue;
        if (memcmp(ac->ip, ip, 4) == 0)
        {
            arp_cache_unlock();
            return ac;
        }
    }
    arp_cache_unlock();
    return NULL;
}

void arp_insert(unsigned char *ip, unsigned char *mac)
{
    struct arp_cache *ac;
    ac = arp_alloc();
    if (ac)
    {
        ac->state = ARP_RESOLVED;
        ac->retry = ARP_RETRY;
        ac->ttl = ARP_TIMEOUT;
        memcpy(ac->ip, ip, 4);
        memcpy(ac->mac, mac, 6);
    }else
    {
        return;
    }
    
}
