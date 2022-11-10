#include "lib.h"
#include "eth.h"
#include "net.h"
#include "arp.h"

static struct arp_cache arp_cache[ARP_CACHE_SIZE];

#define arp_cache_head (&arp_cache[0])
#define arp_cache_end (&arp_cache[ARP_CACHE_SIZE - 1])

pthread_mutex_t arp_cache_mutex;

static inline void arp_cache_lock(void)
{
    pthread_mutex_lock(&arp_cache_mutex);
}

static inline void arp_cache_unlock(void)
{
    pthread_mutex_unlock(&arp_cache_mutex);
}

void arp_cache_init(void)
{
    int i;
    for ( i = 0; i < ARP_CACHE_SIZE; i++)
    {
        arp_cache[i].state = ARP_FREE;
    }
}

struct arp_cache *arp_alooc(void)
{
    static int next = 0;
    int i;
    struct arp_cache *ac = NULL;
    arp_cache_lock();
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
    next = (next + 1)%ARP_CACHE_SIZE;
    arp_cache_unlock();
    return ac;
}

void arp_queue_drop(struct arp_cache *ac)
{
    struct pkg_buf *pkg;
    while(!list_empty(&ac->list))
    {
        pkg = list_first_node(&ac->list, struct pkg_buf, list);
        list_del(&ac->list.next);
        
    }
}

// void arp_timer(void)
// {
//     struct arp_cache *ac;
//     arp_cache_lock();
//     for (ac = arp_cache_head;ac < arp_cache_end;ac++)
//     {
//         if (ac->state == FREE)
//         {
//             continue;
//         }
//         if (ac->ttl <= 0)
//         {
//             if ((ac->state == PENDDING && --ac->retry <= 0) || ac->state == RESOLVED)
//             {
                
//             }
//         }
// }
