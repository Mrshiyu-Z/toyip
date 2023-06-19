#include "lib.h"
#include "netif.h"
#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "netif.h"
#include "route.h"

pthread_t thread[4];

int new_pthread(pfunc_t thread_func)
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, thread_func, NULL) != 0)
    {
        perror("pthread_create");
        return -1;
    }
    return tid;
}

void net_stack_init(void)
{
    netdev_init();
    arp_cache_init();
    rt_init();
}

void net_stack_run(void)
{
    thread[0] = new_pthread((pfunc_t)net_timer);
    netdev_interrupt();
}


int main(int argc, char **argv)
{
    net_stack_init();
    net_stack_run();
    return 0;
}