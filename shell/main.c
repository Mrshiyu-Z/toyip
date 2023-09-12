#include "lib.h"
#include "netif.h"
#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "netif.h"
#include "route.h"
#include "socket.h"

extern void shell_master(char *prompt_str);
extern void *shell_worker(void *none);
extern void shell_init(void);
extern void tcp_timer(void);

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
    socket_init();
    shell_init();
}

void net_stack_run(void)
{
    thread[0] = new_pthread((pfunc_t)net_timer);
    thread[1] = new_pthread((pfunc_t)tcp_timer);
    thread[2] = new_pthread((pfunc_t)netdev_interrupt);
    thread[3] = new_pthread((pfunc_t)shell_worker);
    shell_master(NULL);
}


int main(int argc, char **argv)
{
    net_stack_init();
    net_stack_run();
    return 0;
}