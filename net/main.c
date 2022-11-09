#include "lib.h"
#include "eth.h"
#include "arp.h"
#include "icmp.h"
#include "tap.h"
#include "net.h"

pthread_t threads[4];

int newthread(pfunc_t thread_func)
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, thread_func, NULL)){
        perror("create thread failed");
    }
    return tid;
}

void net_stack_init(void)
{
    eth_init();
}

void net_stack_run(void)
{
    eth_in();
    // threads[0] = newthread((pfunc_t)eth_in);
}

int main()
{
    net_stack_init();
    net_stack_run();
    return 0;
}