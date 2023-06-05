#include "lib.h"
#include "netif.h"

void net_stack_init(void)
{
    netdev_init();
}

void net_stack_run(void)
{
    netdev_interrupt();
}


int main(int argc, char **argv)
{
    net_stack_init();
    net_stack_run();
    return 0;
}