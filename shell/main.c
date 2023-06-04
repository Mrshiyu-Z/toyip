#include "lib.h"
#include "netif.h"

void net_stack_init(void)
{
    netdev_init();
}


int main(int argc, char **argv)
{
    net_stack_init();
    return 0;
}