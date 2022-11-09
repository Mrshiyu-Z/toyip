#include "lib.h"
#include "eth.h"
#include "arp.h"
#include "icmp.h"
#include "tap.h"

pthread_t threads[4];

void net_stack_run(void)
{
    threads[0] = eth_run();
}

int newthread(pfunc_t thread_func)
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, thread_func, NULL)){
        perror("create thread failed");
    }
    return tid;
}

void net_stack_run(void)
{
    threads[0] = newthread();
}


int main()
{
    int ret = 0;
    unsigned char buf[1500+14];
    int tap_fd = alloc_tap("tap0");
    printf("%d", tap_fd);
    struct eth_hdr *hdr;
    struct pollfd pfd[1];
    pfd[0].fd = tap_fd;
    pfd[0].events = POLLIN;
    // pfd.revents = 0;
    while (1)
    {
        ret = poll(pfd, 1, -1);
        if (ret < 0){
            perror("poll");
            continue;
        }
        else if (ret > 0){
            if (pfd[0].revents != 0){
                if (pfd[0].revents & POLLIN)
                {
                    read(pfd[0].fd, (void *)buf, 1500 + sizeof(*hdr));
                    hdr = (struct eth_hdr *)buf;
                    if (hdr->ethertype == 0x0608) //ARP
                    {
                        arp_reply(hdr, tap_fd);
                    }
                    if (hdr->ethertype == 0x0008) //IP
                    {
                        arp_handle(hdr, tap_fd);
                    }
                    memset(hdr, 0, sizeof(*hdr));
                    memset(buf, 0, sizeof(buf));
                }
            }
        }
    }
    close_tap(tap_fd);
    return 0;
}