#include "lib.h"
#include "eth.h"
#include "arp.h"
#include "icmp.h"
#include "tap.h"

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