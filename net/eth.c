#include "tap.h"
#include "net.h"
#include "eth.h"
#include "lib.h"

int tap_fd;

inline void cp_mac_lo(unsigned char *mac)
{
    mac[0] = 0x00;mac[1] = 0x34;
    mac[2] = 0x45;mac[3] = 0x67;
    mac[4] = 0x89;mac[5] = 0xab;
}

void eth_init(void)
{
    tap_fd = alloc_tap("tap0");
    if (tap_fd < 0)
    {
        perror("net init alloc_tap");
        exit(1);
    }
}

int eth_recv(struct pkg_buf *pkg)
{
    int len;
    len = read(tap_fd, pkg->data, pkg->pkg_len);
    if (len < 0)
    {
        perror("net rx read null");
    }
    else{
        pkg->pkg_len = len;
    }
    return len;
}

void eth_rx(void)
{
    struct pkg_buf *pkg = pkg_alloc(MTU_SIZE);
    if(0 < eth_recv(pkg))
    {
        net_in(pkg);
    }
    else{
        perror("eth_rx: eth_recv error");
        free(pkg);
    }
}

void eth_in(void)
{
    int ret = 0;
    struct pollfd pfd[1];
    pfd[0].fd = tap_fd;
    pfd[0].events = POLLIN;
    while (1)
    {
        ret = poll(pfd, 1, -1);
        if (ret < 0){
            perror("net in poll");
            continue;
        }
        else if (ret > 0){
            if (pfd[0].revents & POLLIN){
                eth_rx();
            }
        }
    }
}

void eth_out(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    memcpy(eth->dmac, eth->smac, 6);
    cp_mac_lo(eth->smac);
    eth_tx(pkg);
}

void eth_tx(struct pkg_buf *pkg)
{
    int len;
    len = write(tap_fd, pkg->data, pkg->pkg_len);
    if (len < 0)
    {
        perror("net tx write");
    }
}
