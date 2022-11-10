#include "lib.h"
#include "tap.h"
#include "net.h"

int tap_fd;

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

void eth_tx(struct pkg_buf *pkg)
{
    int len;
    len = write(tap_fd, pkg->data, pkg->pkg_len);
    if (len < 0)
    {
        perror("net tx write");
    }
}
