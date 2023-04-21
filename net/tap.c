#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/if_tun.h>

#include "netif.h"
#include "ether.h"
#include "lib.h"
#include "tap.h"

static int skfd;

int alloc_tap(char *dev)
{
    struct ifreq ifr = {0};
    int tap_fd;

    tap_fd = open(TAP_DEV, O_RDWR);
    if (tap_fd < 0) {
        perror("open");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr
}