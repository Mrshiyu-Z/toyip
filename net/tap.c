#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int alloc_tap(char *dev)
{
    int tap_fd;
    struct ifreq ifr;
    tap_fd = open("/dev/net/tun", O_RDWR);
    if (tap_fd < 0)
    {
        perror("open tap_fd");
        return -1;
    }
	memset(&ifr, 0x0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(tap_fd, TUNSETIFF, (void *)&ifr) < 0) {
		perror("ioctl TUNSETIFF");
		close(tap_fd);
		return -1;
	}
    return tap_fd;
}

int close_tap(int tap_fd)
{
    close(tap_fd);
    return 0;
}