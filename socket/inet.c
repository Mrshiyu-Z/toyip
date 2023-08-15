#include "socket.h"
#include "sock.h"
#include "netif.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "raw.h"
#include "inet.h"
#include "lib.h"
#include "route.h"

static struct inet_type inet_type_table[SOCK_MAX] = {
    [0] = {},
    [SOCK_STREAM] = {
        .type = SOCK_STREAM,
        .protocol = IP_P_TCP,
        .alloc_socks = tcp_alloc_sock,
    },
    [SOCK_DGRAM] = {
        .type = SOCK_DGRAM,
        .protocol = IP_P_UDP,
        .alloc_socks = udp_alloc_sock,
    },
    [SOCK_RAW] = {
        .type = SOCK_RAW,
        .protocol = IP_P_IP,
        .alloc_socks = raw_alloc_sock,
    }
};

