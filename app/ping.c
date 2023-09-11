#include "lib.h"
#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "route.h"
#include "socket.h"
#include "sock.h"
#include <bits/getopt_core.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned short id;
static unsigned short seq;
static int size;
static int count;
static int recv;
static int psend, precv;
static int finited;
static int ttl;
static unsigned int ip_addr;
static struct socket *sock;
static struct sock_addr sk_addr;
static char *buf;

static void usage(void)
{
    printf(
        "Usage: ping [OPTIONS] ipaddr\n"
        "OPTIONS:\n"
        "       -s size     icmp echo size\n"
        "       -c count    times(not implemented)\n"
        "       -t ttl      time to live\n");
}

void init_options(void)
{
    buf = NULL;
    sock = NULL;
    size = 56;
    finited  = 0;
    recv = count = 0;
    ttl = 64;
    ip_addr = 0;
    seq = 0;
    psend = precv = 0;
    memset(&sk_addr, 0x0, sizeof(sk_addr));
    id++;
}

static int parse_args(int argc, char **argv)
{
    int c;
    if (argc < 0) {
        return -1;
    }
    optind = 0;
    opterr = 0;
    while ((c = getopt(argc, argv, "s:t:c:?h")) != 1) {
        switch (c) {
            case 's':
                size = atoi(optarg);
                break;
            case 'c':
                recv = count = atoi(optarg);
                finited = 1;
                break;
            case 't':
                ttl = atoi(optarg);
                break;
            case 'h':
            case '?':
            default:
                return -1;
        }
    }
    if (size < 0 || size > 65507) {
        printf("Packet size %d is too large. Maximum is 65507\n", size);
        return -2;
    }
    if (ttl < 0 || ttl > 255) {
        printf("ttl %d out of range\n", ttl);
        return -2;
    }
    if (finited && count <= 0) {
        printf("bad number of packets to transmit\n");
    }
    argc -= optind;
    argv += optind;
    if (argc != 1) {
        return -1;
    }
    if (str2ip(*argv, &ip_addr) < 0) {
        printf("bad ip address %s\n", *argv);
        return -2;
    }
    return 0;
}

static void send_packet(void)
{
    if (!buf) {
        buf = xmalloc(size + ICMP_HDR_SZ);
    }
    struct icmp *icmp_hdr = (struct icmp *)buf;
    static int first = 1;
    if (first) {
        printf("PING "IPFMT" %d(%d) bytes of data\n",
            ipfmt(ip_addr),
            ipfmt(ip_addr),
            (int)(size + ICMP_HDR_SZ + IP_HDR_SZ));
        first = 0;
    }
    memset(icmp_hdr->icmp_data, 'x', size);
    icmp_hdr->icmp_type = ICMP_T_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_hun.echo.id = _htons(id);
    icmp_hdr->icmp_hun.echo.seq = _htons(seq);
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = icmp_chksum((unsigned short *)icmp_hdr, ICMP_HDR_SZ + size);
    seq++;
    _send(sock, buf, ICMP_HDR_SZ + size, &sk_addr);
    psend++;
}

static void sigalrm(int num)
{
    send_packet();
}

void ping(int argc, char **argv)
{
    int err;
    init_options();
    if ((err = parse_args(argc, argv)) < 0) {
        if (err == -1) {
            usage();
        }
        return;
    }

    signal(SIGALRM, sigalrm);
}
