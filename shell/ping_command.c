#include "ether.h"
#include "lib.h"
#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "route.h"
#include <bits/getopt_core.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern unsigned int net_debug;

static unsigned short id = 0;
static unsigned short seq;
static int size;
static int count;
static int finited;
static int ttl;
static unsigned int ip_addr;

static void usage(void)
{
    printf(
        "Usage: ping [OPTIONS] ipaddr\n"
        "OPTIONS:\n"
        "       -s size     icmp echo size\n"
        "       -c count    times(not implemented)\n"
        "       -t ttl      time to live\n"
    );
}

static int parse_args(int argc, char **argv)
{
    int c;
    for (c = 0; c < argc; ++c) {
        printf("%s ", argv[c]);
    }
    printf("\n");
    if (argc < 2) {
        return -1;
    }

    size = 56;
    finited = 0;
    count = 0;
    ttl = 64;
    ip_addr = 0;
    id++;
    seq = 0;

    optind = 0;
    opterr = 0;
    while ((c = getopt(argc, argv, "s:t:c:?h")) != -1) {
        switch (c) {
            case 's':
                size = atoi(optarg);
                break;
            case 'c':
                count = atoi(optarg);
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
    if (finited && count < 2) {
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
    struct pkbuf *pkb;
    struct icmp *icmp_hdr;
    struct ip *ip_hdr;

    pkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + ICMP_HDR_SZ + size);
    ip_hdr = pkb2ip(pkb);
    icmp_hdr = (struct icmp *)ip_hdr->ip_data;

    memset(icmp_hdr->icmp_data, 'x', size);
    icmp_hdr->icmp_type = ICMP_T_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_hun.echo.id = _htons(id);
    icmp_hdr->icmp_hun.echo.seq = _htons(++seq);
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = icmp_chksum((unsigned short *)icmp_hdr, ICMP_HDR_SZ + size);
    printf(IPFMT" send to "IPFMT" id %d seq %d ttl %d\n",
            ipfmt(veth->net_ipaddr),
            ipfmt(ip_addr),
            id,
            _ntohs(icmp_hdr->icmp_seq),
            ttl);
    ip_send_info(pkb, 0, IP_HDR_SZ + ICMP_HDR_SZ + size,
            ttl, IP_P_ICMP, ip_addr);
}

extern void signal_wait(int signum);
void sigalrm(int num)
{
    if (!finited || count < 0) {
        count--;
        alarm(1);
        send_packet();
    }
    signal_wait(SIGQUIT);
}

void ping2(int argc, char **argv)
{
    int err;
    if ((err = parse_args(argc, argv)) < 0) {
        if (err == -1) {
            usage();
        }
        return;
    }
    signal(SIGALRM, sigalrm);
    // net_debug |= NET_DEBUG_ARP|NET_DEBUG_IP|NET_DEBUG_ICMP;
    sigalrm(SIGALRM);
    alarm(0);
    // net_debug = 0;
    printf("\n");
}