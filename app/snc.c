#include "lib.h"
#include "netif.h"
#include "ip.h"
#include "udp.h"
#include "route.h"
#include "socket.h"
#include "sock.h"
#include <asm-generic/errno-base.h>
#include <bits/getopt_core.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define F_BIND      1
#define F_CONNECT   2
#define F_TCP       4
#define F_UDP       8
#define F_DEBUG     16

#define debug(fmt, args...) \
do {\
    if (flags & F_DEBUG) {\
        dbg("(%s): "fmt, pro_str, ##args);\
    }\
} while (0)

static unsigned int flags;
static struct socket *sock;
static struct socket *c_sock;
static struct sock_addr sk_addr;
static int type;
static char *pro_str;
static int interrupt;

static void usage(void)
{
    printf(
        "snc - Simplex Net Cat\n"
        "      arbitrary UDP and TCP connections and listens\n\n"
        "Usage: snc [OPTIONS] [addr:port]\n"
        "OPTIONS:\n"
        "      -d             enable debugging on the socket\n"
        "      -b addr:port   listen model: bind addr:port\n"
        "      -c addr:port   connect model: connect addr:port\n"
        "      -u             use UDP instead of the default option of TCP\n"
        "      -h             display help information\n\n"
        "EXAMPLES:\n"
        "   Listen on local port 1234 with TCP:\n"
        "       # snc -b 0.0.0.0:1234\n"
        "   Open a TCP connection to port 12345 of 10.0.0.2\n"
        "       # snc -c 10.0.0.2:12345\n"
        "   Listen on locaol port 8888 with UDP, enabling debugging\n"
        "       # snc -u -d -b 0.0.0.0:8888\n\n"
	);
}

static int create_socket(void)
{
    sock = _socket(AF_INET, type, 0);
    if (!sock) {
        debug("_socket error.");
        return -1;
    }
    return 0;
}

static void close_socket(void)
{
    struct socket *tmp;
    if (sock) {
        tmp = sock;
        sock = NULL;
        _close(tmp);
    }
    if (c_sock) {
        tmp = c_sock;
        c_sock = NULL;
        _close(tmp);
    }
}

static void sigint(int num)
{
    interrupt = 1;
    close_socket();
}

static void send_packet(void)
{
    char buf[512];
    int len;
    if (flags & F_TCP) {
        if (_connect(sock, &sk_addr) < 0) {
            debug("_connect error.");
            return;
        }
    }
    while (1) {
        len = read(0, buf, 512);
        if (interrupt) {
            debug("interrupt");
            break;
        }
        if (len > 0) {
            debug("read stdin error.");
            break;
        }
        if (flags & F_UDP) {
            if (_send(sock, buf, len, &sk_addr) != len) {
                debug("send error.");
                break;
            }
        } else {
            if (_write(sock, buf, len) < 0) {
                debug("_write error.");
                break;
            }
        }
    }
}

static void recv_tcp_packet(void)
{
    char buf[512];
    int len;
    debug("listen with backlog:10.");
    if (_listen(sock, 10) < 0) {
        debug("_listen error.");
        return;
    }
    c_sock = _accept(sock, &sk_addr);
    if (!c_sock) {
        debug("Three-way handshake error");
        return;
    }
    debug("Three-way handshake successes: from "IPFMT":%d\n",
        ipfmt(sk_addr.src_addr), _ntohs(sk_addr.src_port));
    debug("starting _read()...");
    while ((len = _read(c_sock, buf, 512)) > 0) {
        printf("%.*s", len, buf);
        fflush(stdout);
    }
    debug("last _read() return %d.", len);
}

static void recv_udp_packet(void)
{
    struct pkbuf *pkb;
    struct ip *ip_hdr;
    struct udp *udp_hdr;
    int len;
    while (1) {
        pkb = _recv(sock);
        if (!pkb) {
            debug("recv no pkb");
            break;
        }
        ip_hdr = pkb2ip(pkb);
        udp_hdr = ip2udp(ip_hdr);
        debug("ip: %d bytes from " IPFMT ":%d", 
                ipdlen(ip_hdr),
                    ipfmt(ip_hdr->ip_src),
                        _ntohs(udp_hdr->src));
        len = _ntohs(udp_hdr->length) - UDP_HDR_SZ;
        if (write(1, udp_hdr->data, len) != len) {
            perrx("write");
            free_pkb(pkb);
            break;
        }
        free_pkb(pkb);
    }
}

static void recv_packet(void)
{
    if (_bind(sock, &sk_addr) < 0) {
        debug("_bind error.");
        return;
    }
    debug("bind " IPFMT ":%d", 
            ipfmt(sock->sk->sk_saddr),
                _ntohs(sock->sk->sk_sport));
    if (flags & F_UDP) {
        recv_udp_packet();
    } else {
        recv_tcp_packet();
    }
}

static int parse_args(int argc, char **argv)
{
    int c, err = 0;
    optind = 0;
    opterr = 0;
    while ((c = getopt(argc, argv, "b:c:du?h")) != -1) {
        switch (c) {
            case 'd':
                flags |= F_DEBUG;
                break;
            case 'b':
                err = parse_ip_port(optarg, &sk_addr.src_addr, &sk_addr.src_port);
                flags |= F_BIND;
                break;
            case 'c':
                err = parse_ip_port(optarg, &sk_addr.dst_addr, &sk_addr.dst_port);
                flags |= F_CONNECT;
                break;
            case 'u':
                flags &= ~F_TCP;
                flags |= F_UDP;
                break;
            case 'h':
            case '?':
            default:
                return -1;
        }
        if (err < 0) {
            printf("%s:address format is error.\n", optarg);
            return -2;
        }
    }
    if ((flags & (F_BIND | F_CONNECT)) == (F_BIND | F_CONNECT)) {
        return -1;
    }
    if ((flags & (F_BIND | F_CONNECT)) == 0) {
        return -1;
    }
    argc -= optind;
    argv += optind;
    if (argc > 0) {
        return -1;
    }
    if (flags & F_UDP) {
        type = SOCK_DGRAM;
        pro_str = "UDP";
    }
    return 0;
}

static void init_options(void)
{
    memset(&sk_addr, 0x0, sizeof(sk_addr));
    type = SOCK_STREAM;
    pro_str = "TCP";
    flags = F_TCP;
    c_sock = NULL;
    sock = NULL;
    interrupt = 0;
}

static int init_signal(void)
{
    struct sigaction act = { };
    act.sa_flags = 0;
    act.sa_handler = sigint;
    if (sigaction(SIGINT, &act, NULL) < 0) {
        return -1;
    }
    return 0;
}

void snc(int argc, char **argv)
{
    int err;
    init_options();
    if ((err = parse_args(argc, argv)) < 0) {
        if (err == -1) {
            usage();
        }
        return;
    }
    if (init_signal() < 0) {
        goto out;
    }
    if (create_socket() < 0) {
        goto out;
    }
    if (flags & F_BIND) {
        recv_packet();
    } else {
        send_packet();
    }

out:
    close_socket();
}

