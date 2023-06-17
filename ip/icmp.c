#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "lib.h"

static void icmp_echo_reply(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_drop_reply(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_dest_unreach(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_redirect(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static struct icmp_desc icmp_table[ICMP_T_MAXNUM + 1] = {
    [ICMP_T_ECHOREPLY] = {
        .error = 0,
        .handler = icmp_echo_reply,
    },
    [ICMP_T_DUMMY_1] = ICMP_DESC_DUMMY_ENTRY,
    [ICMP_T_DUMMY_2] = ICMP_DESC_DUMMY_ENTRY,
    [ICMP_T_UNREACH] = {
        .error = 1,
        .handler = icmp_dest_unreach,
    },
    [ICMP_T_SOURCEQUENCH] = {
        .error = 1,
        .info = "icmp source quench",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_REDIRECT] = {
        .error = 1,
        .info = "icmp redirect",
        .handler = icmp_redirect,
    },
    [ICMP_T_DUMMY_6] = ICMP_DESC_DUMMY_ENTRY,
    [ICMP_T_DUMMY_7] = ICMP_DESC_DUMMY_ENTRY,

    
};

/*
    目标不可达
    @icmp_desc:  icmp描述符
    @pkb:        收到的icmp报文
*/
static void icmp_dest_unreach(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    icmpdbg("dest unreach");
    free_pkb(pkb);
}

/* ICMP重定向报文信息 */
static const char *redirectstr[4] = {
    [ICMP_REDIRECT_NET] = "net redirect",
    [ICMP_REDIRECT_HOST] = "host redirect",
    [ICMP_REDIRECT_TOSNET] = "net redirect for TOS",
    [ICMP_REDIRECT_TOSHOST] = "host redirect for TOS"
};

static void icmp_redirect(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct icmp *icmp_hdr = ip2icmp(ip_hdr);
    if (icmp_hdr->icmp_code > 4)
        icmp_dbg("Redirect code %d is error", icmp_hdr->icmp_code);
    else
        icmpdbg("from " IPFMT " %s(new nexthop " IPFMT ")",
                ipfmt(ip_hdr->ip_src),
                redirectstr[icmp_hdr->icmp_code],
                ipfmt(icmp_hdr->icmp_gw));
    free_pkb(pkb);
}

/*
    icmp回复报文
    @icmp_desc:  icmp描述符
    @pkb:        收到的icmp报文
*/
static void icmp_echo_reply(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct icmp *icmp_hdr = ip2icmp(ip_hdr);
    icmpdbg("from "IPFMT" id %d seq %d ttl %d",
            ipfmt(ip_hdr->ip_src),
            _ntohs(icmp_hdr->icmp_id),
            _ntohs(icmp_hdr->icmp_seq),
            ip_hdr->ip_ttl);
    free_pkb(pkb);
}

/*
    icmp请求报文
    @icmp_desc:  icmp描述符
    @pkb:        收到的icmp报文
*/
static void icmp_echo_request(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct icmp *icmp_hdr = ip2icmp(ip_hdr);
    icmpdbg("echo request data %d bytes icpm_id %d icmp_seq %d",
            (int)(ip_hdr->ip_len - iphlen(ip_hdr) - ICMP_HDR_SZ),
            _ntohs(icmp_hdr->icmp_id),
            _ntohs(icmp_hdr->icmp_seq));
    if (icmp_hdr->icmp_code) {
        icmpdbg("echo request packet corrupted");
        free_pkb(pkb);
        return;
    }
    icmp_hdr->icmp_type = ICMP_T_ECHO;
    if (icmp_hdr->icmp_cksum >= 0xffff - ICMP_T_ECHO)
        icmp_hdr->icmp_cksum += ICMP_T_ECHO + 1;
    else
        icmp_hdr->icmp_cksum + ICMP_T_ECHO;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hton(ip_hdr);
    pkb->pk_indev = NULL;
    pkb->pk_type = PKT_NONE;
    
}

static void icmp_drop_reply(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct icmp *icmp_hdr = ip2icmp(ip_hdr);
    icmpdbg("icmp type %d code %d (droped)",
            icmp_hdr->icmp_type,
            icmp_hdr->icmp_code);
    if (icmp_desc->info)
        icmpdbg("%s", icmp_desc->info);
    free_pkb(pkb);
}

void icmp_in(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct icmp *icmp_hdr = ip2icmp(ip_hdr);
    int icmp_len, type;
    icmp_len = ipdlen(ip_hdr);
    /* 检查报文是否符合规范 */
    icmpdbg("%d bytes", icmp_len);
    if (icmp_len < ICMP_HDR_SZ) {
        icmp_dbg("icmp header is too small");
        goto drop_pkb;
    }
    /* 检查校验和 */
    if (icmp_chksum((unsigned short *)icmp_hdr, icmp_len) != 0) {
        icmp_dbg("icmp header checksum error");
        goto drop_pkb;
    }

    type = icmp_hdr->icmp_type;
    if (type > ICMP_T_MAXNUM) {
        icmp_dbg("unknown icmp type %d code %d",
                    type, icmp_hdr->icmp_code);
        goto drop_pkb;
    }


drop_pkb:
    free_pkb(pkb);
}