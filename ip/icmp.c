#include "ether.h"
#include "list.h"
#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "lib.h"
#include <string.h>

static void icmp_echo_reply(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_drop_reply(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_dest_unreach(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_redirect(struct icmp_desc *icmp_desc, struct pkbuf *pkb);
static void icmp_echo_request(struct icmp_desc *icmp_desc, struct pkbuf *pkb);

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
    [ICMP_T_ECHO] = {
        .error = 0,
        .handler = icmp_echo_request,
    },
    [ICMP_T_ROUTERADVERT] = ICMP_DESC_DUMMY_ENTRY,
    [ICMP_T_ROUTERSOLICIT] = ICMP_DESC_DUMMY_ENTRY,
    [ICMP_T_TIMXCEED] = {
        .error = 1,
        .info = "icmp time exceeded",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_PARAMPROB] = {
        .error = 1,
        .info = "icmp parameter problem",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_TSTAMP] = {
        .error = 1,
        .info = "icmp timestamp request",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_TSTAMPREPLY] = {
        .error = 1,
        .info = "icmp timestamp reply",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_IREQ] = {
        .error = 1,
        .info = "icmp infomation request",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_IREQREPLY] = {
        .error = 1,
        .info = "icmp infomation reply",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_AMREQ] = {
        .error = 1,
        .info = "icmp address mask request",
        .handler = icmp_drop_reply,
    },
    [ICMP_T_AMREQREPLY] = {
        .error = 1,
        .info = "icmp address mask reply",
        .handler = icmp_drop_reply,
    }
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

/*
    icmp重定向
    @icmp_desc: icmp_desc结构体
    @pkb: 收到的报文
*/
static void icmp_redirect(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct icmp *icmp_hdr = ip2icmp(ip_hdr);
    if (icmp_hdr->icmp_code > 4)
        icmpdbg("Redirect code %d is error", icmp_hdr->icmp_code);
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
    处理icmp请求报文
    @icmp_desc:  icmp描述符
    @pkb:        收到的icmp报文
*/
static void icmp_echo_request(struct icmp_desc *icmp_desc, struct pkbuf *pkb)
{
    /*
        这里处理请求报文时
        生成的回复报文只是简单将type设置为ICMP_T_ECHOREPLY
        然后重新设置校验值并回复回去
    */
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
    // 将icmp_type设置为echo reply
    icmp_hdr->icmp_type = ICMP_T_ECHOREPLY;
    // 
    if (icmp_hdr->icmp_cksum >= 0xffff - ICMP_T_ECHO)
        icmp_hdr->icmp_cksum += ICMP_T_ECHO + 1;
    else
        icmp_hdr->icmp_cksum += ICMP_T_ECHO;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hton(ip_hdr);
    pkb->pk_rtdst = NULL;
    pkb->pk_indev = NULL;
    pkb->pk_type = PKT_NONE;
    ip_send_out(pkb);
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
        icmpdbg("icmp header is too small");
        goto drop_pkb;
    }
    /* 检查校验和 */
    if (icmp_chksum((unsigned short *)icmp_hdr, icmp_len) != 0) {
        icmpdbg("icmp header checksum error");
        goto drop_pkb;
    }

    type = icmp_hdr->icmp_type;
    if (type > ICMP_T_MAXNUM) {
        icmpdbg("unknown icmp type %d code %d",
                    type, icmp_hdr->icmp_code);
        goto drop_pkb;
    }
    icmp_table[type].handler(&icmp_table[type], pkb);
    return;
drop_pkb:
    free_pkb(pkb);
}

void icmp_send(unsigned char type, unsigned char code,
        unsigned int data, struct pkbuf *pkb_in)
{
    struct pkbuf *pkb;
    struct ip *ip_hdr = pkb2ip(pkb_in);
    struct icmp *icmp_hdr;
    int pay_len = _ntohs(ip_hdr->ip_len);
    if (pay_len < iphlen(ip_hdr) + 8)
        return;
    // 如果这个pkb原来不是发送给我们的,不发送
    if (pkb_in->pk_type != PKT_LOCALHOST)
        return;
    // 如果目标IP地址是广播或者组播地址,不发送
    if (MULTICAST(ip_hdr->ip_dst) || BROADCAST(ip_hdr->ip_dst))
        return;
    // 当pkb报文是分片报文时(除了第一个分片报文)，不发送
    if (ip_hdr->ip_fragoff & _htons(IP_FRAG_OFF))
        return;
    
    // 如果type是错误的,且pkb是icmp报文
    if (icmp_type_error(type) && ip_hdr->ip_pro == IP_P_ICMP){
        icmp_hdr = ip2icmp(ip_hdr);
        if (icmp_hdr->icmp_type > ICMP_T_MAXNUM || icmp_error(icmp_hdr))
            return;
    }

    /* 开始组装并发送icmp报文 */
    // 这里pay_len必须小于576是因为RFC 791规定所有主机必须能接收至少576字节的IP数据包
    // 所以为了最大可能保证icmp报文能够到达对方,pay_len必须小于576
    if ( IP_HDR_SZ + ICMP_HDR_SZ + pay_len > 576 )
        pay_len = 576 - IP_HDR_SZ - ICMP_HDR_SZ;
    pkb = alloc_pkb(ETH_HDR_SZ + IP_HDR_SZ + ICMP_HDR_SZ + pay_len);
    icmp_hdr = (struct icmp *)(pkb2ip(pkb)->ip_data);
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_undata = data;
    memcpy(icmp_hdr->icmp_data, (unsigned char *)ip_hdr, pay_len);
    icmp_hdr->icmp_cksum = icmp_chksum((unsigned short *)icmp_hdr, ICMP_HDR_SZ + pay_len);
    icmpdbg("to "IPFMT"(payload %d) [type %d code %d]\n",
        ipfmt(ip_hdr->ip_src), pay_len, type, code);
}
