#include "netif.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "lib.h"

void ip_recv_local(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);

    if (ip_hdr->ip_fragoff & ( IP_FRAG_OFF | IP_FRAG_MF)) {
        if(ip_hdr->ip_fragoff & IP_FRAG_DF) {
            ipdbg("error fragment");
            free_pkb(pkb);
            return;
        }
        pkb = ip_reass(pkb);
        if(!pkb)
            return;
        ip_hdr = pkb2ip(pkb);
    }
}

/*
    网络层路由转发
    @pkb:   收到的以太网帧
*/
void ip_recv_route(struct pkbuf *pkb)
{
    ip_recv_local(pkb);
}

/*
    网络层入口
    @dev:   网络设备
    @pkb:   收到的以太网帧
*/
void ip_in(struct netdev *dev, struct pkbuf *pkb)
{
    struct ether *ethhdr = (struct ethhdr *)pkb->pk_data;
    struct ip *iphdr = (struct ip *)ethhdr->eth_data;
    int hlen;
    /* 检查报文的标志 */
    if (pkb->pk_type == PKT_OTHERHOST) {
        ipdbg("ip(l2) packet is not for us");
        goto err_free_pkb;
    }
    /* 检查报文长度 */
    if (pkb->pk_len < ETH_HRD_SZ + IP_HDR_SZ) {
        ipdbg("ip packet length is too small");
        goto err_free_pkb;
    }
    /* 检查IP版本 */
    if (ipver(iphdr) != IP_VERSION_4) {
        ipdbg("ip packet not is ipv4");
        goto err_free_pkb;
    }

    /* 检查IP头部长度字段 */
    hlen = iphlen(iphdr);
    if (hlen < IP_HDR_SZ) {
        ipdbg("ip header is too small");
        goto err_free_pkb;
    }

    /* 检查头部校验值 */
    if (ip_chksum((unsigned short *)iphdr, hlen) != 0) {
        ipdbg("ip header checksum error");
        goto err_free_pkb;
    }

    ip_ntoh(iphdr);
    /* 再次检查头部相关长度字段 */
    if (iphdr->ip_len < hlen ||
        pkb->pk_len < ETH_HRD_SZ + iphdr->ip_len) {
        ipdbg("ip packet length is too small");
        goto err_free_pkb;
    }

    /*
        网络包进来时,申请的内存大小为mtu+以太网头部
        这里重新调整内存大小,使其为ip数据包的大小
        减少内存的浪费
    */
    if (pkb->pk_len > ETH_HRD_SZ + iphdr->ip_len) {
        pkb_trim(pkb, ETH_HRD_SZ + iphdr->ip_len);
    }
    ipdbg(IPFMT " -> " IPFMT "(%d/%d bytes)",
            ipfmt(iphdr->ip_src), ipfmt(iphdr->ip_dst),
            hlen, iphdr->ip_len);
    
    ip_recv_route(pkb);
    return;
err_free_pkb:
    free_pkb(pkb);
}