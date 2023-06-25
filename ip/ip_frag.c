#include "netif.h"
#include "ether.h"
#include "ip.h"
#include "icmp.h"

#include "lib.h"
#include "list.h"
#include "netcfg.h"

/* 分片链表的头节点 */
static LIST_HEAD(frag_head);

/*
    检查分片是否完整
    @frag:  分片
    返回值: 1表示分片完整,0表示分片不完整
*/
static inline int full_frag(struct ip_frag *frag)
{
    return (((frag->frag_flags & FRAG_FL_IN) == FRAG_FL_IN) && 
        (frag->frag_rsize == frag->frag_size));
}

/*
    检查分片是否已经接收完毕
    @frag:  分片
    返回值和full_frag()函数相同,但是不检查分片是否已经重组完毕
*/
static inline int complete_frag(struct ip_frag *frag)
{
    return frag->frag_flags & FRAG_COMPLETE;
}

/*
    创建一个新的IP分片
    @iphdr: IP首部
*/
struct ip_frag *new_frag(struct ip *iphdr)
{
    struct ip_frag *frag;
    frag = xmalloc(sizeof(*frag));
    frag->frag_ttl = FRAG_TIME;                 // 设置分片的超时时间
    frag->frag_id = iphdr->ip_id;               // 设置分片的标识
    frag->frag_src = iphdr->ip_src;
    frag->frag_dst = iphdr->ip_dst;
    frag->frag_pro = iphdr->ip_pro;             // 设置分片的协议类型
    frag->frag_hlen = 0;
    frag->frag_size = 0;
    frag->frag_rsize = 0;
    frag->frag_flags = 0;
    /*
        这里是两个链表
        一个链表是分片链表,用于管理所有的分片,这个链表的头节点是frag_head,后面的成员是各个分片的头节点
        另一个链表是pkb链表,用于管理分片的pkb,这个链表的头节点是frag_pkb,后面的成员是各个分片的pkb
    */
    list_add(&frag->frag_list, &frag_head);     // 将分片添加到分片头链表中
    list_init(&frag->frag_pkb);                 // 初始化分片的pkb链表
    return frag;
}

/*
    删除分片链表
    @frag:  分片头节点
*/
void delete_frag(struct ip_frag *frag)
{
    struct pkbuf *pkb;

    list_del(&frag->frag_list);                 // 从分片链表中删除分片
    while (!list_empty(&frag->frag_pkb)) {      //轮询分片链表的每一个pkb    
        pkb = frag_head_pkb(frag);
        list_del(&pkb->pk_list);                // 从分片的pkb链表中删除pkb
        free(pkb);
    }
    free(frag);                                 // 最后删除分片头节点
}

/*
    重组分片
    @frag:  分片头节点
    返回值: 重组成功返回重组后的IP数据包,重组失败返回NULL
*/
struct pkbuf *reass_frag(struct ip_frag *frag)
{
    struct pkbuf *pkb, *frag_pkb;
    struct ip *frag_hdr;
    unsigned char *p;
    int hlen, len;

    pkb = NULL;
    hlen = frag->frag_hlen;
    len = frag->frag_hlen + frag->frag_size;   // 获取重组后的IP数据包长度
    if (len > 65535) {
        ipdbg("reassembled packet oversize(%d/%d)", hlen, len);
        goto out;
    }
    /* 获取第一个分片的pkb和ip报文 */
    frag_pkb = list_first_entry(&frag->frag_pkb, struct pkbuf, pk_list);
    frag_hdr = pkb2ip(frag_pkb);

    /* 利用第一个分片的pkb,初始化一个重组后的pkb,后面所有分片的数据部分都会复制到这个pkb中 */
    pkb = alloc_pkb(ETH_HRD_SZ + len);
    pkb->pk_protocol = ETH_P_IP;
    p = pkb->pk_data;
    /* 将第一个分片的以太网头部和IP头部 复制 到重组后的pkb */
    memcpy(p, frag_pkb->pk_data, ETH_HRD_SZ + hlen);
    /* 因为重组后的报文是一个完整的IP报文,所以不存在分片,所以偏移量设置为0 */
    pkb2ip(pkb)->ip_fragoff = 0;
    pkb2ip(pkb)->ip_len = len;

    p += ETH_HRD_SZ + hlen;
    list_for_each_entry(frag_pkb, &frag->frag_pkb, pk_list) {
        frag_hdr = pkb2ip(frag_pkb);
        /* 上面已经复制过以太网头部和IP头部了,所以这里只复制data部分 */
        memcpy(p, (char *)frag_hdr + hlen, frag_hdr->ip_len - hlen);
        p += frag_hdr->ip_len - hlen;
    }
    ipdbg("resassembly success(%d/%d bytes)", hlen, len);
out:
    delete_frag(frag);
    return pkb;
}

/*
    将分片插入链表
    @pkb:   分片的pkb
    @frag:  分片头节点
*/
int insert_frag(struct pkbuf *pkb, struct ip_frag *frag)
{
    struct pkbuf *frag_pkb;
    struct ip *ip_hdr, *frag_hdr;
    struct list_head *pos;
    int off, hlen;

    if (complete_frag(frag)) {
        ipdbg("extra fragment for complete reassembled packet");
        goto frag_drop;
    }

    ip_hdr = pkb2ip(pkb);
    off = ipoff(ip_hdr);
    hlen = iphlen(ip_hdr);

    /* 如果pkb是最后一个分片 */
    if ((ip_hdr->ip_fragoff & IP_FRAG_MF) == 0) {
        /* 判断分片链表的标志位,最后一个分片是否已经收到 */
        if (frag->frag_flags & FRAG_LAST_IN) {
            ipdbg("extra fragment for last fragment");
            goto frag_drop;
        }
        frag->frag_flags |= FRAG_LAST_IN;
        frag->frag_size = off + ip_hdr->ip_len - hlen;
        pos = frag->frag_pkb.prev;
        goto frag_out;
    }

    /* 如果是中间的分片 */
    pos = &frag->frag_pkb;
    list_for_each_entry_reverse(frag_pkb, &frag->frag_pkb, pk_list) {
        frag_hdr = pkb2ip(frag_pkb);
        if (off == ipoff(frag_hdr)) {
            ipdbg("reduplicate ip fragment");
            goto frag_drop;
        }
        if (off > ipoff(frag_hdr)) {
            pos = &frag_pkb->pk_list;
            goto frag_found;
        }
    }

    frag_hdr = NULL;

frag_found:
    if (frag->frag_hlen && frag->frag_hlen != hlen) {
        ipdbg("error ip fragment for header length");
        goto frag_drop;
    } else {
        frag->frag_hlen = hlen;
    }

    if (frag_hdr && (ipoff(frag_hdr) + frag_hdr->ip_len - hlen > off)) {
        ipdbg("error ip fragment for offset");
        goto frag_drop;
    }

    if (off == 0)
        frag->frag_flags |= FRAG_FIRST_IN;

frag_out:
    list_add(&pkb->pk_list, pos);
    frag->frag_rsize += ip_hdr->ip_len - hlen;
    if (full_frag(frag))
        frag->frag_flags |= FRAG_COMPLETE;
    return 0;

frag_drop:
    free_pkb(pkb);
    return -1;
}

/*
    查找分片(在分片头节点链表中查找)
    @ip_hdr: IP首部
    返回值: 未找到返回NULL,找到返回分片头节点
*/
struct ip_frag *lookup_frag(struct ip *ip_hdr)
{
    struct ip_frag *frag;
    list_for_each_entry(frag, &frag_head, frag_list)
        if (frag->frag_id == ip_hdr->ip_id &&
            frag->frag_src == ip_hdr->ip_src &&
            frag->frag_dst == ip_hdr->ip_dst &&
            frag->frag_pro == ip_hdr->ip_pro)
            return frag;
    return NULL;
}

/*
    IP重组报文入口
    @pkb: 收到的报文
*/
struct pkbuf *ip_reass(struct pkbuf *pkb)
{
    struct ip *ip_hdr = pkb2ip(pkb);
    struct ip_frag *frag;

    ipdbg("ID:%d RS:%d DF:%d MF:%d OFF:%d bytes size:%d bytes",
		ip_hdr->ip_id,
		(ip_hdr->ip_fragoff & IP_FRAG_RS) ? 1 : 0,
		(ip_hdr->ip_fragoff & IP_FRAG_DF) ? 1 : 0,
		(ip_hdr->ip_fragoff & IP_FRAG_MF) ? 1 : 0,
		ipoff(ip_hdr),
		ip_hdr->ip_len);
    /* 在分片链表中查找,查看是否已经有此IP报文的分片进来 */
    frag = lookup_frag(ip_hdr);
    /* 如果没有找到,就新建分片链表 */
    if (frag == NULL)
        frag = new_frag(ip_hdr);
    /* 将收到的这一片报文插入到分片链表中的pkb链表 */
    if (insert_frag(pkb, frag) < 0)
        return NULL;
    /* 如果报文已经完整,则重组报文 */
    if (complete_frag(frag))
        pkb = reass_frag(frag);
    else
        pkb = NULL;
    return pkb;
}

/*
    通过一些参数从一个完整的IP报文中获取指定的IP分片
    @pkb:    待分片的报文
    @orig:   原始IP首部
    @hlen:   原始IP首部长度
    @dlen:   原始IP数据部分长度
    @off:    分片偏移
    @mf_bit: 分片标志位
*/
struct pkbuf *ip_frag(struct pkbuf *pkb, struct ip *orig, int hlen,
                int dlen, int off, unsigned short mf_bit)
{
    struct pkbuf *frag_pkb;
    struct ip *frag_hdr;

    frag_pkb = alloc_pkb(ETH_HRD_SZ + hlen + dlen);

    frag_pkb->pk_protocol = pkb->pk_protocol;
    frag_pkb->pk_type = pkb->pk_type;
    frag_pkb->pk_indev = pkb->pk_indev;
    frag_pkb->pk_rtdst = pkb->pk_rtdst;
    frag_hdr = pkb2ip(frag_pkb);
    /* 复制IP头 */
    memcpy(frag_hdr, orig, hlen);
    /* 复制数据部分 */
    memcpy((void *)frag_hdr + hlen, (void *)orig + hlen + off, dlen);
    frag_hdr->ip_len = _htons(hlen + dlen);
    mf_bit |= (off >> 3);
    frag_hdr->ip_fragoff = _htons(mf_bit);
    ip_set_checksum(frag_hdr);
    return frag_pkb;
}

/*
    将网络层报文分片发送出去
    @dev: 网络接口
    @pkb: 报文
*/
void ip_send_frag(struct netdev *dev, struct pkbuf *pkb)
{
    struct pkbuf *frag_pkb;
    struct ip *ip_hdr;
    int dlen, hlen, mlen, off;

    ip_hdr = pkb2ip(pkb);
    hlen = iphlen(ip_hdr);
    dlen = _ntohs(ip_hdr->ip_len) - hlen;
    // IP分片偏移需要进行8字节对齐,这里& ~7意思就是最后三位置0,保证mlen是8的整数倍
    mlen = (dev->net_mtu - hlen) & ~7;
    off = 0;
    while (dlen > mlen) {
        ipdbg(" [f] ip frag: off %d hlen %d dlen %d",off, hlen, mlen);
        frag_pkb = ip_frag(pkb, ip_hdr, hlen, mlen, off, IP_FRAG_MF);
        ip_send_dev(dev, frag_pkb);

        dlen -= mlen;
        off += mlen;
    }
    if (dlen) {
        ipdbg(" [f] ip frag: off %d hlen %d dlen %d", off, hlen, dlen);
        /*
            ip_hdr是一个完整的大的报文,所以ip_fragoff为0
            所以ip_hdr->ip_fragoff & IP_FRAG_MF也为0
            表示这是最后一片
        */
        frag_pkb = ip_frag(pkb, ip_hdr, hlen, dlen, off,
                     ip_hdr->ip_fragoff & IP_FRAG_MF);
        ip_send_dev(dev, frag_pkb);
    }
    free_pkb(pkb);
}

void ip_timer(int delay)
{
    struct ip_frag *frag, *__safe_frag;
    list_for_each_entry_safe(frag, __safe_frag, &frag_head, frag_list) {
        if (full_frag(frag))
            continue;
        frag->frag_ttl -= delay;
        if (frag->frag_ttl < 0) {
            struct pkbuf *pkb = frag_head_pkb(frag);
            ip_hton(pkb2ip(pkb));
            icmp_send(ICMP_T_TIMXCEED, ICMP_EXC_FRAGTIME, 0, pkb);
            delete_frag(frag);
        }
    }
}
