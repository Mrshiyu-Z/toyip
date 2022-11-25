#include "list.h"
#include "eth.h"
#include "net.h"
#include "ip.h"

static LIST_HEAD(frag_head); //不同分片链表的头节点组成的链表

static inline int full_frag(struct fragment *frag)
{
    /*
    * 判断分片是否收取完整
    * 当第一个分片到达时,(frag->frag_flags |= 0x0002) == 0x0002
    * 当最后一个分片到达时,(frag->frag_flags |= 0x0004) == 0x0006 (二进制 或等 计算)
    */
    return (((frag->frag_flags & FRAG_FL_IN) == FRAG_FL_IN) && 
            (frag->frag_rec_size == frag->frag_size));
}

/* 判断分片是否完整 */
static inline int complete_frag(struct fragment *frag)
{
    return frag->frag_flags & FRAG_COMPLETE;
}

/* 删除分片队列 */
void delete_frag(struct fragment *frag)
{
    struct pkg_buf *pkg;
    /* 从分片的头节点链表中删除 */
    list_del(&frag->frag_list);
    /* 删除分片队列 */
    while (!list_empty(&frag->frag_pkg)){
        pkg = list_first_node(&frag->frag_pkg, struct pkg_buf, list);
        list_del(&pkg->list);
        printf("pkg_delete: %p\n", pkg);
        free_pkg(pkg);
    }
    /* 删除分片 */
    free(frag);
}

struct pkg_buf *reass_frag(struct fragment *frag)
{
    struct pkg_buf *pkg, *frag_pkg;
    struct ip_hdr *frag_ip;
    unsigned char *p;
    int hlen, len;
    pkg = NULL;
    hlen = frag->frag_hlen;
    len = frag->frag_hlen + frag->frag_size;
    /* 重组后的包太大 */
    if (len > 65535) {
        goto out;
    }
    /* 获取第一个IP分片 */
    frag_pkg = list_first_node(&frag->frag_pkg, struct pkg_buf, list);
    frag_ip = pkg_2_iphdr(frag_pkg);
    /* 分配一个包 */
    pkg = pkg_alloc(ETH_HDR_LEN + len);
    pkg->pkg_pro = ETH_TYPE_IP;
    p = pkg->data;

    /* 复制以太网头 */
    memcpy(p, frag_pkg->data, ETH_HDR_LEN + hlen);
    /* 因为是组装成一个IP包,所以ip_offlags赋值为0 */
    pkg_2_iphdr(pkg)->ip_offlags = 0;
    pkg_2_iphdr(pkg)->ip_len = htons(len);
    /* p指针移动到IP包的data地址 */
    p += ETH_HDR_LEN + hlen;
    /* 轮询每个IP分片 */
    list_for_each_node(frag_pkg, &frag->frag_pkg, list){
        printf("frag_pkg: %p, frag_ip_len: %d\n", frag_pkg, htons(frag_ip->ip_len));
        frag_ip = pkg_2_iphdr(frag_pkg);
        /* 复制每个IP分片的数据部分 */
        memcpy(p, (char *)frag_ip + hlen, htons(frag_ip->ip_len) - hlen);
        /* 移动P指针到刚复制的数据尾部 */
        p += htons(frag_ip->ip_len) - hlen;
    }
out:
    /* IP重组成功,删除IP分片队列 */
    delete_frag(frag);
    return pkg;
}

struct fragment *new_frag(struct ip_hdr *ip)
{
    struct fragment *frag;
    frag = (struct fragment *)malloc(sizeof(struct fragment));
    if(!frag){
        perror("ip_frag malloc error");
        return NULL;
    }
    frag->frag_ttl = FRAG_TIME_OUT;
    frag->frag_id = ip->ip_id;
    frag->frag_proto = ip->ip_proto;
    strncpy(frag->frag_src, ip->ip_src, 4);
    strncpy(frag->frag_dst, ip->ip_dst, 4);
    frag->frag_hlen = 0;
    frag->frag_rec_size = 0;
    frag->frag_size = 0;
    frag->frag_flags = 0;
    list_add_node(&frag->frag_list, &frag_head);
    list_init(&frag->frag_pkg);
    return frag;
}

struct fragment *lookup_frag_head(struct ip_hdr *ip)
{
    struct fragment *frag;
    list_for_each_node(frag, &frag_head, frag_list)
    {
        if (frag->frag_id == ip->ip_id &&
            frag->frag_proto == ip->ip_proto &&
            strncmp(frag->frag_src, ip->ip_src, 4) == 0 &&
            strncmp(frag->frag_dst, ip->ip_dst, 4) == 0)
            return frag;
    }
    return NULL;
}

int insert_frag(struct pkg_buf *pkg, struct fragment *frag)
{
    struct pkg_buf *frag_pkg;
    struct ip_hdr *ip, *frag_ip;
    struct list_head *pos;
    int off, hlen;
    printf("insert_frag: %p\n", pkg);
    /* 如果分片已经完整,释放收到的这个分片 */
    if(complete_frag(frag)){
        perror("insert_frag: complete_frag\n");
        goto frag_drop;
    }
    ip = pkg_2_iphdr(pkg);
    off = ip_off(ip);
    hlen = ip_hlen(ip);

    /* 判断是否是最后一个分片 */
    if (ip_mf(ip) == 0 ){
        if(frag->frag_flags & FRAG_LAST){
            perror("insert_frag: FRAG_LAST\n");
            goto frag_drop;
        }
        frag->frag_flags |= FRAG_LAST;  //设置分片标志位,|=表示赋值的同时，不改变其他位的值
        frag->frag_size = off + htons(ip->ip_len) - hlen;
        pos = frag->frag_pkg.prev;   //pos指向分片的最后一个包
        goto frag_out;
    }
    /* 正常分片处理 */
    pos = &frag->frag_pkg;
    list_for_each_node_last(frag_pkg, &frag->frag_pkg, list)
    {
        frag_ip = pkg_2_iphdr(frag_pkg);
        if (off == ip_off(frag_ip)){     //如果此分片已经收到,丢弃
            perror("insert_frag: off == ip_off(frag_ip)\n");
            goto frag_drop;
        }
        if (off > ip_off(frag_ip)){      //根据偏移量,找到分片应该插入的位置的前一个节点
            pos = &frag_pkg->list;
            goto frag_found;
        }
    }
    //没有找到分片位置,说明此分片是当前分片中偏移量最小的
    frag_ip = NULL;
frag_found:
    /* 检查头部长度是否正确 */
    if (frag->frag_hlen && frag->frag_hlen != hlen){
        perror("insert_frag: frag->frag_hlen && frag->frag_hlen != hlen\n");
        goto frag_drop;
    }else{
        frag->frag_hlen = hlen;
    }
    /* 再次检查分片位置是否正确 */
    if (frag_ip && (ip_off(frag_ip) + htons(frag_ip->ip_len) - hlen) > off){
        perror("insert_frag: ip_off(frag_ip) + frag_ip->ip_len - hlen > off\n");
        goto frag_drop;
    }
    /* 如果这是第一个分片 */
    if (off == 0){
        frag->frag_flags |= FRAG_FIRST;
    }

frag_out:
    list_add_node(&pkg->list, pos);  //将最后一个分片插入到头节点的前面
    frag->frag_rec_size += htons(ip->ip_len) - hlen;
    if (full_frag(frag)){
        frag->frag_flags |= FRAG_COMPLETE;
    }
    return 0;

frag_drop:
    free_pkg(pkg);
    return -1;
}

struct pkg_buf *ip_reass(struct pkg_buf *pkg)
{
    struct ip_hdr *iphdr = pkg_2_iphdr(pkg);
    struct fragment *frag;
    /* 在已有的分片链表中查找是否有相同的分片,这里获取的frag是头节点 */
    frag = lookup_frag_head(iphdr);
    /* 如果没有找到对应的分片链表头节点,创建一个新的分片链表头节点 */
    if (NULL == frag){
        frag = new_frag(iphdr);
    }
    /* 将分片插入分片队列 */
    if (0 > insert_frag(pkg, frag)){
        return NULL;
    }
    if (complete_frag(frag)){
        /* 如果分片已经完整,将分片队列中的分片重新组合成一个完整的包 */
        pkg = reass_frag(frag);
    }else{
        pkg = NULL;
    }
    return pkg;
}

struct pkg_buf *ip_frag(struct pkg_buf *pkg, struct ip_hdr *ip, int hlen,
                    int data_len, int off, unsigned short mf_bit)
{
    struct pkg_buf *frag_pkg;
    struct ip_hdr *frag_ip;
    frag_pkg = pkg_alloc(ETH_HDR_LEN + hlen + data_len);
    /* 复制 pkg_buf 参数 */
    frag_pkg->pkg_pro = pkg->pkg_pro;
    frag_pkg->pkg_type = pkg->pkg_type;
    /* 复制 ip_hdr 参数 */
    frag_ip = pkg_2_iphdr(frag_pkg);
    /* 复制 ip头部 */
    memcpy(frag_ip, ip, hlen);
    /* 复制data部分 */
    memcpy((void *)frag_ip + hlen, (void *)ip + hlen + off, data_len);
    /* 处理IP头部参数 */
    frag_ip->ip_len = htons(hlen + data_len);
    mf_bit |= (off >> 3);
    frag_ip->ip_offlags = htons(mf_bit);
    ip_set_checksum(frag_ip);
    return frag_pkg;
}

void ip_send_frag(struct pkg_buf *pkg)
{
    struct pkg_buf *frag_pkg;
    struct ip_hdr *ip;
    int data_len, hlen, max_len, off;

    ip = pkg_2_iphdr(pkg);
    hlen = ip_hlen(ip);
    data_len = ip->ip_len - hlen;
    /*
    * MTU_SIZE - hlen是分片的最大长度 1480
    * ~7:一是为了保证分片的长度是8的倍数
    * 二是为了max_len赋值给ip->len时,后面三位为DF MF标志位,置零避免影响标志位
    */
    max_len = (MTU_SIZE - hlen) & ~7;
    off = 0;
    while (data_len > max_len)
    {
        /* 分片,获取分片后的包 */
        frag_pkg = ip_frag(pkg, ip, hlen, max_len, off, IP_FLAG_MF);
        ip_send_dev(frag_pkg);

        data_len -= max_len;
        off += max_len;
    }
    /* 发送最后的不足1480的报文 */
    if (data_len)
    {
        frag_pkg = ip_frag(pkg, ip, hlen, data_len, off, 0);
        ip_send_dev(frag_pkg);
    }
    free_pkg(pkg);
}

void ip_frag_timer(int delay)
{
    struct fragment *frag, *tmp;
    list_for_each_node_safe(frag, tmp, &frag_head, frag_list)
    {
        if(full_frag(frag)){
            continue;
        }
        frag->frag_ttl -= delay;
        if (frag->frag_ttl <= 0){
            struct pkg_buf *pkg = list_first_node(&frag->frag_pkg, struct pkg_buf, list);
            delete_frag(frag);
        }
    }
}