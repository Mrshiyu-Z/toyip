#ifndef __TCP_H
#define __TCP_H

#include "list.h"
#include "tcp_timer.h"
#include "tcp_timer.h"
#include "wait.h"

#define TCP_DEFAULT_WINDOW 4096
#define TCP_DEFAULT_TTL    64

#define TCP_LITTLE_ENDIAN    //小端字节序
struct tcp_hdr {
    unsigned short src_port;        //源端口
    unsigned short dst_port;        //目的端口
    unsigned int seq;               //序列号
    unsigned int ack;               //确认号
#ifdef TCP_LITTLE_ENDIAN
    unsigned short  reserved:4,      //保留
                    data_offset:4, //数据偏移
                    fin:1,         //结束标志
                    syn:1,         //同步标志
                    rst:1,         //复位标志
                    psh:1,    //推送标志
                    ack:1,    //确认标志
                    urg:1,    //紧急标志
                    ece:1,    //ECE标志
                    cwr:1;    //CWR标志
#else
    unsigned short	data_offset:4,
                    reserved:4,
			        cwr:1,
			        ece:1,
			        urg:1,
			        ack:1,
			        psh:1,
			        rst:1,
			        syn:1,
			        fin:1;
#endif
    unsigned short window;     //窗口大小
    unsigned short checksum;   //校验和
    unsigned short urgent_ptr;  //紧急指针
    unsigned char data[0];
}__attribute__((packed));

struct tcp_sock {
    // struct sock sk;
    struct hlist_node bhash_list;  // bind hash list
    unsigned int bhash;            // bing hash value
    int accept_backlog;
    int backlog;
    struct list_head listen_queue;
    struct list_head accept_queue;
    struct list_head list;
    struct tcp_timer timewait;
    struct tcpip_wait *wait_accept;
    struct tcpip_wait *wait_connect;
    struct tcp_sock *parent;
    unsigned int flags;
    
};

#endif