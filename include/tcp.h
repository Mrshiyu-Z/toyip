#ifndef __TCP_H
#define __TCP_H

struct tcp_hdr {
    unsigned short src_port;  //源端口
    unsigned short dst_port;  //目的端口
    unsigned int seq;      //序列号
    unsigned int ack;      //确认号
    unsigned short reserved:4,   //保留
                     data_offset:4,  //数据偏移
                     fin:1,    //结束标志
                     syn:1,    //同步标志
                     rst:1,    //复位标志
                     psh:1,    //推送标志
                     ack:1,    //确认标志
                     urg:1,    //紧急标志
                     ece:1,    //ECE标志
                     cwr:1;    //CWR标志
    unsigned short window;     //窗口大小
    unsigned short checksum;   //校验和
    unsigned short urgent_ptr;  //紧急指针
    unsigned char data[0];
}__attribute__((packed));
#endif