#include "tap.h"
#include "net.h"
#include "eth.h"
#include "lib.h"

int tap_fd;

void printf_eth(struct eth_hdr *eth)
{
    printf("eth_out: smac = %02x:%02x:%02x:%02x:%02x:%02x\n", eth->smac[0], eth->smac[1], eth->smac[2], eth->smac[3], eth->smac[4], eth->smac[5]);
    printf("eth_out: dmac = %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dmac[0], eth->dmac[1], eth->dmac[2], eth->dmac[3], eth->dmac[4], eth->dmac[5]);
    printf("eth->type: %04x\n", eth->ethertype);
}

inline void cp_mac_lo(unsigned char *mac)
{
    mac[0] = 0x00;mac[1] = 0x34;
    mac[2] = 0x45;mac[3] = 0x67;
    mac[4] = 0x89;mac[5] = 0xab;
}

void eth_init(void)            //获取tap设备的文件描述符
{
    tap_fd = alloc_tap("tap0");
    if (tap_fd < 0)
    {
        perror("net init alloc_tap");
        exit(1);
    }
}

int eth_recv(struct pkg_buf *pkg)     //从tap设备读取报文
{
    int len;
    len = read(tap_fd, pkg->data, pkg->pkg_len);
    if (len < 0)
    {
        perror("net rx read null");
    }
    else{
        pkg->pkg_len = len;
    }
    return len;
}

void eth_rx(void)                    //从tap设备读取报文并处理                
{
    struct pkg_buf *pkg = pkg_alloc(MTU_SIZE);
    if(0 < eth_recv(pkg))
    {
        // printf_eth(eth);
        net_in(pkg);
    }
    else{
        perror("eth_rx: eth_recv error");
        free(pkg);
    }
}

void eth_in(void)           //监听tap设备
{
    // printf("eth_in start\n");
    int ret = 0;
    struct pollfd pfd[1];
    pfd[0].fd = tap_fd;
    pfd[0].events = POLLIN;
    while (1)
    {
        ret = poll(pfd, 1, -1);
        if (ret < 0){
            perror("net in poll");
            continue;
        }
        else if (ret > 0){
            if (pfd[0].revents & POLLIN){
                eth_rx();
            }
        }
    }
}

void eth_out(struct pkg_buf *pkg)   //发送报文到tap设备
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    if (eth->ethertype != htons(ETH_TYPE_IP) || eth->ethertype != htons(ETH_TYPE_ARP))
    {
        perror("eth_out: ethertype error");
        free(pkg);
        return;
    }
    eth_tx(pkg);
}

void eth_tx(struct pkg_buf *pkg)  //发送
{
    int len;
    len = write(tap_fd, pkg->data, pkg->pkg_len);
    if (len < 0)
    {
        perror("net tx write");
    }
    free(pkg);
}
