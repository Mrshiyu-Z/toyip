#include "lib.h"
#include "net.h"
#include "eth.h"
#include "arp.h"
#include "ip.h"

void arp_in(struct pkg_buf *pkg)
{
    printf("arp in\n");
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    if (pkg->pkg_len < ETH_HDR_LEN + ARP_HDR_LEN){
        printf("arp_in: pkg_len error\n");
        goto err_free_pkg;
    }
    if ((memcmp(arp->smac, eth->smac, ETH_MAC_LEN) != 0)){
        printf("arp_in: memcpy error\n");
        goto err_free_pkg;
    }
    if (htons(arp->htype) != ARP_ETH_TYPE || htons(arp->ptype) != ETH_TYPE_IP || 
        arp->hlen != ETH_MAC_LEN || arp->plen != IP_ADDR_LEN){
            printf("unsupported L2/L3 protocol\n");
            goto err_free_pkg;
    }
    if (htons(arp->opcode) != ARP_REQ && htons(arp->opcode) != ARP_REP){
        printf("unsupported opcode\n");
        goto err_free_pkg;
    }
    arp_recv(pkg);
    return;
err_free_pkg:
    perror("arp_in: error\n");
    free(pkg);
}

void arp_recv(struct pkg_buf *pkg)
{
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    // struct arp_cache *ac;
    if (check_ip_lo(arp->dip)){
        arp_reply(pkg);
        return;
    }
// free_pkg:
//     free(pkg);
}

void arp_reply(struct pkg_buf *pkg)
{
    printf("arp reply\n");
    struct eth_hdr *eth = (struct eth_hdr *)pkg->data;
    struct arp_hdr *arp = (struct arp_hdr *)eth->data;
    arp->opcode = ntohs(2);
    memcpy(arp->dmac, arp->smac, ETH_MAC_LEN);
    cp_mac_lo(arp->smac);
    memcpy(arp->dip, arp->sip, IP_ADDR_LEN);
    cp_ip_lo(arp->sip);
    net_out(pkg);
}