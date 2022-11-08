#include <stdio.h>
#include <string.h>
#include <unistd.h>


#include "arp.h"

void fake_ip(unsigned char *ip)
{
    ip[0] = 10;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 1;
}

void fake_hw(unsigned char *hw)
{
    hw[0] = 0x00;
    hw[1] = 0x12;
    hw[2] = 0x34;
    hw[3] = 0x56;
    hw[4] = 0x78;
    hw[5] = 0x9a;
}

void arp_reply(struct eth_hdr *hdr, int tap_fd)
{
    struct arp_hdr *arp = (struct arp_hdr *)hdr->payload;
    if (arp->opcode == 0x0100)
    {
        printf("ARP request: from %d.%d.%d.%d want to get %d.%d.%d.%d\n", arp->sip[0], arp->sip[1], arp->sip[2], arp->sip[3], arp->dip[0], arp->dip[1], arp->dip[2], arp->dip[3]);
    }
    arp->opcode = 0x0200;
    memcpy(arp->dmac, arp->smac, 6);
    memcpy(hdr->dmac, hdr->smac, 6);
    memcpy(arp->dip, arp->sip, 4);
    fake_hw(arp->smac);
    fake_hw(hdr->smac);
    fake_ip(arp->sip);
    write(tap_fd, (void *)hdr, sizeof(*hdr) + sizeof(*arp));
    printf("ARP reply: from %d.%d.%d.%d to %d.%d.%d.%d with ", arp->sip[0], arp->sip[1], arp->sip[2], arp->sip[3], arp->dip[0], arp->dip[1], arp->dip[2], arp->dip[3]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", arp->smac[0], arp->smac[1], arp->smac[2], arp->smac[3], arp->smac[4], arp->smac[5]);
    printf("------------------------------\n");
}
