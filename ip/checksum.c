
#include "ip.h"

unsigned short checksum(unsigned char *buf, int count)
{
    unsigned int sum = 0;
    unsigned short *pkg = (unsigned short *)buf;
    while (count > 1)
    {
        sum += *pkg++;
        count -= 2;
    }
    if (count > 0)
    {
        sum += *(unsigned char *)buf;
    }
    while(sum >> 16)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return ~sum;
}