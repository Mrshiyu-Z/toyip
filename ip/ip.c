#include "ip.h"
#include "lib.h"

void cp_ip_lo(unsigned char *ip)
{
    ip[0] = 10;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 1;
}