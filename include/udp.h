struct udp
{
    unsigned short src;
    unsigned short dst;
    unsigned short length;
    unsigned short checksum;
    unsigned char data[0];
}__attribute__((packed));
