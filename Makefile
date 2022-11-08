CC = gcc
CFLAGS = -Wall -g -I../include
export CC CFLAGS

NET_STACK_OBJS = arp/arp_obj.o \
		ip/ip_obj.o \
		net/net_obj.o \

all:tap
tap:$(NET_STACK_OBJS)
	$(CC) -o $@ $^

ip/ip_obj.o:ip/*.c
	@make -C ip/
arp/arp_obj.o:arp/*.c
	@make -C arp/
net/net_obj.o:net/*.c
	@make -C net/

clean:
	@rm -rf *.o
	@make -C arp/ clean
	@make -C ip/ clean
	@make -C net/ clean
