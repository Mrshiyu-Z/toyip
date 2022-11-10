CC = gcc
CFLAGS = -Wall -fgnu89-inline -g -I../include
LFALGS = -pthread
export CC CFLAGS

NET_STACK_OBJS = arp/arp_obj.o \
		ip/ip_obj.o \
		net/net_obj.o \

all:tap
tap:$(NET_STACK_OBJS)
	$(CC) $(LFALGS) -o $@ $^

arp/arp_obj.o:arp/*.c
	@make -C arp/
ip/ip_obj.o:ip/*.c
	@make -C ip/
net/net_obj.o:net/*.c
	@make -C net/

clean:
	@rm -rf *.o
	@make -C arp/ clean
	@make -C ip/ clean
	@make -C net/ clean
