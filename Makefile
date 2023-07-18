
LD = ld
CC = gcc
CFLAGS = -Wall -g -Wno-address-of-packed-member -I../include
LFLAGS = -pthread
export LD CC CFLAGS

NET_STACK_OBJS = shell/shell_obj.o \
				 net/net_obj.o \
				 lib/lib_obj.o \
				 arp/arp_obj.o \
				 ip/ip_obj.o \
				 socket/socket_obj.o \
				 udp/udp_obj.o 

all: tcpip

tcpip: $(NET_STACK_OBJS)
	$(CC) $(LFLAGS) $^ -o $@

shell/shell_obj.o: shell/*.c
	@make -j4 -C shell/

net/net_obj.o: net/*.c
	@make -j4 -C net/

lib/lib_obj.o: lib/*.c
	@make -j4 -C lib/

arp/arp_obj.o: arp/*.c
	@make -j4 -C arp/

ip/ip_obj.o: ip/*.c
	@make -j4 -C ip/

socket/socket_obj.o: socket/*.c
	@make -j4 -C socket/

udp/udp_obj.o: udp/*.c
	@make -j4 -C udp/

clean:
	find ./ -name *.o | xargs rm -rf
	rm -rf tcpip
