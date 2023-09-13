
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
				 udp/udp_obj.o \
				 tcp/tcp_obj.o \
				 app/app_obj.o

all: toyip

toyip: $(NET_STACK_OBJS)
	$(CC) $(LFLAGS) $^ -o $@

shell/shell_obj.o: shell/*.c
	@make -C shell/

net/net_obj.o: net/*.c
	@make -C net/

lib/lib_obj.o: lib/*.c
	@make -C lib/

arp/arp_obj.o: arp/*.c
	@make -C arp/

ip/ip_obj.o: ip/*.c
	@make -C ip/

socket/socket_obj.o: socket/*.c
	@make -C socket/

udp/udp_obj.o: udp/*.c
	@make -C udp/

tcp/tcp_obj.o: tcp/*.c
	@make -C tcp/

app/app_obj.o: app/*.c
	@make -C app/

clean:
	find ./ -name *.o | xargs rm -rf
	rm -rf toyip
