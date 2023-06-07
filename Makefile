
LD = ld
CC = gcc
CFLAGS = -Wall -I../include
LFLAGS = -pthread
export LD CC CFLAGS

NET_STACK_OBJS = shell/shell_obj.o \
				 net/net_obj.o \
				 lib/lib_obj.o \
				 arp/arp_obj.o

all: tcpip

tcpip: $(NET_STACK_OBJS)
	$(CC) $(LFLAGS) $^ -o $@

shell/shell_obj.o: shell/*.c
	@make -C shell/

net/net_obj.o: net/*.c
	@make -C net/

lib/lib_obj.o: lib/*.c
	@make -C lib/

arp/arp_obj.o: arp/*.c
	@make -C arp/

clean:
	find ./ -name *.o | xargs rm -rf
	rm -rf tcpip