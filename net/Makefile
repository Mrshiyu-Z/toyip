OBJS   = netdev.o tap.o veth.o
SUBDIR = net

all:net_obj.o
net_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o