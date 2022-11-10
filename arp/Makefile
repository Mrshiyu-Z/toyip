OBJS   = arp.o arp_cache.o
SUBDIR = arp

all:arp_obj.o
arp_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf *.o
