OBJS   = arp_haddle.o
SUBDIR = arp

all:arp_obj.o
arp_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

arp_haddle.o:arp_handle.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o
