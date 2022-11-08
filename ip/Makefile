OBJS = icmp_haddle.o
SUBDIR = ip

all:ip_obj.o
ip_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

icmp_haddle.o:icmp_handle.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o