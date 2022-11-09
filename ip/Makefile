OBJS = icmp_handle.o
SUBDIR = ip

all:ip_obj.o
ip_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf *.o