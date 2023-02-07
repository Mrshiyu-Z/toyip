OBJS = ip_in.o ip_out.o icmp.o ip_frag.o
SUBDIR = ip

all:ip_obj.o
ip_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf *.o