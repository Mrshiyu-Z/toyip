OBJS   = udp.o udp_sock.o
SUBDIR = udp

all:udp_obj.o
udp_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o