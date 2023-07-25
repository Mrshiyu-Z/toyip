OBJS   = tcp_in.o tcp_out.o tcp_reass.o tcp_sock.o tcp_state.o tcp_text.o tcp_timer.o
SUBDIR = ip

all:tcp_obj.o
tcp_obj.o:$(OBJS)
	@echo " [LD] $(SUBDIR)/$@"
	$(LD) -r -o $@ $^

%.o:%.c
	@echo " [CC] $(SUBDIR)/$@"
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o