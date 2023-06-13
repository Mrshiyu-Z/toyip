OBJS   = ip_in.o ip_frag.o 
SUBDIR = ip

all:ip_obj.o
ip_obj.o:$(OBJS)
	@echo " [LD] $(SUBDIR)/$@"
	$(LD) -r -o $@ $^

%.o:%.c
	@echo " [CC] $(SUBDIR)/$@"
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o