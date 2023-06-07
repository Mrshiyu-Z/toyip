OBJS   = arp.o arp_cache.o 
SUBDIR = arp

all:arp_obj.o
arp_obj.o:$(OBJS)
	@echo " [LD] $(SUBDIR)/$@"
	$(LD) -r -o $@ $^

%.o:%.c
	@echo " [CC] $(SUBDIR)/$@"
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o