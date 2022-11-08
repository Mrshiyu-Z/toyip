OBJS = main.o tap.o
SUBDIR = net

all:net_obj.o
net_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

main.o:main.c
	$(CC) $(CFLAGS) -c $< -o $@

tap.o:tap.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf *.o