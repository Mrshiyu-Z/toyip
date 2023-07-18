OBJS   = sock.o
SUBDIR = socket

all:socket_obj.o
socket_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o