OBJS   = main.o
SUBDIR = shell

all:shell_obj.o
shell_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o