OBJS   = main.o net_command.o ping_command.o shell.o
SUBDIR = shell

all:shell_obj.o
shell_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o