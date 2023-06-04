OBJS   = lib.o
SUBDIR = lib

all:lib_obj.o
lib_obj.o:$(OBJS)
	$(LD) -r -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o