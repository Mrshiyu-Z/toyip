OBJS   = ping.o
SUBDIR = app

all:app_obj.o
app_obj.o:$(OBJS)
	@echo " [LD] $(SUBDIR)/$@"
	$(LD) -r -o $@ $^

%.o:%.c
	@echo " [CC] $(SUBDIR)/$@"
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o