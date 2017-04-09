CC = g++
LD = g++

CFLAGS = -c -g -pedantic -Wall
LFLAGS = -pedantic -Wall

OBJS = sr_main.o sha1.o sr_arpcache.o sr_dumper.o sr_if.o sr_router.o sr_rt.o sr_utils.o sr_vns_comm.o
PROG = sr

# clean everything first, including logs and databases. Then, build
# the program.
default: clean $(PROG)

$(PROG): $(OBJS)
	$(LD) $(LFLAGS) $(OBJS) -o $(PROG)

sr_main.o: sr_main.c sr_dumper.h sr_router.h sr_rt.h
	$(CC) $(CFLAGS) sr_main.c

sha1.o: sha1.c 
	$(CC) $(CFLAGS) sha1.c

sr_arpcache.o: sr_arpcache.c sr_arpcache.h sr_router.h sr_if.h sr_protocol.h sr_rt.h sr_utils.h
	$(CC) $(CFLAGS) sr_arpcache.c

sr_dumper.o: sr_dumper.c sr_dumper.h
	$(CC) $(CFLAGS) sr_dumper.c

sr_if.o: sr_if.c sr_if.h sr_router.h
	$(CC) $(CFLAGS) sr_if.c

sr_router.o: sr_router.c sr_router.h sr_if.h sr_rt.h sr_protocol.h sr_utils.h sr_arpcache.h
	$(CC) $(CFLAGS) sr_router.c

sr_rt.o: sr_rt.c sr_rt.h sr_router.h
	$(CC) $(CFLAGS) sr_rt.c

sr_utils.o: sr_utils.c sr_utils.h sr_protocol.h
	$(CC) $(CFLAGS) sr_utils.c

sr_vns_comm.o: sr_vns_comm.c vnscommand.h sr_dumper.h sr_router.h sr_if.h sr_protocol.h sha1.h
	$(CC) $(CFLAGS) sr_vns_comm.c

clean:
	rm -f *.o
