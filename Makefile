all : sr
CC = gcc
CFLAGS = -g -Wall -ansi -D_DEBUG_ -D_GNU_SOURCE -D_LINUX_
LIBS = -lnsl -lresolv -lm -lpthread
PFLAGS = -follow-child-processes=yes -cache-dir=/tmp/${USER} 
PURIFY = purify ${PFLAGS}

sr_HDRS = sr_arpcache.h sr_utils.h sr_dumper.h sr_if.h sr_protocol.h sr_router.h sr_rt.h  \
          vnscommand.h sha1.h

sr_SRCS = sr_router.c sr_main.c sr_if.c sr_rt.c sr_vns_comm.c sr_utils.c sr_dumper.c  \
          sr_arpcache.c sha1.c

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS))
sr_DEPS = $(patsubst %.c,.%.d,$(sr_SRCS))

$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(sr_DEPS) : .%.d : %.c
	$(CC) -MM $(CFLAGS) $<  > $@

-include $(sr_DEPS)	

sr : $(sr_OBJS)
	$(CC) $(CFLAGS) -o sr $(sr_OBJS) $(LIBS) 

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)

.PHONY : clean clean-deps dist    

clean:
	rm -f *.o *~ core sr *.dump *.tar tags .*.d

clean-deps:
	rm -f .*.d

