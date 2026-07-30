CPPFLAGS = -D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D__VM__ -D_UNIX03_SOURCE -D_OPEN_THREADS 
CFLAGS	= -g -O2 -c $(DEBUG) $(CPPFLAGS) -I. -D_ALL_SOURCE -qxplink -qlanglvl=extended:extc89:extc99 \
		  -qfloat=ieee -qlongname -q32 -qseverity=e=CCN3296 -qasm -qdll
LDFLAGS=-qxplink -q32
DLLFLAGS=-qxplink -qdll -Wl,dll -q32
LD=xlc
CC=xlc

all : syslogd libsyslog.so

syslogd : syslog_server.o
		  $(LD) -o $@ $(LDFLAGS) $^

syslog_server.o : syslog_server.c client.h
				  $(CC) $(CFLAGS) -o $@ -c syslog_server.c

libsyslog.so : syslog_client.o
			   $(LD) $(DLLFLAGS) -o $@ $^

syslog_client.o : syslog_client.c client.h
				  $(CC) $(CFLAGS) -o $@ -c syslog_client.c
