CFLAGS=-Wc,langlvl\(extc99\),arch\(4\),tune\(4\),gonum -I.
DEFINES=-D_OE_SOCKETS \                                   
        -D_OPEN_SYS \                                     
		-D_OPEN_SYS_SOCK_IPV6 \                           
		-D_OPEN_THREADS \                                 
		-D_XPG4=1 \                                       
		-D_XOPEN_SOURCE=500 \                             
		-D_XOPEN_SOURCE_EXTENDED=1                        
LDFLAGS=-Wb,x,map                                         
DLLFLAGS=-Wb,x,map,dynam=dll                              
LD=c89                                                    
CC=c89                                                    
												                                                          
all : syslogd libsyslog.so                                
	                                                          
syslogd : syslog_server.o                                 
	@$(LD) -o $@ $(LDFLAGS) $^                               
	                                                          
syslog_server.o : syslog_server.c client.h                
	@$(CC) $(DEFINES) $(CFLAGS) -o $@ -c syslog_server.c     
	                                                          
libsyslog.so : syslog_client.o                            
	@$(LD) $(DLLFLAGS) -o $@ $^                              

                                                    
syslog_client.o : syslog_client.c client.h          
	@$(CC) $(DEFINES) $(CFLAGS) -o $@ -c syslog_client.c
	                                                    
install : syslogd libsyslog.so                      
	@cp syslogd /usr/local/bin                         
	@cp libsyslog.so libsyslog.so.x /usr/local/lib     
