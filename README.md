# Simple Syslog Daemon and Library
This package contains source files used to build a simplistic syslog daemon (syslogd) which accepts UDP and TCP connections plus a shared library containing the following APIs:
- openlog()
- syslog()
- closelog()
- setlogmask()
## Daemon
The daemon does not have all the bells-and-whistles you are used to with packages such as `rsyslog`. There is no configuration file and no ability to forward messages elsewhere. The daemon simply receives, parses, and logs messages coming in from a client.
## Building
The package may be built on CMS or z/OS Unix System Services. If you do not have the C/C++ compiler on CMS then the latter option is what you require.
### Building under CMS
Use the `make` command without parameters when building on CMS. This will invoke the compiler and binder.
### Building under z/OS Unix System Services
Use the `make -f Makefile.uss` command. The object files may then be transferred to the CMS Byte File System (BFS) and linked via the CMS Binder.
## Installing
On CMS use the `make install` command to place the objects in the `/usr/local` file system.
## Starting the Daemon
The daemon may be run in the background using:
`nohup /usr/local/bin/syslogd &`
Messages are logged in `/var/log/messages`.
## Using the Client Library
Applications need to build with the side file `/usr/local/lib/libsyslog.so.x`. For example,
```
c89 -Wb,x /usr/local/lib/libsyslog.x -o target <files.o ...>
```
## Testing the Daemon
Use the `logger` command on any Linux host:
```
logger -i -p 1 -t TAG -d -n 172.17.16.60 Message from TESTER
```
Use the `tail` command to inspect the messages file 
```
Jul 30 00:38:50 vsrv035.svc.sinenomine.net TAG[400482]: Message from TESTER
```
