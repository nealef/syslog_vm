/**
 * @file syslog_server.c
 * @brief Multi-protocol Syslog Daemon supporting AF_INET and AF_INET6
 *
 * This daemon listens for incoming log messages across IPv4/IPv6 networks.
 * Received messages are formatted and appended directly to /var/log/messages.
 *
 * @author Neale Ferguson <neale@sinenomine.net>
 * @date 2026-07-28
 * @version 1.0
 */

#pragma langlvl( extended )

#pragma export(openlog)
#pragma export(closelog)
#pragma export(syslog)
#pragma export(setlogmask)

#pragma map(setlogmask, "\174\174SLOGM")
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "client.h"

/**
 * Prototypes
 */
static syslogClient_t *getClient(int);
static syslogClient_t *initSyslogClient(void);
static void termSyslogClient(void *);
static int formatOutput(char *, size_t, const char *, va_list);

pthread_key_t *keyptr = (pthread_key_t *) NULL;
pthread_key_t key;
char syslogid[8] = "SYSLOG";

/**
 * @brief Returns pointer to current thread's SyslogClient thread
 *
 */
static syslogClient_t *
getClient(int create)
{
    int status;
	syslogClient_t *client;

	/*
	 * Call pthread_getspecific() to get the address of the current thread's
	 * syslogClient_t structure.  If the current thread doesn't have a structure
	 * then call __initSyslogClient() to build one.
	 */
	if (((status = pthread_getspecific(key, (void **) &client)) == -1)  ||
		(client == NULL)) {
        if (create)
            client = initSyslogClient();
	}
	return(client);
}

/**
 * @brief Main initialization for all syslog client routines
 *
 */
static syslogClient_t *
initSyslogClient()
{
	syslogClient_t *client;
	int clientSz;

	/* Perform key create for process if necessary */
	if (keyptr == (pthread_key_t *) NULL) {
		keyptr = &key;
		pthread_key_create(keyptr, termSyslogClient);
	}

	/* Assume the current thread doesn't have a valid athd data area. */
	clientSz = sizeof(syslogClient_t);
	client = (syslogClient_t *) calloc(1, clientSz); 
    if (client == NULL) {
        perror("Error allocating thread pointer data area\n");
        abort();
    }
	if ((pthread_setspecific(key, (void *) client) == -1) &&
	    (errno == EINVAL)) {
		/*
		 * Pthread_setspecific failed because parm key is invalid.
		 */
		keyptr = &key;
		pthread_key_create(keyptr, termSyslogClient);
		pthread_setspecific(key, (void *) client);
	}		

	/* Initialize syslogClient_t structure. */

	memcpy(client->eye, syslogid, sizeof(client->eye));
	client->pid = getpid();
	client->tid = pthread_self();
    client->id = NULL;
    client->facility = LOG_LOCAL0;
    client->option = LOG_PID;
    client->mask = LOG_UPTO(LOG_INFO);

    /* Establish code conversion */
    client->ic = iconv_open(TO_CODEPAGE, FROM_CODEPAGE);
    if (client->ic == (iconv_t) -1) {
        perror("iconv");
        abort();
    }

	/* Set flag indiating athd initialization completed.  */
	client->initDone = 1;
    client->fd = -1;

    return client;
}

/**
 * @brief Thread termination routine for Syslog client
 *
 */
static void 
termSyslogClient(void *inparm)
{
	syslogClient_t *client;
	/*
	 * If client data area exists and initializatione completed then
	 * perform termination.
	 */
	client = (syslogClient_t *) inparm;
	if (client != NULL) {
		if (client->initDone == 1) {
			client->initDone = 0;       /* just to be sure no recursive calls. */
            if (client->fd != -1)
                close(client->fd);
            if (client->id != NULL)
                free(client->id);
            iconv_close(client->ic);
		}
		free(client);     /* free athd data area for current thread */
	    pthread_setspecific(key, (void *) NULL);
	}
    return;  /* for now just return */
}
 
/*
 * @brief Open a syslog client connection to daemon
 *
 * @param[in] ident optional id string to prefix messages
 * @param[in] option syslog options (e.g. LOG_PID)
 * @param[in] facility syslog facility (e.g. LOG_KERN)
 */
void 
openlog(const char *ident, int option, int facility)
{
    syslogClient_t *client = getClient(1);

    if ((!USE_UDP) && client->fd == -1) {
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_port = htons(PORT),
            .sin_addr.s_addr = INADDR_LOOPBACK,
        };

        client->sockType = CONN_TCP;
        client->fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(client->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(client->fd);
            client->fd = -1;
            perror("connect");
        } 
    }
    client->option = option;
    client->facility = facility;
}

/**
 * @brief Constructs a valid RFC 5424 syslog string from raw input parameters.
 *
 * Automatically injects the modern version identifier, calculates current ISO-8601 
 * timestamps, and formats optional fields or structured data blocks.
 *
 * @param[in] client syslog client control block
 * @param[out] dest_buf     Target array buffer to write the complete string message.
 * @param[in]  dest_max     Total maximum byte storage allocation capacity of dest_buf.
 * @param[in]  severity     Syslog severity level classification threat index (0-7).
 * @param[in]  hostname     Originating host network identifier name string (use "-" if none).
 * @param[in]  app_name     Issuing process or application service string moniker (use "-" if none).
 * @param[in]  struct_data  Valid bracketed structured data element blocks (use "-" if none).
 * @param[in]  msg_payload  Human-readable descriptive diagnostic text string payload.
 * @return Returns 0 upon successful construction; returns -1 if formatting bounds overflow.
 */
int 
build_rfc5424_string(syslogClient_t *client, char *dest_buf, size_t dest_max,
                     int severity, const char *hostname, const char *app_name,
                     const char* struct_data, const char* msg_payload)
{
    // 1. Calculate Priority code segment
    int pri = (client->facility * 8) + severity;

    // 2. Derive current high-resolution calendar time in ISO-8601 UTC format
    char time_str[64];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = gmtime(&tv.tv_sec);
    
    // Formats: YYYY-MM-DDTHH:MM:SS.mmmZ
    size_t time_len = strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", tm_info);
    snprintf(time_str + time_len, sizeof(time_str) - time_len, ".%03ldZ", tv.tv_usec / 1000000);

    // 3. Stringify Process ID handling context
    char pid_str[16];
    if (client->pid != 0) {
        snprintf(pid_str, sizeof(pid_str), "%d", client->pid);
    } else {
        strcpy(pid_str, "-");
    }

    // 4. Assemble components under formal RFC 5424 structural layouts
    int printed = snprintf(dest_buf, dest_max, "<%d>1 %s %s %s %s %s %s %s",
                           pri,
                           time_str,
                           (hostname && *hostname) ? hostname : "-",
                           (app_name && *app_name) ? app_name : "-",
                           pid_str,
                           (client->id && *client->id) ? client->id : "-",
                           (struct_data && *struct_data) ? struct_data : "-",
                           (msg_payload) ? msg_payload : "");

    // Verify buffer safety limits to check if strings truncated
    if (printed < 0 || (size_t)printed >= dest_max) {
        return -1; 
    }
    return 0;
}

/**
 * @brief Dispatches a constructed syslog string payload over a UDP link.
 *
 * @param[in] client syslog client control block
 * @param[in] syslog_msg Completed NULL-terminated syslog message string frame to transmit.
 * @return Returns 0 on successful delivery; returns -1 on socket or transit failures.
 */
int 
send_syslog_udp(syslogClient_t *client, const char *syslog_msg)
{
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    sa.sin_addr.s_addr = INADDR_LOOPBACK;
    
    ssize_t sent = sendto(sock_fd, syslog_msg, strlen(syslog_msg), 0,
                          (struct sockaddr*)&sa, sizeof(sa));
    
    close(sock_fd);
    return (sent < 0) ? -1 : 0;
}

/**
 * @brief Dispatches a constructed syslog string payload over a UDP link.
 *
 * @param[in] client syslog client control block
 * @param[in] syslog_msg Completed NULL-terminated syslog message string frame to transmit.
 * @return Returns 0 on successful delivery; returns -1 on socket or transit failures.
 */
int 
send_syslog_tcp(syslogClient_t *client, const char *syslog_msg)
{
    // Allocate memory buffer tracking space for data payload + newline delimiter token
    size_t payload_len = strlen(syslog_msg),
           lSend,
           lSent = 0;
    char *tcp_frame = malloc(payload_len + 2);
    if (!tcp_frame)
        return -1;

    // Frame data packet sequence using trailing newline marker format variations
    lSend = sprintf(tcp_frame, "%s\n", syslog_msg);

    do {
        lSent = send(client->fd, &tcp_frame[lSent], lSend, 0);
        if (lSent > 0) 
            lSend -= lSent;
    } while ((lSend > 0) || (errno == -EINTR));


    free(tcp_frame);
    return (lSent < 0) ? -1 : 0;
}

/*
 * @brief Send a message to syslog daemon
 *
 * Format the message, add any ids, pid, and build a client message to send
 *
 * @param[in] priority LOG_EMERG etc.
 * @param[in] format format string
 * @param[in] ... arguments to format string
 */
void 
syslog(int priority, const char *format, ...)
{
    syslogClient_t *client = getClient(1);
    char hostname[HOST_NAME_MAX + 1];
    char *msg = malloc(BUF_SIZE),
         *out = malloc(BUF_SIZE);
    int  lRem;
    uint8_t *inptr,     /* Pointer used for input buffer */
            *outptr;    /* Pointer used for output buffer */
    size_t inleft,      /* number of bytes left in inbuf */
           outleft;     /* number of bytes left in outbuf */
    va_list va;

    if (msg == NULL || out == NULL) {
        perror("Malloc failed getting buffers");
        abort();
    }

    if (client->fd == -1) 
        openlog(NULL, LOG_PID, LOG_USER);

    if (gethostname(hostname, sizeof(hostname)) == 0)
        hostname[HOST_NAME_MAX] = 0;
    else
        hostname[0] = 0;

    if (LOG_MASK(priority) & client->mask) {
        va_start(va, format);
        lRem = formatOutput(msg, BUF_SIZE, format, va);   /** Format the message */
        if (lRem > 0)  {
            if (build_rfc5424_string(client, out, BUF_SIZE, priority,
                                     hostname, NULL, NULL, msg) == 0) {
                inleft = outleft = strlen(out);
                inptr = out;
                outptr = msg;
                if (iconv(client->ic, &inptr, &inleft, &outptr, &outleft) == -1) {
                    perror("iconv");
                    abort();
                }
                if (USE_UDP)
                    send_syslog_udp(client, out);
                else 
                    send_syslog_tcp(client, out);
            }
        }
        va_end(va);
    }

    free(msg);
    free(out);
}

/*
 * @brief Close the syslog client
 */
void 
closelog(void)
{
	syslogClient_t *client = getClient(0);

    /*
     * If we have a syslogClient_t structure then clean it up 
     */
	if (client != NULL) {
		if (client->initDone == 1) {
			client->initDone = 0;       /* just to be sure no recursive calls. */
            if (client->fd != -1)
                close(client->fd);
            if (client->id != NULL)
                free(client->id);
		}
		free(client);     /* free athd data area for current thread */
	    pthread_setspecific(key, (void *) NULL);
	}
}

/*
 * @brief Set the syslog message priority mask
 *
 * @param[in] mask the new log mask
 * @returns old log mask
 */
int 
setlogmask(int mask)
{
	syslogClient_t *client = getClient(1);
    int ret = 0;

    if (client != NULL) {
        ret = client->mask;
        client->mask = mask;
    }
    return ret;
}

/**
 * @brief Converts format string and all character string
 * arguments to the printf-familiy functions.
 *
 * @param[in] buffer output buffer containing EBCDIC buffer
 * @param[in] buffersize maximum size of buffer
 * @param[in] format format string
 * @param[in] optional argument porinter
 * @returns Integer value containing the number of bytes  
 *			transmitted excluding the null terminating byte or 
 *			a negative value in the case of an error.
 */
static int 
formatOutput(char *buffer, size_t buffersize, const char *format, va_list parg)
{
    int  ltmp,
         lRem,
         saved_errno = errno;
    char *tmp = __alloca(65536),
         *pErr,
         *pBuf = buffer,
         *pTmp = tmp,
         *err = __alloca(256);

	ltmp = vsprintf(tmp, format, parg);     /** Format as for printf */
    if (ltmp < 0)
        return -1;
    buffer[0] = 0;
    pErr = strstr(tmp, "%m");               /** We now scan for all %m and replace */
    while (pErr != NULL) {
        if (*(pErr - 1) != '%') {           /** Check if not %%m */
            strcpy(err, strerror(saved_errno));     /** Get string version of errno */
            lRem = buffersize - strlen(buffer);     /** Get amount of remaining space */
            if (lRem > 0) {                         /** If there's enought space */
                strncat(buffer, err, lRem);             /** Add top buffer */
                pErr += 2;                              /** Skip %m */
                pTmp = pErr;                            /** This is where we'll copy from */
            } else 
                return -1;                              /** No room at the inn */
        } else {
            lRem = buffersize - strlen(buffer);     /** Get amount of remaining space */
            if (lRem > 0)                           /** If there's enought space */
                strncat(buffer, "%%m", lRem);
            else
                return -1;
            pErr += 2;
            pTmp = pErr;
        }
        pErr = strstr(pErr, "%m");
    }
    lRem = buffersize - strlen(buffer);
    if (lRem > 0) 
        strncat(buffer, pTmp, lRem);            /** Copy any remaining string */
    else
        return -1;

    return (strlen(buffer));
}
