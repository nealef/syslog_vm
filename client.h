#ifndef __CLIENT_H
# define __CLIENT_H

/** @brief Standard Syslog port number (requires root/sudo privileges). */
#define PORT 514

/** @brief Maximum buffer size for incoming syslog payloads. */
#define BUF_SIZE 2048

/** @brief Use UDP or TCP for sending to daemon */
#define USE_UDP 1

/** @brief From CODEPAGE for iconv */
#define FROM_CODEPAGE "ibm-1047"

/** @brief To CODEPAGE for iconv */
#define TO_CODEPAGE "iso8859-1"

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 64 /**< Fallback max length if not defined by the system platform */
#endif

typedef struct {
    char      eye[8];     /** Eyecatcher */
    char      *id;        /** Message id - set by openlog */
    int       fd;         /** Socket file descriptor */
    int       mask;       /** syslog mask - set by setlogmask */ 
    pid_t     pid;        /** PID of client process */
    pthread_t tid;        /** Thread id of current thread */
    int       initDone;   /** Thread local storage initialized */
    int       sockType;   /** Type of socket connection */
#define CONN_UDP        1   /** UDP */
#define CONN_TCP        2   /** TCPIP */
    int       option;     /** LOG_PID etc. */
    int       facility;   /** Facility - LOG_KERN etc. */
    iconv_t   ic;         /** iconv token */
} syslogClient_t;

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
int build_rfc5424_string(syslogClient_t *client, char* dest_buf, size_t dest_max,
                         int severity, const char *hostname, const char *app_name,
                         const char* struct_data, const char* msg_payload);

/**
 * @brief Dispatches a constructed syslog string payload over a UDP link.
 *
 * @param[in] client syslog client control block
 * @param[in] syslog_msg Completed NULL-terminated syslog message string frame to transmit.
 * @return Returns 0 on successful delivery; returns -1 on socket or transit failures.
 */
int send_syslog_udp(syslogClient_t *client, const char* syslog_msg);

/**
 * @brief Dispatches a syslog message string payload over a TCP connection line.
 *
 * Enforces RFC 5425 / RFC 5424 standards by appending an explicit tracking trailing 
 * newline delimiter character ('\\n') to safely mark downstream stream reassembly frames.
 *
 * @param[in] client syslog client control block
 * @param[in] syslog_msg Completed NULL-terminated syslog message string frame to transmit.
 * @return Returns 0 on successful delivery; returns -1 on connection or write failures.
 */
int send_syslog_tcp(syslogClient_t *client, const char* syslog_msg);

#endif
