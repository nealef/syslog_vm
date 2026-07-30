#ifndef __SERVER_H
# define __SERVER_H

/**
 * @file syslog_parser.h
 * @brief Multi-standard Syslog Parsing and Network Engine.
 *
 * This header defines data structures and processing routines to identify,
 * decompose, and extract fields from network log events. It supports legacy 
 * BSD Syslog (RFC 3164) and modern structured IETF Syslog (RFC 5424) over
 * network streaming boundaries.
 * 
 * @author Neale Ferguson
 * @date 2026-07-29
 */

#include <stddef.h>

/** @brief Standard Syslog port number (requires root/sudo privileges). */
#define PORT 514

/** @brief Maximum buffer size for incoming syslog payloads. */
#define BUF_SIZE 4096

/** @brief Maximum concurrent active TCP/Stream client connections. */
#define MAX_CLIENTS 64

/** @brief Output path for the destination system log file. */
#define LOG_FILE "/var/log/messages"

/** @brief From CODEPAGE for iconv */
#define TO_CODEPAGE "ibm-1047"

/** @brief To CODEPAGE for iconv */
#define FROM_CODEPAGE "iso8859-1"

#define DUMP_DATA(t, d, l) do {                         \
       int x,y;		                                    \
       char *c = (char *) (d);		                    \
       fprintf(stderr, "%s - %p.%x\n", t, c, (l));	    \
       for (x = 0; x < (l);) {		                    \
           fprintf(stderr, "%04x ", x);                 \
           for (y = 0; y < 16 & x < (l); x++, y++)		\
               fprintf(stderr, "%02x ",c[x]);		    \
           fputc('\n', stderr);                         \
       }		                                        \
   } while (0)

#define DEBUG_PRINT(fmt, ...) do {                      \
        fprintf(stderr, "%s:%d - " fmt"\n",             \
                __func__, __LINE__, __VA_ARGS__);       \
        fflush(stderr);                                 \
    } while (0)

/**
 * @brief Data structure representing a fully parsed Syslog event entity.
 *
 * Encapsulates meta-information (Priority, Facility, Severity) alongside 
 * string containers for protocol-specific routing definitions.
 */
typedef struct {
    int pri;             /**< Raw priority value calculated from facility and severity. */
    int facility;        /**< Log facility source code (calculated as pri / 8). */
    int severity;        /**< Log severity threat scale (calculated as pri % 8). */
    int version;         /**< Protocol version digit. Set to 0 for RFC 3164, positive for RFC 5424. */
    char timestamp[64];  /**< Temporal marker string. Supports BSD format or ISO-8601 string. */
    char hostname[256];  /**< Network source node name or absolute IP address string. */
    char app_name[128];  /**< Originating application process name or identification string tag. */
    char proc_id[32];    /**< Operating system execution Process ID sequence number. */
    char msg_id[32];     /**< Software module identifier trigger code. */
    char structured_data[1024]; /**< Enclosed modern machine-parsing metadata blocks (RFC 5424 only). */
    char message[4096];  /**< Human-readable diagnostic plain text payload block. */
} syslogMessage_t;

/**
 * @brief Tracking structure for active TCP client streaming state context.
 */
typedef struct {
    int fd;                /**< Connected network socket file descriptor. */
    char buf[BUF_SIZE];    /**< Internal stream chunk reassembly buffer window. */
    size_t len;            /**< Current byte data length remaining in the buffer. */
} clientState_t;

/**
 * @brief Primary routing interface for raw log evaluation.
 *
 * Evaluates the structural layout of an inbound text packet, detects its specification 
 * variant, and executes the targeted decomposition routine.
 *
 * @param[in] packet Pointer to the contiguous NULL-terminated syslog input string.
 * @param[out] msg Pointer to a pre-allocated syslogMessage_t structure target.
 * @return Returns 1 if execution succeeded and strings parsed cleanly; 0 otherwise.
 */
static int parse_syslog(const char* packet, syslogMessage_t *msg);

/**
 * @brief Helper to extract space-separated fields, mapping "-" to empty strings
 *
 * @param[in] src data from client
 * @param[in] dest target area
 * @param[in] dest_max maxim size of destination area
 * @returns the next character in message or NULL (error)
 */
static const char *parse_field(const char *src, char *dest, size_t dest_max);

/**
 * @brief Parses an inbound string formatted under the legacy BSD Syslog specification.
 *
 * @param[in] src Pointer to the payload segment positioned directly after the PRI indicator.
 * @param[out] msg Destination structure tracking the tokenized output fragments.
 * @return Returns 1 on success; 0 on parsing rule violations.
 * @note This standard infers missing years from dates and maps tags using explicit colon tokens.
 */
static int parse_rfc3164(const char* src, syslogMessage_t *msg);

/**
 * @brief Parse an RFC 5424 type syslog message
 *
 * @param[in] src data from client
 * @param[in] msg syslog message control block
 * @returns Success (1) or failure (0)
 */
static int parse_rfc5424(const char *src, syslogMessage_t *msg);

/**
 * @brief Standardized target routing point processing parsed data variables.
 *
 * Consumes valid parsed results or raises formatting pipeline diagnostic messages to standard out.
 *
 * @param[in] raw_packet Zero-terminated raw source text targeted for translation.
 */
static void process_packet(const char *raw_packet);

/**
 * @brief Standardized target routing point processing parsed data variables.
 *
 * Consumes valid parsed results or raises formatting pipeline diagnostic messages to standard out.
 *
 * @param[in] client Client state control block
 */
static void process_client_buffer(clientState_t *client);

/**
 * @brief Convert buffer from EBCDIC to ASCII
 *
 * @param[in] cd iconv token
 * @param[in,out] buffer Data to be converted
 * @param[in] bufSize size of data in buffer
 */
static void convertBuffer(iconv_t cd, char *buffer, size_t bufSize);

#endif
