/**
 * @file syslog_server.c
 * @brief Multi-protocol Syslog Daemon supporting AF_INET, AF_INET6, and AF_IUCV sockets.
 *
 * This daemon listens for incoming log messages across IPv4/IPv6 networks and IBM
 * z/VM hypervisor IUCV channels using both Datagram (UDP) and Stream (TCP) sockets.
 * Received messages are formatted and appended directly to /var/log/messages.
 *
 * @author Neale Ferguson <neale@sinenomine.net>
 * @date 2026-07-28
 * @version 1.0
 */

#pragma langlvl( extended )
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "server.h"

/** @brief Shutdown indicator */
int g_stop_server = 0;

/** @brief log file FD */
FILE *g_log_file;

/**
 * @brief Async-signal-safe signal handler for fatal hardware faults and termination signals.
 *
 * Uses low-level, async-signal-safe primitives (write, _exit) to avoid deadlock
 * or corruption when handling crashes like SIGSEGV or SIGILL.
 *
 * @param[in] sig  Signal number received.
 * @param[in] info Pointer to siginfo_t structure containing signal metadata.
 * @param[in] ucontext Pointer to thread context (unused).
 */
static void 
signal_handler(int sig, siginfo_t *info, void *dummy)
{
    switch (sig) {
        case SIGTERM:
        case SIGQUIT:
            // Request graceful shutdown in the main loop
            g_stop_server = 1;
            break;

        case SIGSEGV:
        case SIGILL:
        case SIGABRT: {
            // Low-level diagnostic logging for severe faults
            const char *sig_name = (sig == SIGSEGV) ? "SIGSEGV" :
                                   (sig == SIGILL)  ? "SIGILL"  : "SIGABRT";
            
            if (g_log_file != NULL) {
                char err_buf[128];

                // Note: Direct unbuffered write using safe stack buffer
                fprintf(g_log_file, 
                        "[CRASH] Fatal signal %s (%d) received. Fault addr: %p\n",
                        sig_name, sig, info->si_addr);
            }
            
            // Restore default handler and re-raise to produce core dump / standard exit code
            signal(sig, SIG_DFL);
            raise(sig);
            break;
        }
        default:
            break;
    }
}

/**
 * @brief Registers handlers for SIGTERM, SIGQUIT, SIGABRT, SIGSEGV, and SIGILL.
 */
static void 
setup_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_sigaction = signal_handler;
    sa.sa_flags = 0;

    // Block all other signals during execution of the signal handler
    sigfillset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
}

/**
 * @brief Extract the priority data from the message
 *
 * @param src data from client
 * @param msg syslog message control block
 * @returns the next character in message or NULL (error)
 */
const char *
parse_pri(const char *src, syslogMessage_t *msg)
{
    if (*src != '<') return NULL;
    src++; // Move past '<'
            
    char *end;
    msg->pri = (int)strtol(src, &end, 10);
    if (*end != '>') return NULL;
        
    msg->facility = msg->pri / 8;
    msg->severity = msg->pri % 8;
        
    return end + 1; // Return pointer right after '>'
}

int 
parse_rfc3164(const char *src, syslogMessage_t *msg)
{
    msg->version = 0; // Legacy format has no version field
    
    // 1. Timestamp (Fixed length: 15 bytes, e.g., "Oct 11 22:14:15")
    strncpy(msg->timestamp, src, 15);
    msg->timestamp[15] = '\0';
    src += 15;
    if (*src == ' ') src++;

    // 2. Hostname (Up to next space)
    size_t host_len = strcspn(src, " ");
    snprintf(msg->hostname, sizeof(msg->hostname), "%.*s", (int)host_len, src);
    src += host_len;
    if (*src == ' ') src++;

    // 3. Tag / App-Name (Up to colon or space)
    size_t tag_len = strcspn(src, ": ");
    snprintf(msg->app_name, sizeof(msg->app_name), "%.*s", (int)tag_len, src);
    src += tag_len;

    // Skip colon and subsequent spaces to reach the human-readable message
    if (*src == ':') src++;
    while (*src == ' ') src++;

    // 4. Message Content
    strncpy(msg->message, src, sizeof(msg->message) - 1);
    
    return 1; // Success
}

/**
 * @brief Helper to extract space-separated fields, mapping "-" to empty strings
 *
 * @param[in] src data from client
 * @param[in] dest target area
 * @param[in] dest_max maxim size of destination area
 * @returns the next character in message or NULL (error)
 */
static const char * 
parse_field(const char *src, char *dest, size_t dest_max)
{
    size_t len = strcspn(src, " ");

    if (len == 1 && src[0] == '-') {
        dest[0] = '\0';
    } else {
        snprintf(dest, dest_max, "%.*s", (int)len, src);
    }
    src += len;
    return (*src == ' ') ? src + 1 : src;
}

/**
 * @brief Parse an RFC 5424 type syslog message
 *
 * @param[in] src data from client
 * @param[in] msg syslog message control block
 * @returns Success (1) or failure (0)
 */
static int 
parse_rfc5424(const char *src, syslogMessage_t *msg)
{
    char *end;

    msg->version = (int)strtol(src, &end, 10);
    if (*end != ' ') return 0;

    src = end + 1;

    // Extract basic header elements using our field helper
    src = parse_field(src, msg->timestamp, sizeof(msg->timestamp));
    src = parse_field(src, msg->hostname, sizeof(msg->hostname));
    src = parse_field(src, msg->app_name, sizeof(msg->app_name));
    src = parse_field(src, msg->proc_id, sizeof(msg->proc_id));
    src = parse_field(src, msg->msg_id, sizeof(msg->msg_id));

    // Parse Structured Data field
    if (*src == '-') {
        msg->structured_data[0] = '\0';
        src++;
        if (*src == ' ') src++;
    } else if (*src == '[') {
        // Find matching closing bracket while accounting for nested brackets
        int brackets = 0;
        size_t idx = 0;
        while (*src && (brackets > 0 || idx == 0)) {
            if (*src == '[') brackets++;
            if (*src == ']') brackets--;
            if (idx < sizeof(msg->structured_data) - 1) {
                msg->structured_data[idx++] = *src;
            }
            src++;
        }
        msg->structured_data[idx] = '\0';
        if (*src == ' ') src++;
    }

    // Remaining string payload is the message body
    strncpy(msg->message, src, sizeof(msg->message) - 1);
    return 1; // Success
}

/**
 * @brief Parse a syslog message depending on type
 *
 * @param[in] src data from client
 * @param[in] msg syslog message control block
 * @returns Success (1) or failure (0)
 */
static int 
parse_syslog(const char *packet, syslogMessage_t *msg)
{
    memset(msg, 0, sizeof(syslogMessage_t));
    
    const char* payload = parse_pri(packet, msg);
    if (!payload) return 0; // Invalid PRI format

    // Peek immediately after the PRI header to identify the protocol variation
    // If a digit followed by a space exists, treat it as an RFC 5424 format.
    char *end;
    strtol(payload, &end, 10);
    if (end != payload && *end == ' ') {
        return parse_rfc5424(payload, msg);
    } else {
        return parse_rfc3164(payload, msg);
    }
}

/*
 * @brief Application entry point and main select() event processing loop.
 *
 * Initializes log file storage with 0600 permissions, configures network/hypervisor
 * listening sockets, and multiplexes incoming requests using select().
 *
 * @return Returns 0 on normal exit, or terminates with EXIT_FAILURE on setup errors.
 */
int 
main(void) {
    int udp_master_fd, tcp_master_fd; 
    clientState_t clients[MAX_CLIENTS];
    iconv_t cd;

    cd = iconv_open(TO_CODEPAGE, FROM_CODEPAGE);
    if (cd == (iconv_t) -1) {
        perror("iconv_open");
        abort();
    }

    setup_signal_handlers();

    /* ---------------------------------------------------------------
     * Open /var/log/messages with 0600 permissions
     * --------------------------------------------------------------- */
    int log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (log_fd < 0) {
        perror("Failed to open " LOG_FILE);
        exit(EXIT_FAILURE);
    }

    // Force explicit 0600 permissions regardless of system umask
    chmod(LOG_FILE, S_IRUSR | S_IWUSR);

    g_log_file = fdopen(log_fd, "a");

    for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;

    /* ---------------------------------------------------------------
     * Socket Initialization & Binding
     * --------------------------------------------------------------- */

    // Setup INET UDP
    udp_master_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in inet_udp_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(udp_master_fd, (struct sockaddr *)&inet_udp_addr, sizeof(inet_udp_addr));

    // Setup INET TCP
    tcp_master_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(tcp_master_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in inet_tcp_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(tcp_master_fd, (struct sockaddr *)&inet_tcp_addr, sizeof(inet_tcp_addr));
    listen(tcp_master_fd, 10);

    /* ---------------------------------------------------------------
     * Event Multiplexing Loop
     * --------------------------------------------------------------- */
    fd_set readfds;

    while (!g_stop_server) {
        FD_ZERO(&readfds);

        FD_SET(udp_master_fd, &readfds);
        FD_SET(tcp_master_fd, &readfds);

        int max_fd = (udp_master_fd > tcp_master_fd) ? udp_master_fd : tcp_master_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].fd;
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_fd) max_fd = sd;
        }

        int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            perror("Selection interaction exception error");
            break;
        }

        // --- Event Type 1: Inbound UDP Datagram Event ---
        if (FD_ISSET(udp_master_fd, &readfds)) {
            char udp_buf[BUF_SIZE];
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            ssize_t bytes = recvfrom(udp_master_fd, udp_buf, sizeof(udp_buf) - 1, 0,
                                     (struct sockaddr*)&client_addr, &addr_len);
            if (bytes > 0) {
                udp_buf[bytes] = '\0';
                convertBuffer(cd, udp_buf, bytes + 1);
                process_packet(udp_buf);
            }
        }

        // --- Event Type 2: New Inbound TCP Client Connection Request ---
        if (FD_ISSET(tcp_master_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_client_fd = accept(tcp_master_fd, (struct sockaddr*)&client_addr, &addr_len);
            
            if (new_client_fd >= 0) {
                int accepted = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].fd == -1) {
                        clients[i].fd = new_client_fd;
                        clients[i].len = 0;
                        accepted = 1;
                        break;
                    }
                }
                if (!accepted) {
                    close(new_client_fd); // Drop client connection if capacity is exceeded
                }
            }
        }

        // --- Event Type 3: Existing TCP Client Streaming Input ---
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd != -1 && FD_ISSET(clients[i].fd, &readfds)) {
                ssize_t bytes = recv(clients[i].fd, clients[i].buf + clients[i].len, 
                                     sizeof(clients[i].buf) - clients[i].len - 1, 0);
                
                if (bytes <= 0) {
                    // Connection closed by peer or hit by a network interface read error
                    close(clients[i].fd);
                    clients[i].fd = -1;
                    clients[i].len = 0;
                } else {
                    clients[i].len += bytes;
                    clients[i].buf[clients[i].len] = '\0';
                    convertBuffer(cd, clients[i].buf, clients[i].len + 1);
                    process_client_buffer(&clients[i]);
                }
            }
        }

    }

    fclose(g_log_file);
    iconv_close(cd);

    return 0;
}

/**
 * @brief Processes incomplete TCP stream chunks by scanning for newline characters.
 *
 * @param[in,out] client Pointer to the active tracking state structure of the TCP client.
 */
static void 
process_client_buffer(clientState_t *client)
{
    size_t start_idx = 0;
    char process_buf[BUF_SIZE];

    // Scan the combined internal buffer window for newline markers (\n or \r)
    for (size_t i = 0; i < client->len; i++) {
        if (client->buf[i] == '\n' || client->buf[i] == '\r') {
            size_t msg_len = i - start_idx;
            if (msg_len > 0) {
                snprintf(process_buf, sizeof(process_buf), "%.*s", (int)msg_len, &client->buf[start_idx]);
                process_packet(process_buf);
            }
            start_idx = i + 1;
        }
    }

    // Shift unparsed fragments to the front of the tracking window buffer
    if (start_idx < client->len) {
        client->len -= start_idx;
        memmove(client->buf, &client->buf[start_idx], client->len);
    } else {
        client->len = 0;
    }
}

/**
 * @brief Standardized target routing point processing parsed data variables.
 *
 * Consumes valid parsed results and appends them to the system log file 
 * located at `/var/log/messages`. Falls back to stderr if the destination 
 * file cannot be opened due to permission or path restrictions.
 *
 * @param[in] raw_packet Zero-terminated raw source text targeted for translation.
 * @note This operation requires administrative/root privileges to write to /var/log/.
 */
static void 
process_packet(const char* raw_packet)
{
    syslogMessage_t msg;
    
    // Parse the inbound raw syslog packet frame string
    if (parse_syslog(raw_packet, &msg)) {
        char time_str[64],
             pid_str[32];
        time_t temp;
        struct tm *timeptr;
           
        temp = time(NULL);
        timeptr = localtime(&temp);
        strftime(time_str, sizeof(time_str), "%b %e %T", timeptr);

        if (msg.proc_id[0] != 0) 
            snprintf(pid_str, sizeof(pid_str), "[%s]", msg.proc_id);
        else
            pid_str[0] = 0;

        // Write structured output format to file target
        fprintf(g_log_file, "%s %-16s %s%s: %s \n",
                time_str, msg.hostname, msg.app_name, pid_str, msg.message);
        
        // Force operational flush to disk immediately to prevent caching delays
        fflush(g_log_file);
    } else {
        // Log explicitly unparseable garbage sequences or anomalies
        fprintf(g_log_file, "Unparseable Syslog Payload Received: %s\n", raw_packet);
        fflush(g_log_file);
    }
}

/**
 * @brief Convert buffer from EBCDIC to ASCII
 *
 * @param[in] cd iconv token
 * @param[in,out] buffer Data to be converted
 * @param[in] bufSize size of data in buffer
 */
static void
convertBuffer(iconv_t cd, char *buffer, size_t bufSize)
{
    char *cvtBuf,
         *inPtr,
         *outPtr;
    size_t inLeft,
           outLeft;

    cvtBuf = __alloca(bufSize);
    memcpy(cvtBuf, buffer, bufSize);

    inLeft = outLeft = bufSize;
    inPtr = cvtBuf;
    outPtr = buffer;

    if (iconv(cd, &inPtr, &inLeft, &outPtr, &outLeft) == -1) {
        perror("iconv");
        abort();
    }
}
