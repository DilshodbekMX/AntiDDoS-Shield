/**
 * @file control_socket_security.h
 * @brief Security enhancements for control socket
 *
 * Security audit findings for control socket
 *
 * Security measures:
 * 1. Restrict socket permissions (0660 instead of 0666)
 * 2. Rate limiting for commands
 * 3. Command validation and bounds checking
 * 4. Audit logging
 */

#ifndef CONTROL_SOCKET_SECURITY_H
#define CONTROL_SOCKET_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Security configuration */
#define CTRL_SEC_SOCKET_PERMS          0660   /* Group-readable/writable only */
#define CTRL_SEC_SOCKET_GROUP          "antiddos" /* Group for socket access */

/* Rate limiting */
#define CTRL_SEC_MAX_CMDS_PER_SEC      100    /* Max commands per second */
#define CTRL_SEC_MAX_CMDS_PER_MINUTE   1000   /* Max commands per minute */
#define CTRL_SEC_BURST_LIMIT           20     /* Burst limit */

/* Input validation limits */
#define CTRL_SEC_MAX_PREFIX_LEN        32     /* Max CIDR prefix length */
#define CTRL_SEC_MIN_PREFIX_LEN        8      /* Min CIDR prefix length (prevent /0-/7) */

/* Audit log levels */
typedef enum {
    CTRL_AUDIT_DEBUG = 0,
    CTRL_AUDIT_INFO = 1,
    CTRL_AUDIT_WARNING = 2,
    CTRL_AUDIT_ERROR = 3,
    CTRL_AUDIT_SECURITY = 4  /* Security events (always logged) */
} ctrl_audit_level_t;

/**
 * Rate limiter state for a client
 */
struct ctrl_rate_limiter {
    uint64_t tokens;          /* Available tokens */
    uint64_t last_update_ns;  /* Last update timestamp */
    uint32_t second_count;    /* Commands this second */
    uint32_t minute_count;    /* Commands this minute */
    uint64_t second_start_ns; /* Start of current second window */
    uint64_t minute_start_ns; /* Start of current minute window */
};

/**
 * Initialize security features for control socket
 *
 * @return 0 on success, -1 on error
 */
int ctrl_security_init(void);

/**
 * Cleanup security features
 */
void ctrl_security_cleanup(void);

/**
 * Validate a command before execution
 *
 * Checks:
 * - Command type is known
 * - IP address is valid (not multicast, not broadcast, not reserved)
 * - CIDR prefix is within allowed range
 *
 * @param cmd Command type
 * @param ip IP address (network byte order)
 * @param prefix_len CIDR prefix length
 * @return true if valid, false otherwise
 */
bool ctrl_security_validate_command(uint8_t cmd, uint32_t ip, uint8_t prefix_len);

/**
 * Check rate limit for a client
 *
 * @param limiter Rate limiter state (per-client)
 * @return true if allowed, false if rate limited
 */
bool ctrl_security_check_rate_limit(struct ctrl_rate_limiter *limiter);

/**
 * Log an audit event
 *
 * @param level Log level
 * @param client_pid Client process ID (from SO_PEERCRED)
 * @param cmd Command that was executed
 * @param ip Target IP address
 * @param result Result code (0 = success)
 * @param message Optional message
 */
void ctrl_security_audit_log(ctrl_audit_level_t level,
                             pid_t client_pid,
                             uint8_t cmd,
                             uint32_t ip,
                             int result,
                             const char *message);

/**
 * Validate IP address for security
 *
 * Rejects:
 * - 0.0.0.0/8 (except 0.0.0.0 for special commands)
 * - 127.0.0.0/8 (loopback)
 * - 224.0.0.0/4 (multicast)
 * - 255.255.255.255 (broadcast)
 * - 169.254.0.0/16 (link-local)
 *
 * @param ip IP address in host byte order
 * @return true if valid, false otherwise
 */
bool ctrl_security_validate_ip(uint32_t ip);

/**
 * Get client credentials from socket (SO_PEERCRED)
 *
 * @param client_fd Client socket file descriptor
 * @param pid Output: client process ID
 * @param uid Output: client user ID
 * @param gid Output: client group ID
 * @return 0 on success, -1 on error
 */
int ctrl_security_get_peer_creds(int client_fd, pid_t *pid, uid_t *uid, gid_t *gid);

/**
 * Set socket permissions with proper security
 *
 * Creates socket with 0660 permissions and sets group ownership
 *
 * @param socket_path Path to socket
 * @return 0 on success, -1 on error
 */
int ctrl_security_set_socket_perms(const char *socket_path);

#ifdef __cplusplus
}
#endif

#endif /* CONTROL_SOCKET_SECURITY_H */
