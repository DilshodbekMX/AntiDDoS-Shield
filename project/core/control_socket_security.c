/**
 * @file control_socket_security.c
 * @brief Security enhancements for control socket
 *
 * Security audit implementation
 */

#include "control_socket_security.h"
#include "control_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <rte_log.h>

#define RTE_LOGTYPE_CTRL_SEC RTE_LOGTYPE_USER2

/* Audit log file */
static FILE *g_audit_log = NULL;
static pthread_mutex_t g_audit_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *AUDIT_LOG_PATH = "/var/log/antiddos/control_audit.log";

/* Rate limiter constants */
#define NS_PER_SEC 1000000000ULL

/* Command names for audit logging */
static const char *cmd_names[] = {
    [CMD_ADD_WHITELIST]   = "ADD_WHITELIST",
    [CMD_DEL_WHITELIST]   = "DEL_WHITELIST",
    [CMD_ADD_BLACKLIST]   = "ADD_BLACKLIST",
    [CMD_DEL_BLACKLIST]   = "DEL_BLACKLIST",
    [CMD_ADD_PROTECTED]   = "ADD_PROTECTED",
    [CMD_DEL_PROTECTED]   = "DEL_PROTECTED",
    [CMD_CLEAR_WHITELIST] = "CLEAR_WHITELIST",
    [CMD_CLEAR_BLACKLIST] = "CLEAR_BLACKLIST",
    [CMD_GET_STATS]       = "GET_STATS",
    [CMD_RELOAD_CONFIG]   = "RELOAD_CONFIG",
    [CMD_UPDATE_STAGE]    = "UPDATE_STAGE",
};
#define NUM_CMD_NAMES (sizeof(cmd_names) / sizeof(cmd_names[0]))

/* Get current time in nanoseconds */
static inline uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

int ctrl_security_init(void)
{
    /* Open audit log */
    g_audit_log = fopen(AUDIT_LOG_PATH, "a");
    if (!g_audit_log) {
        /* Try to create the directory */
        (void)system("mkdir -p /var/log/antiddos 2>/dev/null");
        g_audit_log = fopen(AUDIT_LOG_PATH, "a");
    }

    if (!g_audit_log) {
        RTE_LOG(WARNING, CTRL_SEC,
                "Could not open audit log %s, using stderr\n",
                AUDIT_LOG_PATH);
        g_audit_log = stderr;
    } else {
        /* Set permissions on log file */
        chmod(AUDIT_LOG_PATH, 0640);
    }

    RTE_LOG(INFO, CTRL_SEC, "Control socket security initialized\n");
    return 0;
}

void ctrl_security_cleanup(void)
{
    pthread_mutex_lock(&g_audit_lock);
    if (g_audit_log && g_audit_log != stderr) {
        fclose(g_audit_log);
        g_audit_log = NULL;
    }
    pthread_mutex_unlock(&g_audit_lock);

    RTE_LOG(INFO, CTRL_SEC, "Control socket security cleaned up\n");
}

bool ctrl_security_validate_ip(uint32_t ip)
{
    /* IP is in host byte order */
    uint8_t first_octet = (ip >> 24) & 0xFF;

    /* Reject 0.0.0.0/8 (except 0.0.0.0 itself for special commands) */
    if (first_octet == 0 && ip != 0) {
        return false;
    }

    /* Reject 127.0.0.0/8 (loopback) */
    if (first_octet == 127) {
        return false;
    }

    /* Reject 224.0.0.0/4 (multicast: 224-239) */
    if (first_octet >= 224 && first_octet <= 239) {
        return false;
    }

    /* Reject 240.0.0.0/4 (reserved: 240-255, except broadcast) */
    if (first_octet >= 240 && ip != 0xFFFFFFFF) {
        return false;
    }

    /* Reject broadcast */
    if (ip == 0xFFFFFFFF) {
        return false;
    }

    /* Reject 169.254.0.0/16 (link-local) */
    if (first_octet == 169 && ((ip >> 16) & 0xFF) == 254) {
        return false;
    }

    return true;
}

bool ctrl_security_validate_command(uint8_t cmd, uint32_t ip, uint8_t prefix_len)
{
    /* Validate command type */
    switch (cmd) {
    case CMD_ADD_WHITELIST:
    case CMD_DEL_WHITELIST:
    case CMD_ADD_BLACKLIST:
    case CMD_DEL_BLACKLIST:
    case CMD_ADD_PROTECTED:
    case CMD_DEL_PROTECTED:
        /* These commands require valid IP */
        break;

    case CMD_CLEAR_WHITELIST:
    case CMD_CLEAR_BLACKLIST:
    case CMD_GET_STATS:
    case CMD_RELOAD_CONFIG:
    case CMD_UPDATE_STAGE:
    case CMD_L2_RELOAD_CONFIG:
    case CMD_L2_LOAD_PROFILE:
    case CMD_L2_SAVE_BASELINES:
    case CMD_L2_RESET_BASELINES:
    case CMD_L2_FORCE_MATURE:
    case CMD_L2_RELOAD_PER_IP_CONFIG:
    case CMD_L2_FEEDBACK:
    case CMD_CLEAR_PER_IP_ANOMALY:
    case CMD_CLEAR_ALL_ANOMALY:
    case CMD_L2_UNFREEZE_BASELINES:
        /* These commands don't use IP field, skip validation */
        return true;

    default:
        /* Unknown command */
        return false;
    }

    /* Validate CIDR prefix length */
    if (prefix_len > CTRL_SEC_MAX_PREFIX_LEN) {
        return false;
    }

    /* Reject overly broad CIDR ranges (< /8) except for exact match (/32) */
    if (prefix_len < CTRL_SEC_MIN_PREFIX_LEN && prefix_len != 32) {
        return false;
    }

    /* Validate IP address - convert from network to host byte order */
    uint32_t ip_host = ntohl(ip);

    /* For 0.0.0.0, only allow in clear commands or /0 (which we already blocked) */
    if (ip_host == 0) {
        return false;
    }

    return ctrl_security_validate_ip(ip_host);
}

bool ctrl_security_check_rate_limit(struct ctrl_rate_limiter *limiter)
{
    uint64_t now = get_time_ns();

    /* Initialize on first call */
    if (limiter->last_update_ns == 0) {
        limiter->tokens = CTRL_SEC_BURST_LIMIT;
        limiter->last_update_ns = now;
        limiter->second_start_ns = now;
        limiter->minute_start_ns = now;
        limiter->second_count = 0;
        limiter->minute_count = 0;
    }

    /* Refill tokens based on elapsed time */
    uint64_t elapsed_ns = now - limiter->last_update_ns;
    double elapsed_sec = (double)elapsed_ns / NS_PER_SEC;
    double refill = elapsed_sec * CTRL_SEC_MAX_CMDS_PER_SEC;
    limiter->tokens += (uint64_t)refill;
    if (limiter->tokens > CTRL_SEC_BURST_LIMIT) {
        limiter->tokens = CTRL_SEC_BURST_LIMIT;
    }
    limiter->last_update_ns = now;

    /* Reset second counter if window expired */
    if (now - limiter->second_start_ns >= NS_PER_SEC) {
        limiter->second_start_ns = now;
        limiter->second_count = 0;
    }

    /* Reset minute counter if window expired */
    if (now - limiter->minute_start_ns >= 60 * NS_PER_SEC) {
        limiter->minute_start_ns = now;
        limiter->minute_count = 0;
    }

    /* Check all limits */
    if (limiter->tokens < 1) {
        return false;
    }

    if (limiter->second_count >= CTRL_SEC_MAX_CMDS_PER_SEC) {
        return false;
    }

    if (limiter->minute_count >= CTRL_SEC_MAX_CMDS_PER_MINUTE) {
        return false;
    }

    /* Consume token and increment counters */
    limiter->tokens--;
    limiter->second_count++;
    limiter->minute_count++;

    return true;
}

void ctrl_security_audit_log(ctrl_audit_level_t level,
                             pid_t client_pid,
                             uint8_t cmd,
                             uint32_t ip,
                             int result,
                             const char *message)
{
    static const char *level_names[] = {
        [CTRL_AUDIT_DEBUG]    = "DEBUG",
        [CTRL_AUDIT_INFO]     = "INFO",
        [CTRL_AUDIT_WARNING]  = "WARNING",
        [CTRL_AUDIT_ERROR]    = "ERROR",
        [CTRL_AUDIT_SECURITY] = "SECURITY",
    };

    /* Always log security events, filter others */
    if (level < CTRL_AUDIT_INFO && level != CTRL_AUDIT_SECURITY) {
        return;
    }

    const char *cmd_name = "UNKNOWN";
    if (cmd < NUM_CMD_NAMES && cmd_names[cmd]) {
        cmd_name = cmd_names[cmd];
    }

    /* Format IP address */
    char ip_str[INET_ADDRSTRLEN];
    uint32_t ip_host = ntohl(ip);
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
             (ip_host >> 24) & 0xFF, (ip_host >> 16) & 0xFF,
             (ip_host >> 8) & 0xFF, ip_host & 0xFF);

    /* Get timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", tm_info);

    pthread_mutex_lock(&g_audit_lock);

    if (g_audit_log) {
        fprintf(g_audit_log,
                "%s | %s | pid=%d | cmd=%s | ip=%s | result=%s | %s\n",
                time_str,
                level_names[level],
                (int)client_pid,
                cmd_name,
                ip_str,
                result == 0 ? "SUCCESS" : "FAILURE",
                message ? message : "");
        fflush(g_audit_log);
    }

    pthread_mutex_unlock(&g_audit_lock);

    /* Also log to RTE_LOG for critical events */
    if (level >= CTRL_AUDIT_WARNING) {
        RTE_LOG(WARNING, CTRL_SEC,
                "AUDIT: pid=%d cmd=%s ip=%s result=%d %s\n",
                (int)client_pid, cmd_name, ip_str, result,
                message ? message : "");
    }
}

int ctrl_security_get_peer_creds(int client_fd, pid_t *pid, uid_t *uid, gid_t *gid)
{
#ifdef SO_PEERCRED
    struct ucred creds;
    socklen_t len = sizeof(creds);

    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &creds, &len) < 0) {
        return -1;
    }

    if (pid) *pid = creds.pid;
    if (uid) *uid = creds.uid;
    if (gid) *gid = creds.gid;

    return 0;
#else
    (void)client_fd;
    if (pid) *pid = 0;
    if (uid) *uid = 0;
    if (gid) *gid = 0;
    return -1;
#endif
}

int ctrl_security_set_socket_perms(const char *socket_path)
{
    /* Set restrictive permissions: owner and group only */
    if (chmod(socket_path, CTRL_SEC_SOCKET_PERMS) < 0) {
        RTE_LOG(WARNING, CTRL_SEC,
                "Failed to set socket permissions: %s\n", socket_path);
        return -1;
    }

    /* Try to set group ownership to 'antiddos' if it exists */
    struct group *grp = getgrnam(CTRL_SEC_SOCKET_GROUP);
    if (grp) {
        if (chown(socket_path, -1, grp->gr_gid) < 0) {
            RTE_LOG(WARNING, CTRL_SEC,
                    "Failed to set socket group: %s\n", socket_path);
        } else {
            RTE_LOG(INFO, CTRL_SEC,
                    "Socket group set to '%s' (gid=%d)\n",
                    CTRL_SEC_SOCKET_GROUP, grp->gr_gid);
        }
    } else {
        RTE_LOG(INFO, CTRL_SEC,
                "Group '%s' not found, using default group\n",
                CTRL_SEC_SOCKET_GROUP);
    }

    return 0;
}
