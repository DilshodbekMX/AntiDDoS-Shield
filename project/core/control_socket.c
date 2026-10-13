#include "control_socket.h"
#include "control_socket_security.h"  /* Security enhancements */
#include "../layer1/tables/ip_lists.h"
#include "../layer1/config/layer1_config.h"  /* For L1_DEFAULT_CONFIG_FILE */
#include "../layer1/layer1.h"
#include "../layer2/layer2.h"
#include "../layer2/config/layer2_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <rte_log.h>

#define RTE_LOGTYPE_CONTROL RTE_LOGTYPE_USER1

// Global state
static int g_socket_fd = -1;
static pthread_t g_listener_thread;
static volatile bool g_running = false;

// Statistics
static uint64_t g_cmd_received = 0;
static uint64_t g_cmd_success = 0;
static uint64_t g_cmd_failed = 0;

// Config path for reload
// Use defined constant instead of hardcoded absolute path
static char g_config_path[256] = L1_DEFAULT_CONFIG_FILE;

/**
 * Create directory for socket if it doesn't exist
 */
static int ensure_socket_dir(void)
{
    const char *path = CONTROL_SOCKET_PATH;
    char dir[256];

    // Extract directory from socket path
    const char *last_slash = strrchr(path, '/');
    if (!last_slash) {
        return 0;  // No directory component
    }

    size_t dir_len = last_slash - path;
    if (dir_len >= sizeof(dir)) {
        return -1;
    }

    strncpy(dir, path, dir_len);
    dir[dir_len] = '\0';

    // Create directory with permissions allowing socket creation
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        RTE_LOG(ERR, CONTROL, "Failed to create socket directory %s: %s\n",
                dir, strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Handle a single command from the backend
 */
static uint8_t handle_command(const struct control_cmd *cmd)
{
    uint32_t ip = cmd->ip;
    uint8_t prefix_len = cmd->prefix_len;
    int ret;

    RTE_LOG(DEBUG, CONTROL, "Received command: 0x%02x, IP: %u.%u.%u.%u/%u\n",
            cmd->cmd,
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF,
            prefix_len);

    switch (cmd->cmd) {
    case CMD_ADD_WHITELIST:
        if (prefix_len == 32) {
            // Exact IP match
            ret = ip_whitelist_add(htonl(ip), WL_MODE_BYPASS);
        } else {
            // CIDR prefix
            ret = ip_whitelist_cidr_add(ip, prefix_len);
        }
        if (ret == 0) ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_DEL_WHITELIST:
        if (prefix_len == 32) {
            ret = ip_whitelist_remove(htonl(ip));
        } else {
            ret = ip_whitelist_cidr_remove(ip, prefix_len);
        }
        if (ret == 0) ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_ADD_BLACKLIST:
        ret = ip_blacklist_add(htonl(ip));
        if (ret == 0) ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_DEL_BLACKLIST:
        ret = ip_blacklist_remove(htonl(ip));
        if (ret == 0) ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_ADD_PROTECTED:
        if (prefix_len == 0 || prefix_len >= 32) {
            ret = ip_protected_add(htonl(ip));               // exact /32 (ip is host order)
        } else {
            ret = ip_protected_subnet_add(ip, prefix_len);   // CIDR subnet aggregate
        }
        if (ret == 0) ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_DEL_PROTECTED:
        if (prefix_len == 0 || prefix_len >= 32) {
            ret = ip_protected_remove(htonl(ip));
        } else {
            ret = ip_protected_subnet_remove(ip, prefix_len);
        }
        if (ret == 0) ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_CLEAR_WHITELIST:
        ip_whitelist_clear();
        ip_whitelist_cidr_clear();
        ret = 0;
        ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_CLEAR_BLACKLIST:
        ip_blacklist_clear();
        ret = 0;
        ip_lists_save(NULL);  // Persist to file
        break;

    case CMD_CLEAR_PROTECTED:
        ip_protected_clear();
        ip_protected_subnet_clear();
        ret = 0;
        ip_lists_save(NULL);  // Persist to file
        RTE_LOG(INFO, CONTROL, "Protected IPs list cleared\n");
        break;

    case CMD_RELOAD_CONFIG:
        ret = layer1_config_reload(g_config_path);
        if (ret == 0) {
            layer1_refresh_cached_config();  // Update cached values in fast path
            RTE_LOG(INFO, CONTROL, "Configuration reloaded successfully\n");
        } else {
            RTE_LOG(ERR, CONTROL, "Configuration reload failed\n");
        }
        break;

    case CMD_UPDATE_STAGE:
        // Stage updates are handled via config reload
        ret = layer1_config_reload(g_config_path);
        if (ret == 0) {
            layer1_refresh_cached_config();  // Update cached values in fast path
        }
        break;

    case CMD_GET_STATS:
        // Stats are handled separately via stats socket
        ret = 0;
        break;

    case CMD_L2_RELOAD_CONFIG:
        ret = layer2_config_reload();
        RTE_LOG(INFO, CONTROL, "Layer 2 config %s\n", ret == 0 ? "reloaded" : "reload failed");
        break;

    case CMD_L2_SAVE_BASELINES:
        ret = layer2_save_baselines();
        RTE_LOG(INFO, CONTROL, "Baselines %s\n", ret == 0 ? "saved" : "save failed");
        break;

    case CMD_L2_RESET_BASELINES:
        layer2_reset_baselines();
        ret = 0;
        RTE_LOG(INFO, CONTROL, "Baselines reset\n");
        break;

    case CMD_L2_FORCE_MATURE:
    case CMD_L2_LOAD_PROFILE:
    case CMD_L2_FEEDBACK:
    case CMD_CLEAR_PER_IP_ANOMALY:
        /* Accepted -- no-op for now, prevents "Invalid command" errors */
        ret = 0;
        break;

    case CMD_L2_RELOAD_PER_IP_CONFIG:
        layer2_load_per_ip_feature_weights();
        ret = 0;
        RTE_LOG(INFO, CONTROL, "Per-IP feature weights reloaded\n");
        break;

    case CMD_L2_UNFREEZE_BASELINES:
        layer2_unfreeze_baselines();
        ret = 0;
        RTE_LOG(INFO, CONTROL, "Baselines unfrozen\n");
        break;

    case CMD_CLEAR_ALL_ANOMALY:
        layer2_clear_anomaly();
        ret = 0;
        RTE_LOG(INFO, CONTROL, "Anomaly state cleared\n");
        break;

    default:
        RTE_LOG(WARNING, CONTROL, "Unknown command: 0x%02x\n", cmd->cmd);
        return RESP_INVALID_CMD;
    }

    return (ret == 0) ? RESP_OK : RESP_ERROR;
}

/**
 * Handle a client connection
 *
 * Added security validation and rate limiting
 */
static void handle_client(int client_fd)
{
    struct control_cmd cmd;
    struct control_resp resp;
    ssize_t n;

    /* Get client credentials for audit logging */
    pid_t client_pid = 0;
    uid_t client_uid = 0;
    gid_t client_gid = 0;
    ctrl_security_get_peer_creds(client_fd, &client_pid, &client_uid, &client_gid);

    /* Per-client rate limiter */
    struct ctrl_rate_limiter rate_limiter = {0};

    while (g_running) {
        /* Read command */
        n = recv(client_fd, &cmd, sizeof(cmd), 0);
        if (n <= 0) {
            if (n < 0 && errno != ECONNRESET) {
                RTE_LOG(ERR, CONTROL, "recv error: %s\n", strerror(errno));
            }
            break;
        }

        if (n != sizeof(cmd)) {
            RTE_LOG(WARNING, CONTROL, "Incomplete command received: %zd bytes\n", n);
            resp.status = RESP_ERROR;
            ctrl_security_audit_log(CTRL_AUDIT_WARNING, client_pid, 0, 0,
                                    -1, "Incomplete command");
        } else {
            g_cmd_received++;

            /* Check rate limit */
            if (!ctrl_security_check_rate_limit(&rate_limiter)) {
                resp.status = RESP_RATE_LIMITED;
                ctrl_security_audit_log(CTRL_AUDIT_SECURITY, client_pid, cmd.cmd,
                                        cmd.ip, -1, "Rate limited");
                g_cmd_failed++;
            }
            /* Validate command before execution */
            else if (!ctrl_security_validate_command(cmd.cmd, cmd.ip, cmd.prefix_len)) {
                resp.status = RESP_INVALID_CMD;
                ctrl_security_audit_log(CTRL_AUDIT_SECURITY, client_pid, cmd.cmd,
                                        cmd.ip, -1, "Invalid command or IP");
                g_cmd_failed++;
            } else {
                resp.status = handle_command(&cmd);

                if (resp.status == RESP_OK) {
                    g_cmd_success++;
                    ctrl_security_audit_log(CTRL_AUDIT_INFO, client_pid, cmd.cmd,
                                            cmd.ip, 0, NULL);
                } else {
                    g_cmd_failed++;
                    ctrl_security_audit_log(CTRL_AUDIT_ERROR, client_pid, cmd.cmd,
                                            cmd.ip, -1, "Command failed");
                }
            }
        }

        /* Send response */
        memset(resp.reserved, 0, sizeof(resp.reserved));
        n = send(client_fd, &resp, sizeof(resp), 0);
        if (n < 0) {
            RTE_LOG(ERR, CONTROL, "send error: %s\n", strerror(errno));
            break;
        }
    }
}

/**
 * Listener thread function
 */
static void *listener_thread(void *arg __attribute__((unused)))
{
    int client_fd;
    struct sockaddr_un client_addr;
    socklen_t client_len;

    RTE_LOG(INFO, CONTROL, "Control socket listener started on %s\n",
            CONTROL_SOCKET_PATH);

    while (g_running) {
        client_len = sizeof(client_addr);
        client_fd = accept(g_socket_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            if (g_running) {
                RTE_LOG(ERR, CONTROL, "accept error: %s\n", strerror(errno));
            }
            break;
        }

        RTE_LOG(DEBUG, CONTROL, "Client connected\n");
        handle_client(client_fd);
        close(client_fd);
        RTE_LOG(DEBUG, CONTROL, "Client disconnected\n");
    }

    RTE_LOG(INFO, CONTROL, "Control socket listener stopped\n");
    return NULL;
}

int control_socket_init(void)
{
    struct sockaddr_un addr;
    int ret;

    if (g_running) {
        RTE_LOG(WARNING, CONTROL, "Control socket already running\n");
        return 0;
    }

    // Create socket directory
    if (ensure_socket_dir() < 0) {
        return -1;
    }

    // Remove old socket if exists
    unlink(CONTROL_SOCKET_PATH);

    // Create socket
    g_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_socket_fd < 0) {
        RTE_LOG(ERR, CONTROL, "socket() failed: %s\n", strerror(errno));
        return -1;
    }

    // Bind socket
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    ret = bind(g_socket_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        RTE_LOG(ERR, CONTROL, "bind() failed: %s\n", strerror(errno));
        close(g_socket_fd);
        g_socket_fd = -1;
        return -1;
    }

    /* Set restrictive socket permissions (group only, not world-writable) */
    ctrl_security_set_socket_perms(CONTROL_SOCKET_PATH);

    // Listen
    ret = listen(g_socket_fd, 5);
    if (ret < 0) {
        RTE_LOG(ERR, CONTROL, "listen() failed: %s\n", strerror(errno));
        close(g_socket_fd);
        unlink(CONTROL_SOCKET_PATH);
        g_socket_fd = -1;
        return -1;
    }

    // Start listener thread
    g_running = true;
    ret = pthread_create(&g_listener_thread, NULL, listener_thread, NULL);
    if (ret != 0) {
        RTE_LOG(ERR, CONTROL, "pthread_create() failed: %s\n", strerror(ret));
        g_running = false;
        close(g_socket_fd);
        unlink(CONTROL_SOCKET_PATH);
        g_socket_fd = -1;
        return -1;
    }

    RTE_LOG(INFO, CONTROL, "Control socket initialized at %s\n", CONTROL_SOCKET_PATH);
    return 0;
}

void control_socket_cleanup(void)
{
    if (!g_running) {
        return;
    }

    g_running = false;

    // Close socket to unblock accept()
    if (g_socket_fd >= 0) {
        shutdown(g_socket_fd, SHUT_RDWR);
        close(g_socket_fd);
        g_socket_fd = -1;
    }

    // Wait for listener thread
    pthread_join(g_listener_thread, NULL);

    // Remove socket file
    unlink(CONTROL_SOCKET_PATH);

    RTE_LOG(INFO, CONTROL, "Control socket cleaned up\n");
}

bool control_socket_running(void)
{
    return g_running;
}

void control_socket_get_stats(uint64_t *commands_received,
                              uint64_t *commands_success,
                              uint64_t *commands_failed)
{
    if (commands_received) {
        *commands_received = g_cmd_received;
    }
    if (commands_success) {
        *commands_success = g_cmd_success;
    }
    if (commands_failed) {
        *commands_failed = g_cmd_failed;
    }
}

/**
 * Set config path for reload commands
 */
void control_socket_set_config_path(const char *path)
{
    if (path && strlen(path) < sizeof(g_config_path)) {
        strncpy(g_config_path, path, sizeof(g_config_path) - 1);
        g_config_path[sizeof(g_config_path) - 1] = '\0';
    }
}
