#ifndef CONTROL_SOCKET_H
#define CONTROL_SOCKET_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @file control_socket.h
 * @brief Control socket for real-time rule and config updates from backend
 *
 * Listens on a Unix domain socket for commands from the Flask backend.
 * Commands include:
 * - Add/remove IP to whitelist/blacklist/protected
 * - Clear lists
 * - Reload configuration
 * - Toggle protection stages
 */

// Control socket path
#define CONTROL_SOCKET_PATH "/var/run/antiddos/control.sock"

// Command types (must match backend/rules.py)
#define CMD_ADD_WHITELIST    0x01
#define CMD_DEL_WHITELIST    0x02
#define CMD_ADD_BLACKLIST    0x03
#define CMD_DEL_BLACKLIST    0x04
#define CMD_ADD_PROTECTED    0x05
#define CMD_DEL_PROTECTED    0x06
#define CMD_CLEAR_WHITELIST  0x10
#define CMD_CLEAR_BLACKLIST  0x11
#define CMD_CLEAR_PROTECTED  0x12
#define CMD_GET_STATS        0x20
#define CMD_RELOAD_CONFIG    0x30
#define CMD_UPDATE_STAGE     0x31
#define CMD_L2_RELOAD_CONFIG       0x32
#define CMD_L2_LOAD_PROFILE        0x33
#define CMD_L2_SAVE_BASELINES      0x34
#define CMD_L2_RESET_BASELINES     0x35
#define CMD_L2_FORCE_MATURE        0x36
#define CMD_L2_RELOAD_PER_IP_CONFIG 0x37
#define CMD_L2_FEEDBACK            0x38
#define CMD_CLEAR_PER_IP_ANOMALY   0x40
#define CMD_CLEAR_ALL_ANOMALY      0x41
#define CMD_L2_UNFREEZE_BASELINES  0x42

/* Response codes */
#define RESP_OK              0x00
#define RESP_ERROR           0x01
#define RESP_INVALID_CMD     0x02
#define RESP_INVALID_IP      0x03
#define RESP_RATE_LIMITED    0x04  /* Rate limiting response */

/**
 * Command packet format (from backend)
 * - cmd: 1 byte command type
 * - ip: 4 bytes IP address (network byte order)
 * - prefix_len: 1 byte prefix length (for CIDR, 32 for exact match)
 */
struct __attribute__((packed)) control_cmd {
    uint8_t  cmd;
    uint32_t ip;
    uint8_t  prefix_len;
};

/**
 * Response packet format (to backend)
 */
struct __attribute__((packed)) control_resp {
    uint8_t  status;
    uint8_t  reserved[3];
};

/**
 * Initialize control socket
 *
 * Creates Unix domain socket and starts listener thread.
 * The socket path directory is created if it doesn't exist.
 *
 * @return 0 on success, -1 on error
 */
int control_socket_init(void);

/**
 * Cleanup control socket
 *
 * Stops listener thread and removes socket file.
 */
void control_socket_cleanup(void);

/**
 * Check if control socket is running
 *
 * @return true if running and accepting connections
 */
bool control_socket_running(void);

/**
 * Get control socket statistics
 *
 * @param commands_received  Output: total commands received
 * @param commands_success   Output: successful commands
 * @param commands_failed    Output: failed commands
 */
void control_socket_get_stats(uint64_t *commands_received,
                              uint64_t *commands_success,
                              uint64_t *commands_failed);

/**
 * Set config file path for reload commands
 *
 * @param path  Path to layer1_config.json
 */
void control_socket_set_config_path(const char *path);

#endif // CONTROL_SOCKET_H
