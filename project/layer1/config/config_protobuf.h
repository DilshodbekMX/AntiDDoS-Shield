#ifndef CONFIG_PROTOBUF_H
#define CONFIG_PROTOBUF_H

/**
 * @file config_protobuf.h
 * @brief Memory-safe configuration parsing using Protocol Buffers
 *
 * This replaces cJSON to eliminate unbounded sprintf/strcpy vulnerabilities.
 * Supports both binary protobuf and JSON text formats for configuration.
 *
 * Security improvements:
 * - All string lengths are validated before copy
 * - No unbounded memory operations
 * - Schema validation enforced by protobuf
 */

#include "layer1_config.h"
#include <stddef.h>
#include <stdbool.h>

// Maximum allowed configuration file size (1 MB)
#define CONFIG_MAX_FILE_SIZE (1024 * 1024)

// Maximum string field lengths (enforced during parsing)
#define CONFIG_MAX_PATH_LEN 256
#define CONFIG_MAX_STRING_LEN 1024

// Error codes for configuration parsing
typedef enum {
    CONFIG_OK = 0,
    CONFIG_ERR_FILE_NOT_FOUND = -1,
    CONFIG_ERR_FILE_TOO_LARGE = -2,
    CONFIG_ERR_MEMORY_ALLOC = -3,
    CONFIG_ERR_PARSE_FAILED = -4,
    CONFIG_ERR_VALIDATION_FAILED = -5,
    CONFIG_ERR_STRING_TOO_LONG = -6,
    CONFIG_ERR_VALUE_OUT_OF_RANGE = -7,
    CONFIG_ERR_WRITE_FAILED = -8,
} config_error_t;

/**
 * Load configuration from JSON file (text format)
 * Uses bounded parsing to prevent buffer overflows.
 *
 * @param config_path  Path to JSON config file
 * @param config       Output configuration structure
 * @return CONFIG_OK on success, error code on failure
 */
config_error_t config_load_json(const char *config_path, struct layer1_config *config);

/**
 * Load configuration from binary protobuf file
 * More efficient than JSON for production deployments.
 *
 * @param config_path  Path to binary config file
 * @param config       Output configuration structure
 * @return CONFIG_OK on success, error code on failure
 */
config_error_t config_load_binary(const char *config_path, struct layer1_config *config);

/**
 * Save configuration to JSON file (human-readable)
 *
 * @param config_path  Path to output JSON file
 * @param config       Configuration to save
 * @return CONFIG_OK on success, error code on failure
 */
config_error_t config_save_json(const char *config_path, const struct layer1_config *config);

/**
 * Save configuration to binary protobuf file
 *
 * @param config_path  Path to output binary file
 * @param config       Configuration to save
 * @return CONFIG_OK on success, error code on failure
 */
config_error_t config_save_binary(const char *config_path, const struct layer1_config *config);

/**
 * Get error message for config error code
 *
 * @param error  Error code
 * @return Human-readable error message
 */
const char* config_error_str(config_error_t error);

/**
 * Safely copy string with bounds checking
 * Prevents buffer overflow by truncating if necessary.
 *
 * @param dest      Destination buffer
 * @param src       Source string
 * @param dest_size Size of destination buffer
 * @return true if string fit completely, false if truncated
 */
static inline bool config_safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) return false;
    if (!src) {
        dest[0] = '\0';
        return true;
    }

    size_t src_len = 0;
    while (src[src_len] != '\0' && src_len < dest_size - 1) {
        dest[src_len] = src[src_len];
        src_len++;
    }
    dest[src_len] = '\0';

    // Check if source was fully copied
    return (src[src_len] == '\0');
}

/**
 * Validate integer value is within range
 *
 * @param value  Value to validate
 * @param min    Minimum allowed value
 * @param max    Maximum allowed value
 * @return true if value is within range
 */
static inline bool config_validate_range_u32(uint32_t value, uint32_t min, uint32_t max) {
    return (value >= min && value <= max);
}

static inline bool config_validate_range_u64(uint64_t value, uint64_t min, uint64_t max) {
    return (value >= min && value <= max);
}

#endif // CONFIG_PROTOBUF_H
