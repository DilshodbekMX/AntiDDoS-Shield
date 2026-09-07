/**
 * @file security_hardening.c
 * @brief Security hardening implementation for multi-tenant Anti-DDoS system
 *
 * Implementation of:
 * - Tenant memory isolation
 * - Input validation
 * - Cryptographic operations
 * - Audit logging
 */

#include "security_hardening.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

// ==================== Memory Isolation ====================

#define MAX_MEMORY_REGIONS 4096
#define GUARD_PAGE_SIZE 4096

typedef struct {
    tenant_memory_region_t regions[MAX_MEMORY_REGIONS];
    size_t count;
    pthread_mutex_t lock;
    bool initialized;
} memory_isolation_state_t;

static memory_isolation_state_t mem_state = {
    .count = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .initialized = false,
};

int sec_memory_init(void) {
    pthread_mutex_lock(&mem_state.lock);

    if (mem_state.initialized) {
        pthread_mutex_unlock(&mem_state.lock);
        return 0;
    }

    memset(mem_state.regions, 0, sizeof(mem_state.regions));
    mem_state.count = 0;
    mem_state.initialized = true;

    pthread_mutex_unlock(&mem_state.lock);
    return 0;
}

void sec_memory_cleanup(void) {
    pthread_mutex_lock(&mem_state.lock);

    for (size_t i = 0; i < mem_state.count; i++) {
        if (mem_state.regions[i].base_addr) {
            // Securely zero before freeing
            sec_memory_secure_zero(mem_state.regions[i].base_addr,
                                   mem_state.regions[i].size);

            // Free with guard pages if used
            if (mem_state.regions[i].isolation_level >= SEC_ISOLATION_PHYSICAL) {
                munmap((char*)mem_state.regions[i].base_addr - GUARD_PAGE_SIZE,
                       mem_state.regions[i].size + 2 * GUARD_PAGE_SIZE);
            } else {
                free(mem_state.regions[i].base_addr);
            }
        }
    }

    mem_state.count = 0;
    mem_state.initialized = false;

    pthread_mutex_unlock(&mem_state.lock);
}

void *sec_memory_alloc(uint32_t tenant_id, size_t size, uint8_t isolation_level) {
    if (!mem_state.initialized || size == 0) {
        return NULL;
    }

    pthread_mutex_lock(&mem_state.lock);

    if (mem_state.count >= MAX_MEMORY_REGIONS) {
        pthread_mutex_unlock(&mem_state.lock);
        return NULL;
    }

    void *ptr = NULL;
    size_t alloc_size = size + 2 * SEC_MEMORY_GUARD_BYTES;

    if (isolation_level >= SEC_ISOLATION_PHYSICAL) {
        // Use mmap with guard pages for physical isolation
        size_t total_size = alloc_size + 2 * GUARD_PAGE_SIZE;
        void *mapped = mmap(NULL, total_size, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapped == MAP_FAILED) {
            pthread_mutex_unlock(&mem_state.lock);
            return NULL;
        }

        // Make the middle portion read/write
        ptr = (char*)mapped + GUARD_PAGE_SIZE;
        if (mprotect(ptr, alloc_size, PROT_READ | PROT_WRITE) != 0) {
            munmap(mapped, total_size);
            pthread_mutex_unlock(&mem_state.lock);
            return NULL;
        }
    } else {
        // Standard allocation for logical isolation
        ptr = malloc(alloc_size);
        if (!ptr) {
            pthread_mutex_unlock(&mem_state.lock);
            return NULL;
        }
    }

    // Zero the memory
    memset(ptr, 0, alloc_size);

    // Set up canaries
    uint64_t *canary_start = (uint64_t*)ptr;
    uint64_t *canary_end = (uint64_t*)((char*)ptr + alloc_size - sizeof(uint64_t));
    *canary_start = SEC_MEMORY_CANARY;
    *canary_end = SEC_MEMORY_CANARY;

    // Record the region
    tenant_memory_region_t *region = &mem_state.regions[mem_state.count];
    region->tenant_id = tenant_id;
    region->base_addr = (char*)ptr + SEC_MEMORY_GUARD_BYTES;
    region->size = size;
    region->isolation_level = isolation_level;
    region->canary_start = SEC_MEMORY_CANARY;
    region->canary_end = SEC_MEMORY_CANARY;
    region->read_only = false;
    region->executable = false;
    region->key_len = 0;

    mem_state.count++;

    pthread_mutex_unlock(&mem_state.lock);

    return region->base_addr;
}

void sec_memory_free(uint32_t tenant_id, void *ptr) {
    if (!ptr || !mem_state.initialized) {
        return;
    }

    pthread_mutex_lock(&mem_state.lock);

    for (size_t i = 0; i < mem_state.count; i++) {
        if (mem_state.regions[i].base_addr == ptr &&
            mem_state.regions[i].tenant_id == tenant_id) {

            // Verify canaries
            char *base = (char*)ptr - SEC_MEMORY_GUARD_BYTES;
            uint64_t *canary_start = (uint64_t*)base;
            uint64_t *canary_end = (uint64_t*)(base + mem_state.regions[i].size +
                                                2 * SEC_MEMORY_GUARD_BYTES - sizeof(uint64_t));

            if (*canary_start != SEC_MEMORY_CANARY || *canary_end != SEC_MEMORY_CANARY) {
                // Memory corruption detected!
                sec_audit_log_violation(SEC_VIOLATION_CANARY_CORRUPT, tenant_id,
                                       "system", "Memory canary corruption detected");
            }

            // Securely zero
            sec_memory_secure_zero(base, mem_state.regions[i].size + 2 * SEC_MEMORY_GUARD_BYTES);

            // Free memory
            if (mem_state.regions[i].isolation_level >= SEC_ISOLATION_PHYSICAL) {
                munmap(base - GUARD_PAGE_SIZE,
                       mem_state.regions[i].size + 2 * SEC_MEMORY_GUARD_BYTES + 2 * GUARD_PAGE_SIZE);
            } else {
                free(base);
            }

            // Remove from tracking
            if (i < mem_state.count - 1) {
                memmove(&mem_state.regions[i], &mem_state.regions[i + 1],
                       (mem_state.count - i - 1) * sizeof(tenant_memory_region_t));
            }
            mem_state.count--;
            break;
        }
    }

    pthread_mutex_unlock(&mem_state.lock);
}

bool sec_memory_verify_integrity(uint32_t tenant_id) {
    if (!mem_state.initialized) {
        return false;
    }

    pthread_mutex_lock(&mem_state.lock);

    bool all_valid = true;

    for (size_t i = 0; i < mem_state.count; i++) {
        if (mem_state.regions[i].tenant_id == tenant_id) {
            char *base = (char*)mem_state.regions[i].base_addr - SEC_MEMORY_GUARD_BYTES;
            uint64_t *canary_start = (uint64_t*)base;
            uint64_t *canary_end = (uint64_t*)(base + mem_state.regions[i].size +
                                                2 * SEC_MEMORY_GUARD_BYTES - sizeof(uint64_t));

            if (*canary_start != SEC_MEMORY_CANARY || *canary_end != SEC_MEMORY_CANARY) {
                all_valid = false;
                sec_audit_log_violation(SEC_VIOLATION_MEMORY_CORRUPTION, tenant_id,
                                       "system", "Memory integrity check failed");
            }
        }
    }

    pthread_mutex_unlock(&mem_state.lock);
    return all_valid;
}

bool sec_memory_check_access(uint32_t tenant_id, const void *ptr, size_t size, bool write) {
    if (!ptr || !mem_state.initialized) {
        return false;
    }

    pthread_mutex_lock(&mem_state.lock);

    bool allowed = false;

    for (size_t i = 0; i < mem_state.count; i++) {
        if (mem_state.regions[i].tenant_id == tenant_id) {
            const char *region_start = mem_state.regions[i].base_addr;
            const char *region_end = region_start + mem_state.regions[i].size;
            const char *access_start = ptr;
            const char *access_end = access_start + size;

            if (access_start >= region_start && access_end <= region_end) {
                // Check write permission
                if (write && mem_state.regions[i].read_only) {
                    allowed = false;
                } else {
                    allowed = true;
                }
                break;
            }
        }
    }

    pthread_mutex_unlock(&mem_state.lock);

    if (!allowed) {
        sec_audit_log_violation(SEC_VIOLATION_ACCESS_DENIED, tenant_id,
                               "system", "Unauthorized memory access attempt");
    }

    return allowed;
}

void sec_memory_secure_zero(void *ptr, size_t size) {
    if (!ptr || size == 0) {
        return;
    }

    // Use volatile to prevent compiler optimization
    volatile unsigned char *p = (volatile unsigned char*)ptr;
    while (size--) {
        *p++ = 0;
    }

    // Memory barrier to ensure the zeroing is complete
    __asm__ volatile("" ::: "memory");
}

// ==================== Input Validation ====================

bool sec_validate_ipv4(const char *ip, validation_result_t *result) {
    if (!ip || !result) {
        if (result) {
            result->valid = false;
            result->violation = SEC_VIOLATION_INVALID_INPUT;
            snprintf(result->error_message, sizeof(result->error_message),
                    "NULL input");
        }
        return false;
    }

    struct in_addr addr;
    int ret = inet_pton(AF_INET, ip, &addr);

    if (ret == 1) {
        result->valid = true;
        result->violation = SEC_VIOLATION_NONE;
        result->error_message[0] = '\0';
        result->error_position = -1;
        return true;
    }

    result->valid = false;
    result->violation = SEC_VIOLATION_INVALID_INPUT;
    snprintf(result->error_message, sizeof(result->error_message),
            "Invalid IPv4 address format");
    result->error_position = 0;
    return false;
}

bool sec_validate_ipv6(const char *ip, validation_result_t *result) {
    if (!ip || !result) {
        if (result) {
            result->valid = false;
            result->violation = SEC_VIOLATION_INVALID_INPUT;
            snprintf(result->error_message, sizeof(result->error_message),
                    "NULL input");
        }
        return false;
    }

    struct in6_addr addr;
    int ret = inet_pton(AF_INET6, ip, &addr);

    if (ret == 1) {
        result->valid = true;
        result->violation = SEC_VIOLATION_NONE;
        result->error_message[0] = '\0';
        result->error_position = -1;
        return true;
    }

    result->valid = false;
    result->violation = SEC_VIOLATION_INVALID_INPUT;
    snprintf(result->error_message, sizeof(result->error_message),
            "Invalid IPv6 address format");
    result->error_position = 0;
    return false;
}

bool sec_validate_cidr(const char *cidr, validation_result_t *result) {
    if (!cidr || !result) {
        if (result) {
            result->valid = false;
            result->violation = SEC_VIOLATION_INVALID_INPUT;
            snprintf(result->error_message, sizeof(result->error_message),
                    "NULL input");
        }
        return false;
    }

    // Find the slash
    const char *slash = strchr(cidr, '/');
    if (!slash) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Missing prefix length (no '/' found)");
        result->error_position = strlen(cidr);
        return false;
    }

    // Extract IP and prefix
    size_t ip_len = slash - cidr;
    if (ip_len >= 64) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "IP address too long");
        result->error_position = 0;
        return false;
    }

    char ip[64];
    strncpy(ip, cidr, ip_len);
    ip[ip_len] = '\0';

    // Parse prefix length
    int prefix = atoi(slash + 1);

    // Determine if IPv4 or IPv6
    bool is_ipv6 = strchr(ip, ':') != NULL;

    // Validate IP
    validation_result_t ip_result;
    bool ip_valid = is_ipv6 ? sec_validate_ipv6(ip, &ip_result)
                            : sec_validate_ipv4(ip, &ip_result);

    if (!ip_valid) {
        *result = ip_result;
        return false;
    }

    // Validate prefix
    int max_prefix = is_ipv6 ? 128 : 32;
    if (prefix < 0 || prefix > max_prefix) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Invalid prefix length: %d (must be 0-%d)", prefix, max_prefix);
        result->error_position = slash - cidr + 1;
        return false;
    }

    result->valid = true;
    result->violation = SEC_VIOLATION_NONE;
    result->error_message[0] = '\0';
    result->error_position = -1;
    return true;
}

bool sec_validate_port(uint16_t port, validation_result_t *result) {
    if (!result) {
        return port >= 1 && port <= 65535;
    }

    if (port < 1 || port > 65535) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Invalid port: %u (must be 1-65535)", port);
        result->error_position = 0;
        return false;
    }

    result->valid = true;
    result->violation = SEC_VIOLATION_NONE;
    result->error_message[0] = '\0';
    result->error_position = -1;
    return true;
}

bool sec_validate_tenant_id(uint32_t tenant_id, validation_result_t *result) {
    if (!result) {
        return tenant_id >= 1 && tenant_id <= 1023;
    }

    if (tenant_id < 1 || tenant_id > 1023) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Invalid tenant ID: %u (must be 1-1023)", tenant_id);
        result->error_position = 0;
        return false;
    }

    result->valid = true;
    result->violation = SEC_VIOLATION_NONE;
    result->error_message[0] = '\0';
    result->error_position = -1;
    return true;
}

bool sec_validate_string(const char *str, size_t max_len, uint32_t flags,
                        validation_result_t *result) {
    if (!result) {
        return str != NULL;
    }

    if (!str) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "NULL string");
        result->error_position = -1;
        return false;
    }

    size_t len = strlen(str);
    if (len > max_len) {
        result->valid = false;
        result->violation = SEC_VIOLATION_BUFFER_OVERFLOW;
        snprintf(result->error_message, sizeof(result->error_message),
                "String too long: %zu (max %zu)", len, max_len);
        result->error_position = max_len;
        return false;
    }

    // Check for null bytes
    if (flags & SEC_VALIDATE_NO_NULL) {
        for (size_t i = 0; i < len; i++) {
            if (str[i] == '\0') {
                result->valid = false;
                result->violation = SEC_VIOLATION_INVALID_INPUT;
                snprintf(result->error_message, sizeof(result->error_message),
                        "Embedded null byte at position %zu", i);
                result->error_position = i;
                return false;
            }
        }
    }

    // Check ASCII
    if (flags & SEC_VALIDATE_ASCII) {
        for (size_t i = 0; i < len; i++) {
            if ((unsigned char)str[i] > 127) {
                result->valid = false;
                result->violation = SEC_VIOLATION_INVALID_INPUT;
                snprintf(result->error_message, sizeof(result->error_message),
                        "Non-ASCII character at position %zu", i);
                result->error_position = i;
                return false;
            }
        }
    }

    // Check UTF-8 (simplified check)
    if (flags & SEC_VALIDATE_UTF8) {
        for (size_t i = 0; i < len; i++) {
            unsigned char c = str[i];

            // Check for invalid UTF-8 start bytes
            if (c == 0xC0 || c == 0xC1 || c >= 0xF5) {
                result->valid = false;
                result->violation = SEC_VIOLATION_INVALID_INPUT;
                snprintf(result->error_message, sizeof(result->error_message),
                        "Invalid UTF-8 sequence at position %zu", i);
                result->error_position = i;
                return false;
            }
        }
    }

    result->valid = true;
    result->violation = SEC_VIOLATION_NONE;
    result->error_message[0] = '\0';
    result->error_position = -1;
    return true;
}

bool sec_validate_json(const char *json, size_t max_len, validation_result_t *result) {
    // First validate as string
    if (!sec_validate_string(json, max_len, SEC_VALIDATE_UTF8, result)) {
        return false;
    }

    // Simple JSON structure validation
    int braces = 0;
    int brackets = 0;
    bool in_string = false;
    bool escape_next = false;

    for (size_t i = 0; json[i]; i++) {
        char c = json[i];

        if (escape_next) {
            escape_next = false;
            continue;
        }

        if (c == '\\' && in_string) {
            escape_next = true;
            continue;
        }

        if (c == '"') {
            in_string = !in_string;
        } else if (!in_string) {
            if (c == '{') braces++;
            else if (c == '}') {
                braces--;
                if (braces < 0) {
                    result->valid = false;
                    result->violation = SEC_VIOLATION_INVALID_INPUT;
                    snprintf(result->error_message, sizeof(result->error_message),
                            "Unmatched '}' at position %zu", i);
                    result->error_position = i;
                    return false;
                }
            }
            else if (c == '[') brackets++;
            else if (c == ']') {
                brackets--;
                if (brackets < 0) {
                    result->valid = false;
                    result->violation = SEC_VIOLATION_INVALID_INPUT;
                    snprintf(result->error_message, sizeof(result->error_message),
                            "Unmatched ']' at position %zu", i);
                    result->error_position = i;
                    return false;
                }
            }
        }
    }

    if (in_string) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Unclosed string");
        result->error_position = strlen(json);
        return false;
    }

    if (braces != 0) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Unmatched braces: %d open", braces);
        result->error_position = strlen(json);
        return false;
    }

    if (brackets != 0) {
        result->valid = false;
        result->violation = SEC_VIOLATION_INVALID_INPUT;
        snprintf(result->error_message, sizeof(result->error_message),
                "Unmatched brackets: %d open", brackets);
        result->error_position = strlen(json);
        return false;
    }

    result->valid = true;
    result->violation = SEC_VIOLATION_NONE;
    result->error_message[0] = '\0';
    result->error_position = -1;
    return true;
}

int sec_sanitize_string(const char *input, char *output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return -1;
    }

    size_t out_pos = 0;
    size_t max_out = output_size - 1;  // Leave room for null terminator

    for (size_t i = 0; input[i] && out_pos < max_out; i++) {
        char c = input[i];

        // Allow printable ASCII characters
        if (c >= 32 && c < 127) {
            // Escape special characters
            if (c == '<' && out_pos + 4 < max_out) {
                memcpy(output + out_pos, "&lt;", 4);
                out_pos += 4;
            } else if (c == '>' && out_pos + 4 < max_out) {
                memcpy(output + out_pos, "&gt;", 4);
                out_pos += 4;
            } else if (c == '&' && out_pos + 5 < max_out) {
                memcpy(output + out_pos, "&amp;", 5);
                out_pos += 5;
            } else if (c == '"' && out_pos + 6 < max_out) {
                memcpy(output + out_pos, "&quot;", 6);
                out_pos += 6;
            } else if (c == '\'' && out_pos + 5 < max_out) {
                memcpy(output + out_pos, "&#39;", 5);
                out_pos += 5;
            } else {
                output[out_pos++] = c;
            }
        } else if (c == '\n' || c == '\r' || c == '\t') {
            // Allow common whitespace
            output[out_pos++] = c;
        }
        // Skip other characters
    }

    output[out_pos] = '\0';
    return out_pos;
}

// ==================== Cryptographic Operations ====================

static bool crypto_initialized = false;

int sec_crypto_init(void) {
    if (crypto_initialized) {
        return 0;
    }

    // In production, initialize crypto library (OpenSSL, etc.)
    crypto_initialized = true;
    return 0;
}

void sec_crypto_cleanup(void) {
    crypto_initialized = false;
}

int sec_crypto_random(uint8_t *buffer, size_t size) {
    if (!buffer || size == 0) {
        return -1;
    }

    // Use /dev/urandom for cryptographically secure random bytes
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t bytes_read = read(fd, buffer, size);
    close(fd);

    if (bytes_read != (ssize_t)size) {
        return -1;
    }

    return 0;
}

int sec_crypto_generate_token(char *buffer, size_t size) {
    if (!buffer || size < 32) {
        return -1;
    }

    uint8_t random_bytes[32];
    if (sec_crypto_random(random_bytes, sizeof(random_bytes)) != 0) {
        return -1;
    }

    // Convert to hex string
    const char hex[] = "0123456789abcdef";
    size_t out_len = 0;

    for (size_t i = 0; i < sizeof(random_bytes) && out_len < size - 1; i++) {
        buffer[out_len++] = hex[random_bytes[i] >> 4];
        if (out_len < size - 1) {
            buffer[out_len++] = hex[random_bytes[i] & 0x0f];
        }
    }

    buffer[out_len] = '\0';

    // Secure zero the random bytes
    sec_memory_secure_zero(random_bytes, sizeof(random_bytes));

    return 0;
}

int sec_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *hmac) {
    if (!key || !data || !hmac) {
        return -1;
    }
    (void)key_len;
    (void)data_len;

    /*
     * Not implemented. This module ships no real HMAC-SHA256. A previous
     * placeholder XOR-mixed the key and data and returned success with a
     * forgeable, INSECURE MAC — a security trap. It has been removed and this
     * function now fails closed: callers must use a vetted crypto library
     * (e.g. OpenSSL HMAC_SHA256) rather than relying on this stub. The output
     * buffer is zeroed so a caller that ignores the return value cannot mistake
     * stale memory for a valid tag.
     */
    memset(hmac, 0, 32);
    return -1;
}

// ==================== Audit Logging ====================

static struct {
    FILE *log_file;
    pthread_mutex_t lock;
    bool initialized;
    char log_path[256];
} audit_state = {
    .log_file = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .initialized = false,
};

int sec_audit_init(const char *log_path) {
    pthread_mutex_lock(&audit_state.lock);

    if (audit_state.initialized) {
        pthread_mutex_unlock(&audit_state.lock);
        return 0;
    }

    if (log_path) {
        strncpy(audit_state.log_path, log_path, sizeof(audit_state.log_path) - 1);
        audit_state.log_file = fopen(log_path, "a");
        if (!audit_state.log_file) {
            pthread_mutex_unlock(&audit_state.lock);
            return -1;
        }
    } else {
        audit_state.log_file = stderr;
    }

    audit_state.initialized = true;

    pthread_mutex_unlock(&audit_state.lock);
    return 0;
}

void sec_audit_cleanup(void) {
    pthread_mutex_lock(&audit_state.lock);

    if (audit_state.log_file && audit_state.log_file != stderr) {
        fclose(audit_state.log_file);
    }

    audit_state.log_file = NULL;
    audit_state.initialized = false;

    pthread_mutex_unlock(&audit_state.lock);
}

static const char* audit_event_name(audit_event_type_t type) {
    switch (type) {
        case AUDIT_LOGIN: return "LOGIN";
        case AUDIT_LOGOUT: return "LOGOUT";
        case AUDIT_CONFIG_CHANGE: return "CONFIG_CHANGE";
        case AUDIT_TENANT_CREATE: return "TENANT_CREATE";
        case AUDIT_TENANT_DELETE: return "TENANT_DELETE";
        case AUDIT_TENANT_MODIFY: return "TENANT_MODIFY";
        case AUDIT_BLACKLIST_ADD: return "BLACKLIST_ADD";
        case AUDIT_BLACKLIST_REMOVE: return "BLACKLIST_REMOVE";
        case AUDIT_WHITELIST_ADD: return "WHITELIST_ADD";
        case AUDIT_WHITELIST_REMOVE: return "WHITELIST_REMOVE";
        case AUDIT_ATTACK_DETECTED: return "ATTACK_DETECTED";
        case AUDIT_ATTACK_MITIGATED: return "ATTACK_MITIGATED";
        case AUDIT_POLICY_CHANGE: return "POLICY_CHANGE";
        case AUDIT_EMERGENCY_MODE: return "EMERGENCY_MODE";
        case AUDIT_SECURITY_VIOLATION: return "SECURITY_VIOLATION";
        case AUDIT_ACCESS_DENIED: return "ACCESS_DENIED";
        case AUDIT_API_CALL: return "API_CALL";
        case AUDIT_DATA_EXPORT: return "DATA_EXPORT";
        case AUDIT_KEY_ROTATION: return "KEY_ROTATION";
        default: return "UNKNOWN";
    }
}

static const char* violation_name(security_violation_t type) {
    switch (type) {
        case SEC_VIOLATION_NONE: return "NONE";
        case SEC_VIOLATION_BUFFER_OVERFLOW: return "BUFFER_OVERFLOW";
        case SEC_VIOLATION_MEMORY_CORRUPTION: return "MEMORY_CORRUPTION";
        case SEC_VIOLATION_ACCESS_DENIED: return "ACCESS_DENIED";
        case SEC_VIOLATION_INVALID_INPUT: return "INVALID_INPUT";
        case SEC_VIOLATION_RATE_LIMIT: return "RATE_LIMIT";
        case SEC_VIOLATION_AUTH_FAILURE: return "AUTH_FAILURE";
        case SEC_VIOLATION_CRYPTO_FAILURE: return "CRYPTO_FAILURE";
        case SEC_VIOLATION_CANARY_CORRUPT: return "CANARY_CORRUPT";
        case SEC_VIOLATION_CROSS_TENANT: return "CROSS_TENANT";
        default: return "UNKNOWN";
    }
}

int sec_audit_log(const audit_entry_t *entry) {
    if (!entry || !audit_state.initialized) {
        return -1;
    }

    pthread_mutex_lock(&audit_state.lock);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    fprintf(audit_state.log_file,
            "{\"timestamp\":%lu.%09lu,\"event\":\"%s\",\"tenant_id\":%u,"
            "\"user_id\":%u,\"source_ip\":\"%s\",\"resource\":\"%s\","
            "\"action\":\"%s\",\"success\":%s,\"violation\":\"%s\","
            "\"details\":\"%s\"}\n",
            ts.tv_sec, ts.tv_nsec,
            audit_event_name(entry->event_type),
            entry->tenant_id,
            entry->user_id,
            entry->source_ip,
            entry->resource,
            entry->action,
            entry->success ? "true" : "false",
            violation_name(entry->violation),
            entry->details);

    fflush(audit_state.log_file);

    pthread_mutex_unlock(&audit_state.lock);
    return 0;
}

int sec_audit_log_simple(audit_event_type_t event_type, uint32_t tenant_id,
                         const char *source_ip, const char *message, bool success) {
    audit_entry_t entry = {0};
    entry.event_type = event_type;
    entry.tenant_id = tenant_id;
    entry.success = success;
    entry.violation = SEC_VIOLATION_NONE;

    if (source_ip) {
        strncpy(entry.source_ip, source_ip, sizeof(entry.source_ip) - 1);
    }

    if (message) {
        strncpy(entry.details, message, sizeof(entry.details) - 1);
    }

    return sec_audit_log(&entry);
}

int sec_audit_log_violation(security_violation_t violation, uint32_t tenant_id,
                            const char *source_ip, const char *details) {
    audit_entry_t entry = {0};
    entry.event_type = AUDIT_SECURITY_VIOLATION;
    entry.tenant_id = tenant_id;
    entry.success = false;
    entry.violation = violation;

    if (source_ip) {
        strncpy(entry.source_ip, source_ip, sizeof(entry.source_ip) - 1);
    }

    if (details) {
        strncpy(entry.details, details, sizeof(entry.details) - 1);
    }

    return sec_audit_log(&entry);
}

// ==================== Rate Limiting ====================

int sec_rate_limiter_init(rate_limiter_t *limiter, uint32_t window_size_ms,
                          uint32_t max_requests) {
    if (!limiter) {
        return -1;
    }

    limiter->window_size_ms = window_size_ms;
    limiter->max_requests = max_requests;
    limiter->capacity = max_requests * 2;  // Buffer for sliding window
    limiter->timestamps = calloc(limiter->capacity, sizeof(uint64_t));
    limiter->count = 0;
    limiter->head = 0;

    if (!limiter->timestamps) {
        return -1;
    }

    return 0;
}

void sec_rate_limiter_cleanup(rate_limiter_t *limiter) {
    if (limiter && limiter->timestamps) {
        free(limiter->timestamps);
        limiter->timestamps = NULL;
    }
}

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

bool sec_rate_limiter_allow(rate_limiter_t *limiter) {
    if (!limiter || !limiter->timestamps) {
        return false;
    }

    uint64_t now = get_time_ms();
    uint64_t window_start = now - limiter->window_size_ms;

    // Remove expired entries
    while (limiter->count > 0 && limiter->timestamps[limiter->head] < window_start) {
        limiter->head = (limiter->head + 1) % limiter->capacity;
        limiter->count--;
    }

    // Check if under limit
    if (limiter->count >= limiter->max_requests) {
        return false;
    }

    // Add new timestamp
    size_t tail = (limiter->head + limiter->count) % limiter->capacity;
    limiter->timestamps[tail] = now;
    limiter->count++;

    return true;
}

void sec_rate_limiter_reset(rate_limiter_t *limiter) {
    if (limiter) {
        limiter->count = 0;
        limiter->head = 0;
    }
}

// ==================== Secure Defaults ====================

int sec_apply_secure_defaults(void) {
    // Initialize all security subsystems
    if (sec_memory_init() != 0) {
        return -1;
    }

    if (sec_crypto_init() != 0) {
        return -1;
    }

    if (sec_audit_init(NULL) != 0) {
        return -1;
    }

    // Log security initialization
    sec_audit_log_simple(AUDIT_CONFIG_CHANGE, 0, "system",
                        "Security hardening initialized", true);

    return 0;
}

int sec_verify_configuration(char *report, size_t report_size) {
    if (!report || report_size == 0) {
        return -1;
    }

    int failures = 0;
    size_t offset = 0;

    // Check memory isolation
    offset += snprintf(report + offset, report_size - offset,
                      "Security Configuration Report\n");
    offset += snprintf(report + offset, report_size - offset,
                      "==============================\n\n");

    offset += snprintf(report + offset, report_size - offset,
                      "[%s] Memory isolation initialized\n",
                      mem_state.initialized ? "OK" : "FAIL");
    if (!mem_state.initialized) failures++;

    offset += snprintf(report + offset, report_size - offset,
                      "[%s] Cryptographic subsystem initialized\n",
                      crypto_initialized ? "OK" : "FAIL");
    if (!crypto_initialized) failures++;

    offset += snprintf(report + offset, report_size - offset,
                      "[%s] Audit logging initialized\n",
                      audit_state.initialized ? "OK" : "FAIL");
    if (!audit_state.initialized) failures++;

    // Test random number generation
    uint8_t test_random[16];
    bool random_ok = (sec_crypto_random(test_random, sizeof(test_random)) == 0);
    offset += snprintf(report + offset, report_size - offset,
                      "[%s] Random number generation\n",
                      random_ok ? "OK" : "FAIL");
    if (!random_ok) failures++;

    offset += snprintf(report + offset, report_size - offset,
                      "\nTotal failures: %d\n", failures);

    return failures;
}

static security_callback_t security_monitor_callback = NULL;

int sec_enable_monitoring(security_callback_t callback) {
    security_monitor_callback = callback;
    return 0;
}
