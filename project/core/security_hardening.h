/**
 * @file security_hardening.h
 * @brief Security hardening for multi-tenant Anti-DDoS system
 *
 * Security measures:
 * - Tenant memory isolation
 * - Secure data handling
 * - Input validation
 * - Cryptographic operations
 */

#ifndef SECURITY_HARDENING_H
#define SECURITY_HARDENING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ==================== Constants ====================

#define SEC_MAX_KEY_LEN         256
#define SEC_MAX_IV_LEN          16
#define SEC_MAX_SALT_LEN        32
#define SEC_MAX_HASH_LEN        64
#define SEC_MAX_TOKEN_LEN       128
#define SEC_NONCE_LEN           12
#define SEC_TAG_LEN             16

#define SEC_MEMORY_GUARD_BYTES  16
#define SEC_MEMORY_CANARY       0xDEADBEEFCAFEBABEULL

// Memory isolation levels
#define SEC_ISOLATION_NONE      0
#define SEC_ISOLATION_LOGICAL   1
#define SEC_ISOLATION_PHYSICAL  2
#define SEC_ISOLATION_ENCRYPTED 3

// Input validation flags
#define SEC_VALIDATE_IPV4       (1 << 0)
#define SEC_VALIDATE_IPV6       (1 << 1)
#define SEC_VALIDATE_CIDR       (1 << 2)
#define SEC_VALIDATE_PORT       (1 << 3)
#define SEC_VALIDATE_PROTOCOL   (1 << 4)
#define SEC_VALIDATE_TENANT_ID  (1 << 5)
#define SEC_VALIDATE_ASCII      (1 << 6)
#define SEC_VALIDATE_UTF8       (1 << 7)
#define SEC_VALIDATE_JSON       (1 << 8)
#define SEC_VALIDATE_NO_NULL    (1 << 9)

// Audit event types
typedef enum {
    AUDIT_LOGIN = 1,
    AUDIT_LOGOUT,
    AUDIT_CONFIG_CHANGE,
    AUDIT_TENANT_CREATE,
    AUDIT_TENANT_DELETE,
    AUDIT_TENANT_MODIFY,
    AUDIT_BLACKLIST_ADD,
    AUDIT_BLACKLIST_REMOVE,
    AUDIT_WHITELIST_ADD,
    AUDIT_WHITELIST_REMOVE,
    AUDIT_ATTACK_DETECTED,
    AUDIT_ATTACK_MITIGATED,
    AUDIT_POLICY_CHANGE,
    AUDIT_EMERGENCY_MODE,
    AUDIT_SECURITY_VIOLATION,
    AUDIT_ACCESS_DENIED,
    AUDIT_API_CALL,
    AUDIT_DATA_EXPORT,
    AUDIT_KEY_ROTATION,
} audit_event_type_t;

// Security violation types
typedef enum {
    SEC_VIOLATION_NONE = 0,
    SEC_VIOLATION_BUFFER_OVERFLOW,
    SEC_VIOLATION_MEMORY_CORRUPTION,
    SEC_VIOLATION_ACCESS_DENIED,
    SEC_VIOLATION_INVALID_INPUT,
    SEC_VIOLATION_RATE_LIMIT,
    SEC_VIOLATION_AUTH_FAILURE,
    SEC_VIOLATION_CRYPTO_FAILURE,
    SEC_VIOLATION_CANARY_CORRUPT,
    SEC_VIOLATION_CROSS_TENANT,
} security_violation_t;

// ==================== Memory Isolation ====================

/**
 * @brief Tenant memory region descriptor
 */
typedef struct {
    uint32_t tenant_id;
    void *base_addr;
    size_t size;
    uint8_t isolation_level;
    uint64_t canary_start;
    uint64_t canary_end;
    bool read_only;
    bool executable;
    uint8_t encryption_key[SEC_MAX_KEY_LEN];
    uint8_t key_len;
} tenant_memory_region_t;

/**
 * @brief Initialize memory isolation subsystem
 * @return 0 on success, negative on error
 */
int sec_memory_init(void);

/**
 * @brief Cleanup memory isolation subsystem
 */
void sec_memory_cleanup(void);

/**
 * @brief Allocate isolated memory for a tenant
 * @param tenant_id Tenant identifier
 * @param size Requested size in bytes
 * @param isolation_level Isolation level (SEC_ISOLATION_*)
 * @return Pointer to allocated memory, NULL on failure
 */
void *sec_memory_alloc(uint32_t tenant_id, size_t size, uint8_t isolation_level);

/**
 * @brief Free isolated tenant memory
 * @param tenant_id Tenant identifier
 * @param ptr Pointer to memory
 */
void sec_memory_free(uint32_t tenant_id, void *ptr);

/**
 * @brief Verify memory integrity for a tenant
 * @param tenant_id Tenant identifier
 * @return true if integrity check passes
 */
bool sec_memory_verify_integrity(uint32_t tenant_id);

/**
 * @brief Check if memory access is valid for tenant
 * @param tenant_id Tenant identifier
 * @param ptr Pointer to check
 * @param size Access size
 * @param write True for write access, false for read
 * @return true if access is allowed
 */
bool sec_memory_check_access(uint32_t tenant_id, const void *ptr, size_t size, bool write);

/**
 * @brief Securely zero memory
 * @param ptr Pointer to memory
 * @param size Size to zero
 */
void sec_memory_secure_zero(void *ptr, size_t size);

// ==================== Input Validation ====================

/**
 * @brief Validation result
 */
typedef struct {
    bool valid;
    security_violation_t violation;
    char error_message[256];
    int error_position;
} validation_result_t;

/**
 * @brief Validate IPv4 address string
 * @param ip IP address string
 * @param result Validation result
 * @return true if valid
 */
bool sec_validate_ipv4(const char *ip, validation_result_t *result);

/**
 * @brief Validate IPv6 address string
 * @param ip IP address string
 * @param result Validation result
 * @return true if valid
 */
bool sec_validate_ipv6(const char *ip, validation_result_t *result);

/**
 * @brief Validate CIDR notation
 * @param cidr CIDR string (e.g., "192.168.1.0/24")
 * @param result Validation result
 * @return true if valid
 */
bool sec_validate_cidr(const char *cidr, validation_result_t *result);

/**
 * @brief Validate port number
 * @param port Port number
 * @param result Validation result
 * @return true if valid (1-65535)
 */
bool sec_validate_port(uint16_t port, validation_result_t *result);

/**
 * @brief Validate tenant ID
 * @param tenant_id Tenant ID
 * @param result Validation result
 * @return true if valid
 */
bool sec_validate_tenant_id(uint32_t tenant_id, validation_result_t *result);

/**
 * @brief Validate string input
 * @param str Input string
 * @param max_len Maximum allowed length
 * @param flags Validation flags (SEC_VALIDATE_*)
 * @param result Validation result
 * @return true if valid
 */
bool sec_validate_string(const char *str, size_t max_len, uint32_t flags,
                        validation_result_t *result);

/**
 * @brief Validate JSON input
 * @param json JSON string
 * @param max_len Maximum allowed length
 * @param result Validation result
 * @return true if valid
 */
bool sec_validate_json(const char *json, size_t max_len, validation_result_t *result);

/**
 * @brief Sanitize string for safe use
 * @param input Input string
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Number of characters written, or -1 on error
 */
int sec_sanitize_string(const char *input, char *output, size_t output_size);

// ==================== Cryptographic Operations ====================

/**
 * @brief Encryption context
 */
typedef struct {
    uint8_t key[SEC_MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t iv[SEC_MAX_IV_LEN];
    uint8_t nonce[SEC_NONCE_LEN];
    uint32_t counter;
} crypto_context_t;

/**
 * @brief Initialize cryptographic subsystem
 * @return 0 on success
 */
int sec_crypto_init(void);

/**
 * @brief Cleanup cryptographic subsystem
 */
void sec_crypto_cleanup(void);

/**
 * @brief Generate cryptographically secure random bytes
 * @param buffer Output buffer
 * @param size Number of bytes to generate
 * @return 0 on success
 */
int sec_crypto_random(uint8_t *buffer, size_t size);

/**
 * @brief Generate a secure token
 * @param buffer Output buffer
 * @param size Buffer size (should be at least 32 bytes)
 * @return 0 on success
 */
int sec_crypto_generate_token(char *buffer, size_t size);

/**
 * @brief Hash password with salt
 * @param password Password to hash
 * @param salt Salt (or NULL to generate)
 * @param salt_len Salt length
 * @param hash Output hash buffer
 * @param hash_size Hash buffer size
 * @return 0 on success
 */
int sec_crypto_hash_password(const char *password, const uint8_t *salt,
                             size_t salt_len, uint8_t *hash, size_t hash_size);

/**
 * @brief Verify password against hash
 * @param password Password to verify
 * @param salt Salt used during hashing
 * @param salt_len Salt length
 * @param hash Expected hash
 * @param hash_len Hash length
 * @return true if password matches
 */
bool sec_crypto_verify_password(const char *password, const uint8_t *salt,
                                size_t salt_len, const uint8_t *hash, size_t hash_len);

/**
 * @brief Encrypt data with authenticated encryption (AES-GCM)
 * @param ctx Crypto context with key
 * @param plaintext Input data
 * @param plaintext_len Input length
 * @param aad Additional authenticated data (optional)
 * @param aad_len AAD length
 * @param ciphertext Output buffer (plaintext_len + SEC_TAG_LEN)
 * @param tag Authentication tag output
 * @return 0 on success
 */
int sec_crypto_encrypt_aead(const crypto_context_t *ctx,
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *ciphertext, uint8_t *tag);

/**
 * @brief Decrypt data with authenticated encryption (AES-GCM)
 * @param ctx Crypto context with key
 * @param ciphertext Input data
 * @param ciphertext_len Input length
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param tag Authentication tag
 * @param plaintext Output buffer
 * @return 0 on success, negative if authentication fails
 */
int sec_crypto_decrypt_aead(const crypto_context_t *ctx,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *tag, uint8_t *plaintext);

/**
 * @brief Derive key from password (PBKDF2)
 * @param password Password
 * @param salt Salt
 * @param salt_len Salt length
 * @param iterations Number of iterations
 * @param key Output key buffer
 * @param key_len Desired key length
 * @return 0 on success
 */
int sec_crypto_derive_key(const char *password, const uint8_t *salt,
                          size_t salt_len, uint32_t iterations,
                          uint8_t *key, size_t key_len);

/**
 * @brief Generate HMAC-SHA256
 * @param key HMAC key
 * @param key_len Key length
 * @param data Input data
 * @param data_len Data length
 * @param hmac Output buffer (32 bytes)
 * @return 0 on success
 */
int sec_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *hmac);

// ==================== Audit Logging ====================

/**
 * @brief Audit log entry
 */
typedef struct {
    uint64_t timestamp_ns;
    audit_event_type_t event_type;
    uint32_t tenant_id;
    uint32_t user_id;
    char source_ip[64];
    char resource[256];
    char action[128];
    char details[1024];
    bool success;
    security_violation_t violation;
} audit_entry_t;

/**
 * @brief Initialize audit logging
 * @param log_path Path to audit log file
 * @return 0 on success
 */
int sec_audit_init(const char *log_path);

/**
 * @brief Cleanup audit logging
 */
void sec_audit_cleanup(void);

/**
 * @brief Log an audit event
 * @param entry Audit entry
 * @return 0 on success
 */
int sec_audit_log(const audit_entry_t *entry);

/**
 * @brief Log a simple audit event
 * @param event_type Event type
 * @param tenant_id Tenant ID (0 for system)
 * @param source_ip Source IP address
 * @param message Event message
 * @param success Whether event succeeded
 * @return 0 on success
 */
int sec_audit_log_simple(audit_event_type_t event_type, uint32_t tenant_id,
                         const char *source_ip, const char *message, bool success);

/**
 * @brief Log a security violation
 * @param violation Violation type
 * @param tenant_id Tenant ID (0 for system)
 * @param source_ip Source IP
 * @param details Violation details
 * @return 0 on success
 */
int sec_audit_log_violation(security_violation_t violation, uint32_t tenant_id,
                            const char *source_ip, const char *details);

// ==================== Rate Limiting ====================

/**
 * @brief Rate limiter state
 */
typedef struct {
    uint32_t window_size_ms;
    uint32_t max_requests;
    uint64_t *timestamps;
    size_t count;
    size_t capacity;
    size_t head;
} rate_limiter_t;

/**
 * @brief Initialize a rate limiter
 * @param limiter Rate limiter
 * @param window_size_ms Time window in milliseconds
 * @param max_requests Maximum requests in window
 * @return 0 on success
 */
int sec_rate_limiter_init(rate_limiter_t *limiter, uint32_t window_size_ms,
                          uint32_t max_requests);

/**
 * @brief Cleanup rate limiter
 * @param limiter Rate limiter
 */
void sec_rate_limiter_cleanup(rate_limiter_t *limiter);

/**
 * @brief Check if request is allowed
 * @param limiter Rate limiter
 * @return true if request is allowed
 */
bool sec_rate_limiter_allow(rate_limiter_t *limiter);

/**
 * @brief Reset rate limiter
 * @param limiter Rate limiter
 */
void sec_rate_limiter_reset(rate_limiter_t *limiter);

// ==================== Secure Defaults ====================

/**
 * @brief Apply secure default settings
 * @return 0 on success
 */
int sec_apply_secure_defaults(void);

/**
 * @brief Verify system security configuration
 * @param report Output buffer for report
 * @param report_size Report buffer size
 * @return 0 if all checks pass, number of failures otherwise
 */
int sec_verify_configuration(char *report, size_t report_size);

/**
 * @brief Enable security monitoring
 * @param callback Callback for security events
 * @return 0 on success
 */
typedef void (*security_callback_t)(security_violation_t violation,
                                    uint32_t tenant_id, const char *details);
int sec_enable_monitoring(security_callback_t callback);

#endif /* SECURITY_HARDENING_H */
