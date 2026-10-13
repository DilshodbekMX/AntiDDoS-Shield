/**
 * @file test_security_hardening.c
 * @brief Unit tests for security hardening module
 *
 * Security tests for:
 * - Memory isolation
 * - Input validation
 * - Cryptographic operations
 * - Audit logging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "../../core/security_hardening.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_SECTION(name) printf("\n--- %s ---\n", name)

#define TEST_START(name) do { \
    printf("  [TEST] %s ... ", name); \
    fflush(stdout); \
    tests_run++; \
} while(0)

#define TEST_PASS() do { \
    printf("\033[32mPASS\033[0m\n"); \
    tests_passed++; \
} while(0)

#define TEST_FAIL(msg) do { \
    printf("\033[31mFAIL\033[0m: %s\n", msg); \
    tests_failed++; \
    return; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_FALSE(cond, msg) do { \
    if ((cond)) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_NOT_NULL(ptr, msg) do { \
    if ((ptr) == NULL) { TEST_FAIL(msg); } \
} while(0)

#define ASSERT_NULL(ptr, msg) do { \
    if ((ptr) != NULL) { TEST_FAIL(msg); } \
} while(0)

// ==================== Memory Isolation Tests ====================

static void test_memory_init(void) {
    TEST_START("Memory isolation init/cleanup");

    int ret = sec_memory_init();
    ASSERT_EQ(ret, 0, "Memory init failed");

    sec_memory_cleanup();
    TEST_PASS();
}

static void test_memory_alloc_free(void) {
    TEST_START("Memory alloc/free");

    int ret = sec_memory_init();
    ASSERT_EQ(ret, 0, "Memory init failed");

    // Allocate memory for tenant 1
    void *ptr = sec_memory_alloc(1, 1024, SEC_ISOLATION_LOGICAL);
    ASSERT_NOT_NULL(ptr, "Allocation failed");

    // Write to memory
    memset(ptr, 0xAA, 1024);

    // Free memory
    sec_memory_free(1, ptr);

    sec_memory_cleanup();
    TEST_PASS();
}

static void test_memory_isolation_between_tenants(void) {
    TEST_START("Memory isolation between tenants");

    int ret = sec_memory_init();
    ASSERT_EQ(ret, 0, "Memory init failed");

    // Allocate for tenant 1
    void *ptr1 = sec_memory_alloc(1, 1024, SEC_ISOLATION_LOGICAL);
    ASSERT_NOT_NULL(ptr1, "Tenant 1 allocation failed");

    // Allocate for tenant 2
    void *ptr2 = sec_memory_alloc(2, 1024, SEC_ISOLATION_LOGICAL);
    ASSERT_NOT_NULL(ptr2, "Tenant 2 allocation failed");

    // Verify different addresses
    ASSERT_TRUE(ptr1 != ptr2, "Tenants should have different memory");

    // Verify access control
    ASSERT_TRUE(sec_memory_check_access(1, ptr1, 1024, false),
               "Tenant 1 should access own memory");
    ASSERT_FALSE(sec_memory_check_access(1, ptr2, 1024, false),
                "Tenant 1 should not access tenant 2 memory");
    ASSERT_FALSE(sec_memory_check_access(2, ptr1, 1024, false),
                "Tenant 2 should not access tenant 1 memory");

    sec_memory_free(1, ptr1);
    sec_memory_free(2, ptr2);
    sec_memory_cleanup();
    TEST_PASS();
}

static void test_memory_integrity(void) {
    TEST_START("Memory integrity verification");

    int ret = sec_memory_init();
    ASSERT_EQ(ret, 0, "Memory init failed");

    void *ptr = sec_memory_alloc(1, 1024, SEC_ISOLATION_LOGICAL);
    ASSERT_NOT_NULL(ptr, "Allocation failed");

    // Fill with pattern
    memset(ptr, 0x55, 1024);

    // Verify integrity
    ASSERT_TRUE(sec_memory_verify_integrity(1), "Integrity check should pass");

    sec_memory_free(1, ptr);
    sec_memory_cleanup();
    TEST_PASS();
}

static void test_secure_zero(void) {
    TEST_START("Secure memory zeroing");

    char buffer[256];
    memset(buffer, 0xAA, sizeof(buffer));

    sec_memory_secure_zero(buffer, sizeof(buffer));

    // Verify all bytes are zero
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            TEST_FAIL("Memory not properly zeroed");
        }
    }

    TEST_PASS();
}

// ==================== Input Validation Tests ====================

static void test_validate_ipv4(void) {
    TEST_START("IPv4 validation");

    validation_result_t result;

    // Valid IPv4
    ASSERT_TRUE(sec_validate_ipv4("192.168.1.1", &result), "Valid IPv4 failed");
    ASSERT_TRUE(result.valid, "Result should be valid");

    // Edge cases
    ASSERT_TRUE(sec_validate_ipv4("0.0.0.0", &result), "0.0.0.0 should be valid");
    ASSERT_TRUE(sec_validate_ipv4("255.255.255.255", &result), "255.255.255.255 should be valid");

    // Invalid IPv4
    ASSERT_FALSE(sec_validate_ipv4("256.1.1.1", &result), "256.x.x.x should be invalid");
    ASSERT_FALSE(sec_validate_ipv4("1.2.3", &result), "Incomplete IP should be invalid");
    ASSERT_FALSE(sec_validate_ipv4("not.an.ip.address", &result), "String should be invalid");
    ASSERT_FALSE(sec_validate_ipv4("", &result), "Empty string should be invalid");

    TEST_PASS();
}

static void test_validate_ipv6(void) {
    TEST_START("IPv6 validation");

    validation_result_t result;

    // Valid IPv6
    ASSERT_TRUE(sec_validate_ipv6("2001:db8::1", &result), "Valid IPv6 failed");
    ASSERT_TRUE(sec_validate_ipv6("::1", &result), "Loopback should be valid");
    ASSERT_TRUE(sec_validate_ipv6("::", &result), "All zeros should be valid");
    ASSERT_TRUE(sec_validate_ipv6("fe80::1", &result), "Link local should be valid");

    // Invalid IPv6
    ASSERT_FALSE(sec_validate_ipv6("192.168.1.1", &result), "IPv4 should be invalid for IPv6");
    ASSERT_FALSE(sec_validate_ipv6("not:a:valid:ipv6", &result), "Invalid IPv6 format");

    TEST_PASS();
}

static void test_validate_cidr(void) {
    TEST_START("CIDR validation");

    validation_result_t result;

    // Valid CIDR
    ASSERT_TRUE(sec_validate_cidr("192.168.1.0/24", &result), "Valid CIDR failed");
    ASSERT_TRUE(sec_validate_cidr("10.0.0.0/8", &result), "Class A CIDR failed");
    ASSERT_TRUE(sec_validate_cidr("0.0.0.0/0", &result), "Default route CIDR failed");

    // Valid IPv6 CIDR
    ASSERT_TRUE(sec_validate_cidr("2001:db8::/32", &result), "IPv6 CIDR failed");

    // Invalid CIDR
    ASSERT_FALSE(sec_validate_cidr("192.168.1.0", &result), "Missing prefix length");
    ASSERT_FALSE(sec_validate_cidr("192.168.1.0/33", &result), "IPv4 prefix > 32");
    ASSERT_FALSE(sec_validate_cidr("192.168.1.0/-1", &result), "Negative prefix");

    TEST_PASS();
}

static void test_validate_port(void) {
    TEST_START("Port validation");

    validation_result_t result;

    // Valid ports
    ASSERT_TRUE(sec_validate_port(80, &result), "Port 80 should be valid");
    ASSERT_TRUE(sec_validate_port(443, &result), "Port 443 should be valid");
    ASSERT_TRUE(sec_validate_port(1, &result), "Port 1 should be valid");
    ASSERT_TRUE(sec_validate_port(65535, &result), "Port 65535 should be valid");

    // Invalid ports
    ASSERT_FALSE(sec_validate_port(0, &result), "Port 0 should be invalid");

    TEST_PASS();
}

static void test_validate_tenant_id(void) {
    TEST_START("Tenant ID validation");

    validation_result_t result;

    // Valid tenant IDs
    ASSERT_TRUE(sec_validate_tenant_id(1, &result), "Tenant ID 1 should be valid");
    ASSERT_TRUE(sec_validate_tenant_id(1023, &result), "Tenant ID 1023 should be valid");
    ASSERT_TRUE(sec_validate_tenant_id(500, &result), "Tenant ID 500 should be valid");

    // Invalid tenant IDs
    ASSERT_FALSE(sec_validate_tenant_id(0, &result), "Tenant ID 0 should be invalid");
    ASSERT_FALSE(sec_validate_tenant_id(1024, &result), "Tenant ID 1024 should be invalid");

    TEST_PASS();
}

static void test_validate_string(void) {
    TEST_START("String validation");

    validation_result_t result;

    // Valid strings
    ASSERT_TRUE(sec_validate_string("Hello World", 100, SEC_VALIDATE_ASCII, &result),
               "ASCII string should be valid");

    // Too long
    char long_string[200];
    memset(long_string, 'A', 199);
    long_string[199] = '\0';
    ASSERT_FALSE(sec_validate_string(long_string, 100, 0, &result),
                "String exceeding max length should be invalid");
    ASSERT_EQ(result.violation, SEC_VIOLATION_BUFFER_OVERFLOW, "Should be buffer overflow");

    // NULL string
    ASSERT_FALSE(sec_validate_string(NULL, 100, 0, &result),
                "NULL string should be invalid");

    TEST_PASS();
}

static void test_validate_json(void) {
    TEST_START("JSON validation");

    validation_result_t result;

    // Valid JSON
    ASSERT_TRUE(sec_validate_json("{\"key\":\"value\"}", 1000, &result),
               "Valid JSON failed");
    ASSERT_TRUE(sec_validate_json("{}", 1000, &result),
               "Empty object failed");
    ASSERT_TRUE(sec_validate_json("[]", 1000, &result),
               "Empty array failed");
    ASSERT_TRUE(sec_validate_json("{\"nested\":{\"key\":\"value\"}}", 1000, &result),
               "Nested object failed");

    // Invalid JSON
    ASSERT_FALSE(sec_validate_json("{\"key\":\"value\"", 1000, &result),
                "Unclosed brace should be invalid");
    ASSERT_FALSE(sec_validate_json("{\"key\"}", 1000, &result),
                "Missing value should be valid structure");  // Structure-only check
    ASSERT_FALSE(sec_validate_json("{{}", 1000, &result),
                "Extra brace should be invalid");

    TEST_PASS();
}

static void test_sanitize_string(void) {
    TEST_START("String sanitization");

    char output[256];

    // Test HTML escaping
    int len = sec_sanitize_string("<script>alert('xss')</script>", output, sizeof(output));
    ASSERT_TRUE(len > 0, "Sanitization failed");
    ASSERT_TRUE(strstr(output, "<") == NULL, "< should be escaped");
    ASSERT_TRUE(strstr(output, ">") == NULL, "> should be escaped");

    // Test normal string passes through
    len = sec_sanitize_string("Hello World", output, sizeof(output));
    ASSERT_EQ(strcmp(output, "Hello World"), 0, "Normal string should pass unchanged");

    // Test NULL handling
    len = sec_sanitize_string(NULL, output, sizeof(output));
    ASSERT_EQ(len, -1, "NULL input should return -1");

    TEST_PASS();
}

// ==================== Cryptographic Tests ====================

static void test_crypto_init(void) {
    TEST_START("Crypto subsystem init");

    int ret = sec_crypto_init();
    ASSERT_EQ(ret, 0, "Crypto init failed");

    sec_crypto_cleanup();
    TEST_PASS();
}

static void test_crypto_random(void) {
    TEST_START("Random number generation");

    sec_crypto_init();

    uint8_t buffer1[32];
    uint8_t buffer2[32];

    int ret = sec_crypto_random(buffer1, sizeof(buffer1));
    ASSERT_EQ(ret, 0, "Random generation failed");

    ret = sec_crypto_random(buffer2, sizeof(buffer2));
    ASSERT_EQ(ret, 0, "Second random generation failed");

    // Verify they're different (statistically should never be equal)
    ASSERT_TRUE(memcmp(buffer1, buffer2, 32) != 0, "Random values should be different");

    // Verify not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (buffer1[i] != 0) {
            all_zero = false;
            break;
        }
    }
    ASSERT_FALSE(all_zero, "Random should not be all zeros");

    sec_crypto_cleanup();
    TEST_PASS();
}

static void test_crypto_token(void) {
    TEST_START("Token generation");

    sec_crypto_init();

    char token1[65];
    char token2[65];

    int ret = sec_crypto_generate_token(token1, sizeof(token1));
    ASSERT_EQ(ret, 0, "Token generation failed");

    ret = sec_crypto_generate_token(token2, sizeof(token2));
    ASSERT_EQ(ret, 0, "Second token generation failed");

    // Verify tokens are different
    ASSERT_TRUE(strcmp(token1, token2) != 0, "Tokens should be unique");

    // Verify token is hex string
    for (int i = 0; token1[i]; i++) {
        char c = token1[i];
        ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
                   "Token should be hex string");
    }

    sec_crypto_cleanup();
    TEST_PASS();
}

static void test_crypto_hmac(void) {
    TEST_START("HMAC-SHA256");

    sec_crypto_init();

    uint8_t key[] = "secret-key";
    uint8_t data[] = "Hello, World!";
    uint8_t hmac1[32];
    uint8_t hmac2[32];

    int ret = sec_crypto_hmac_sha256(key, sizeof(key) - 1,
                                     data, sizeof(data) - 1, hmac1);
    ASSERT_EQ(ret, 0, "HMAC generation failed");

    // Same input should produce same output
    ret = sec_crypto_hmac_sha256(key, sizeof(key) - 1,
                                 data, sizeof(data) - 1, hmac2);
    ASSERT_EQ(ret, 0, "Second HMAC failed");
    ASSERT_EQ(memcmp(hmac1, hmac2, 32), 0, "Same input should produce same HMAC");

    // Different data should produce different output
    uint8_t data2[] = "Different data";
    ret = sec_crypto_hmac_sha256(key, sizeof(key) - 1,
                                 data2, sizeof(data2) - 1, hmac2);
    ASSERT_EQ(ret, 0, "Third HMAC failed");
    ASSERT_TRUE(memcmp(hmac1, hmac2, 32) != 0, "Different data should produce different HMAC");

    sec_crypto_cleanup();
    TEST_PASS();
}

// ==================== Audit Logging Tests ====================

static void test_audit_init(void) {
    TEST_START("Audit logging init");

    int ret = sec_audit_init(NULL);  // Use stderr
    ASSERT_EQ(ret, 0, "Audit init failed");

    sec_audit_cleanup();
    TEST_PASS();
}

static void test_audit_log_simple(void) {
    TEST_START("Simple audit logging");

    int ret = sec_audit_init(NULL);
    ASSERT_EQ(ret, 0, "Audit init failed");

    ret = sec_audit_log_simple(AUDIT_LOGIN, 1, "192.168.1.100",
                               "User login successful", true);
    ASSERT_EQ(ret, 0, "Audit log failed");

    ret = sec_audit_log_simple(AUDIT_CONFIG_CHANGE, 1, "192.168.1.100",
                               "Rate limit updated", true);
    ASSERT_EQ(ret, 0, "Config change log failed");

    sec_audit_cleanup();
    TEST_PASS();
}

static void test_audit_log_violation(void) {
    TEST_START("Security violation logging");

    int ret = sec_audit_init(NULL);
    ASSERT_EQ(ret, 0, "Audit init failed");

    ret = sec_audit_log_violation(SEC_VIOLATION_ACCESS_DENIED, 1,
                                  "10.0.0.100", "Attempted cross-tenant access");
    ASSERT_EQ(ret, 0, "Violation log failed");

    ret = sec_audit_log_violation(SEC_VIOLATION_BUFFER_OVERFLOW, 2,
                                  "10.0.0.101", "Input exceeds maximum length");
    ASSERT_EQ(ret, 0, "Buffer overflow log failed");

    sec_audit_cleanup();
    TEST_PASS();
}

// ==================== Rate Limiting Tests ====================

static void test_rate_limiter(void) {
    TEST_START("Rate limiter");

    rate_limiter_t limiter;
    int ret = sec_rate_limiter_init(&limiter, 1000, 5);  // 5 requests per second
    ASSERT_EQ(ret, 0, "Rate limiter init failed");

    // Should allow first 5 requests
    for (int i = 0; i < 5; i++) {
        ASSERT_TRUE(sec_rate_limiter_allow(&limiter),
                   "Request within limit should be allowed");
    }

    // 6th request should be denied
    ASSERT_FALSE(sec_rate_limiter_allow(&limiter),
                "Request over limit should be denied");

    sec_rate_limiter_cleanup(&limiter);
    TEST_PASS();
}

static void test_rate_limiter_reset(void) {
    TEST_START("Rate limiter reset");

    rate_limiter_t limiter;
    int ret = sec_rate_limiter_init(&limiter, 1000, 3);
    ASSERT_EQ(ret, 0, "Rate limiter init failed");

    // Use up the limit
    for (int i = 0; i < 3; i++) {
        sec_rate_limiter_allow(&limiter);
    }
    ASSERT_FALSE(sec_rate_limiter_allow(&limiter), "Should be at limit");

    // Reset and verify we can make requests again
    sec_rate_limiter_reset(&limiter);
    ASSERT_TRUE(sec_rate_limiter_allow(&limiter), "After reset should allow");

    sec_rate_limiter_cleanup(&limiter);
    TEST_PASS();
}

// ==================== Secure Defaults Tests ====================

static void test_secure_defaults(void) {
    TEST_START("Secure defaults application");

    int ret = sec_apply_secure_defaults();
    ASSERT_EQ(ret, 0, "Secure defaults failed");

    // Verify configuration
    char report[4096];
    int failures = sec_verify_configuration(report, sizeof(report));

    printf("\n%s", report);

    ASSERT_EQ(failures, 0, "Configuration verification failed");

    sec_memory_cleanup();
    sec_crypto_cleanup();
    sec_audit_cleanup();
    TEST_PASS();
}

// ==================== Test Runner ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          Security Hardening Unit Tests                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    TEST_SECTION("Memory Isolation");
    test_memory_init();
    test_memory_alloc_free();
    test_memory_isolation_between_tenants();
    test_memory_integrity();
    test_secure_zero();

    TEST_SECTION("Input Validation");
    test_validate_ipv4();
    test_validate_ipv6();
    test_validate_cidr();
    test_validate_port();
    test_validate_tenant_id();
    test_validate_string();
    test_validate_json();
    test_sanitize_string();

    TEST_SECTION("Cryptographic Operations");
    test_crypto_init();
    test_crypto_random();
    test_crypto_token();
    test_crypto_hmac();

    TEST_SECTION("Audit Logging");
    test_audit_init();
    test_audit_log_simple();
    test_audit_log_violation();

    TEST_SECTION("Rate Limiting");
    test_rate_limiter();
    test_rate_limiter_reset();

    TEST_SECTION("Secure Defaults");
    test_secure_defaults();

    // Summary
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                       Test Summary                           ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:  %3d                                                 ║\n", tests_run);
    printf("║  Passed: %3d  \033[32m✓\033[0m                                              ║\n", tests_passed);
    printf("║  Failed: %3d  %s                                              ║\n",
           tests_failed, tests_failed > 0 ? "\033[31m✗\033[0m" : " ");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    if (tests_failed > 0) {
        printf("\n\033[31m[RESULT] SOME TESTS FAILED!\033[0m\n\n");
        return 1;
    }

    printf("\n\033[32m[RESULT] ALL TESTS PASSED!\033[0m\n\n");
    return 0;
}
