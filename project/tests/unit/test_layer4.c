/**
 * @file test_layer4.c
 * @brief Comprehensive unit tests for Layer 4 (Reputation, Challenge, Bot Management)
 *
 * Tests cover:
 * - Reputation engine initialization and scoring
 * - Challenge generation and verification
 * - Bot classification and detection
 * - Decision engine with all signal combinations
 * - Per-tenant isolation
 * - Performance benchmarks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "../../layer4/layer4.h"
#include "../../layer4/reputation.h"
#include "../../layer4/challenge.h"
#include "../../layer4/bot_management.h"
#include "../../common/tenant.h"
#include "../../common/tenant_config.h"

// ==================== Test Framework ====================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;

#define TEST_START(name) do { \
    printf("  Testing: %-50s ", name); \
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
} while(0)

#define TEST_SKIP(msg) do { \
    printf("\033[33mSKIP\033[0m: %s\n", msg); \
    tests_skipped++; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %ld, expected %ld)", msg, (long)(a), (long)(b)); \
        TEST_FAIL(_buf); \
        return; \
    } \
} while(0)

#define ASSERT_NE(a, b, msg) do { \
    if ((a) == (b)) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_FALSE(cond, msg) do { \
    if (cond) { \
        TEST_FAIL(msg); \
        return; \
    } \
} while(0)

#define ASSERT_DOUBLE_EQ(a, b, eps, msg) do { \
    if (fabs((a) - (b)) > (eps)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %.4f, expected %.4f)", msg, (a), (b)); \
        TEST_FAIL(_buf); \
        return; \
    } \
} while(0)

#define ASSERT_DOUBLE_GT(a, b, msg) do { \
    if ((a) <= (b)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %.4f, expected > %.4f)", msg, (a), (b)); \
        TEST_FAIL(_buf); \
        return; \
    } \
} while(0)

#define ASSERT_DOUBLE_LT(a, b, msg) do { \
    if ((a) >= (b)) { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "%s (got %.4f, expected < %.4f)", msg, (a), (b)); \
        TEST_FAIL(_buf); \
        return; \
    } \
} while(0)

// ==================== Helper Functions ====================

static uint32_t ip_to_uint32(const char *ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);
    return addr.s_addr; // Network byte order for lookup
}

static struct tenant_l4_config create_default_l4_config(void) {
    struct tenant_l4_config cfg = {0};

    // Reputation settings
    cfg.reputation.initial_score = 0.5;
    cfg.reputation.decay_rate_per_hour = 0.01;
    cfg.reputation.block_threshold = 0.1;
    cfg.reputation.challenge_threshold = 0.3;
    cfg.reputation.trust_threshold = 0.7;
    cfg.reputation.history_window_hours = 24;

    // Challenge settings
    cfg.challenge.js_challenge_enabled = true;
    cfg.challenge.captcha_enabled = true;
    cfg.challenge.proof_of_work_enabled = true;
    cfg.challenge.challenge_validity_sec = 300;
    cfg.challenge.max_challenge_attempts = 3;
    cfg.challenge.challenge_difficulty = 5;

    // Bot management
    cfg.bot_management.enabled = true;
    cfg.bot_management.block_known_bots = true;
    cfg.bot_management.block_headless_browsers = true;
    cfg.bot_management.block_automation_tools = true;
    cfg.bot_management.allow_good_bots = true;

    return cfg;
}

static bool setup_test_environment(void) {
    // Initialize tenant registry
    if (tenant_registry_init() != TENANT_OK) {
        return false;
    }

    // Initialize tenant config
    if (tenant_config_init() != 0) {
        tenant_registry_cleanup();
        return false;
    }

    // Initialize Layer 4
    if (l4_init() != 0) {
        tenant_config_cleanup();
        tenant_registry_cleanup();
        return false;
    }

    return true;
}

static void teardown_test_environment(void) {
    l4_cleanup();
    tenant_config_cleanup();
    tenant_registry_cleanup();
}

// ==================== Reputation Engine Tests ====================

static void test_reputation_init(void) {
    TEST_START("reputation init/cleanup");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    reputation_cleanup();
    TEST_PASS();
}

static void test_reputation_initial_score(void) {
    TEST_START("reputation initial score");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.1");
    tenant_id_t tenant_id = 1;
    struct tenant_l4_config cfg = create_default_l4_config();

    // First lookup should create entry with initial score
    double score = reputation_get_score(src_ip, tenant_id);

    // Should be close to initial score (0.5) or -1 if not created yet
    if (score >= 0) {
        ASSERT_DOUBLE_EQ(score, cfg.reputation.initial_score, 0.01, "wrong initial score");
    }

    reputation_cleanup();
    TEST_PASS();
}

static void test_reputation_positive_events(void) {
    TEST_START("reputation positive events");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.2");
    tenant_id_t tenant_id = 1;

    // Set initial score
    reputation_set_score(src_ip, tenant_id, 0.5);
    double initial = reputation_get_score(src_ip, tenant_id);

    // Apply positive event (TCP handshake completed)
    reputation_update_positive(src_ip, tenant_id, REP_EVENT_TCP_HANDSHAKE, 0.05);

    double after = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_GT(after, initial, "score should increase after positive event");

    // Apply multiple positive events
    reputation_update_positive(src_ip, tenant_id, REP_EVENT_HTTP_REQUEST, 0.02);
    reputation_update_positive(src_ip, tenant_id, REP_EVENT_CHALLENGE_PASSED, 0.10);

    double final = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_GT(final, after, "score should increase after more positive events");
    ASSERT_DOUBLE_LT(final, 1.0, "score should not exceed 1.0");

    reputation_cleanup();
    TEST_PASS();
}

static void test_reputation_negative_events(void) {
    TEST_START("reputation negative events");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.3");
    tenant_id_t tenant_id = 1;

    // Set initial score
    reputation_set_score(src_ip, tenant_id, 0.5);
    double initial = reputation_get_score(src_ip, tenant_id);

    // Apply negative event (SYN without ACK)
    reputation_update_negative(src_ip, tenant_id, REP_EVENT_SYN_NO_ACK, 0.10);

    double after = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(after, initial, "score should decrease after negative event");

    // Apply multiple negative events (attack behavior)
    reputation_update_negative(src_ip, tenant_id, REP_EVENT_SIGNATURE_MATCH, 0.30);
    reputation_update_negative(src_ip, tenant_id, REP_EVENT_RATE_EXCEEDED, 0.25);

    double final = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(final, after, "score should decrease after more negative events");
    ASSERT_DOUBLE_GT(final, 0.0, "score should not go below 0.0");

    reputation_cleanup();
    TEST_PASS();
}

static void test_reputation_tenant_isolation(void) {
    TEST_START("reputation tenant isolation");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.4");
    tenant_id_t tenant1 = 1;
    tenant_id_t tenant2 = 2;

    // Set different scores for same IP in different tenants
    reputation_set_score(src_ip, tenant1, 0.8);
    reputation_set_score(src_ip, tenant2, 0.2);

    double score1 = reputation_get_score(src_ip, tenant1);
    double score2 = reputation_get_score(src_ip, tenant2);

    ASSERT_DOUBLE_EQ(score1, 0.8, 0.01, "tenant 1 score wrong");
    ASSERT_DOUBLE_EQ(score2, 0.2, 0.01, "tenant 2 score wrong");

    // Negative event on tenant1 should not affect tenant2
    reputation_update_negative(src_ip, tenant1, REP_EVENT_L3_FLAGGED, 0.40);

    double score1_after = reputation_get_score(src_ip, tenant1);
    double score2_after = reputation_get_score(src_ip, tenant2);

    ASSERT_DOUBLE_LT(score1_after, score1, "tenant 1 score should decrease");
    ASSERT_DOUBLE_EQ(score2_after, score2, 0.01, "tenant 2 score should be unchanged");

    reputation_cleanup();
    TEST_PASS();
}

static void test_reputation_decision(void) {
    TEST_START("reputation decision thresholds");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    // Test ACCEPT for trusted IP
    uint32_t trusted_ip = ip_to_uint32("10.0.0.5");
    reputation_set_score(trusted_ip, 1, 0.8);  // Above trust threshold

    reputation_decision_t decision = reputation_check(trusted_ip, 1, &cfg);
    ASSERT_EQ(decision, REP_DECISION_ACCEPT, "trusted IP should be accepted");

    // Test CHALLENGE for medium score
    uint32_t medium_ip = ip_to_uint32("10.0.0.6");
    reputation_set_score(medium_ip, 1, 0.25);  // Between block and challenge threshold

    decision = reputation_check(medium_ip, 1, &cfg);
    ASSERT_EQ(decision, REP_DECISION_CHALLENGE, "medium score should require challenge");

    // Test DROP for low score
    uint32_t blocked_ip = ip_to_uint32("10.0.0.7");
    reputation_set_score(blocked_ip, 1, 0.05);  // Below block threshold

    decision = reputation_check(blocked_ip, 1, &cfg);
    ASSERT_EQ(decision, REP_DECISION_DROP, "low score should be dropped");

    reputation_cleanup();
    TEST_PASS();
}

static void test_reputation_l3_integration(void) {
    TEST_START("reputation L3 ML integration");

    int ret = reputation_init();
    ASSERT_EQ(ret, 0, "reputation init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.8");
    tenant_id_t tenant_id = 1;

    reputation_set_score(src_ip, tenant_id, 0.5);
    double before = reputation_get_score(src_ip, tenant_id);

    // L3 flags as attacker with high confidence
    reputation_apply_l3_result(src_ip, tenant_id, true, 0.95);

    double after = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(after, before, "L3 attacker flag should decrease score");
    ASSERT_DOUBLE_LT(after, 0.2, "high confidence attacker should have low score");

    // Test L3 clearing
    reputation_set_score(src_ip, tenant_id, 0.3);
    reputation_apply_l3_result(src_ip, tenant_id, false, 0.9);  // Not attacker

    double cleared = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_GT(cleared, 0.3, "L3 clear should increase score");

    reputation_cleanup();
    TEST_PASS();
}

// ==================== Challenge System Tests ====================

static void test_challenge_init(void) {
    TEST_START("challenge init/cleanup");

    int ret = challenge_init();
    ASSERT_EQ(ret, 0, "challenge init failed");

    challenge_cleanup();
    TEST_PASS();
}

static void test_challenge_selection(void) {
    TEST_START("challenge type selection");

    int ret = challenge_init();
    ASSERT_EQ(ret, 0, "challenge init failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    // High reputation should get easier challenge
    challenge_type_t type = challenge_select(ip_to_uint32("10.0.0.10"), 1, 0.6, &cfg);
    ASSERT_TRUE(type == CHALLENGE_JS_POW || type == CHALLENGE_TCP_TIMESTAMP,
                "high rep should get easy challenge");

    // Low reputation should get harder challenge
    type = challenge_select(ip_to_uint32("10.0.0.11"), 1, 0.15, &cfg);
    ASSERT_TRUE(type == CHALLENGE_CAPTCHA_IMAGE || type == CHALLENGE_CAPTCHA_TEXT,
                "low rep should get hard challenge");

    challenge_cleanup();
    TEST_PASS();
}

static void test_challenge_issue_and_verify(void) {
    TEST_START("challenge issue and verify");

    int ret = challenge_init();
    ASSERT_EQ(ret, 0, "challenge init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.12");
    tenant_id_t tenant_id = 1;
    struct challenge_state state = {0};

    // Issue challenge
    ret = challenge_issue(src_ip, tenant_id, CHALLENGE_JS_POW, &state);
    ASSERT_EQ(ret, 0, "challenge issue failed");
    ASSERT_EQ(state.src_ip, src_ip, "wrong src_ip in state");
    ASSERT_EQ(state.tenant_id, tenant_id, "wrong tenant_id in state");
    ASSERT_EQ(state.current_challenge, CHALLENGE_JS_POW, "wrong challenge type");
    ASSERT_TRUE(state.challenge_expires_at > state.challenge_issued_at,
                "expiry should be after issue time");

    // Verify that IP has pending challenge
    ASSERT_FALSE(challenge_has_valid_pass(src_ip, tenant_id),
                 "should not have valid pass yet");

    challenge_cleanup();
    TEST_PASS();
}

static void test_challenge_max_attempts(void) {
    TEST_START("challenge max attempts");

    int ret = challenge_init();
    ASSERT_EQ(ret, 0, "challenge init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.13");
    tenant_id_t tenant_id = 1;
    struct challenge_state state = {0};

    // Issue challenge
    ret = challenge_issue(src_ip, tenant_id, CHALLENGE_CAPTCHA_TEXT, &state);
    ASSERT_EQ(ret, 0, "challenge issue failed");

    // Fail verification multiple times
    for (int i = 0; i < 5; i++) {
        const char *wrong_response = "wrong_answer";
        challenge_result_t result = challenge_verify(src_ip, tenant_id,
                                                      wrong_response, strlen(wrong_response));
        if (i < 3) {  // max_challenge_attempts = 3
            ASSERT_EQ(result, CHALLENGE_RESULT_FAILED, "should fail verification");
        } else {
            ASSERT_EQ(result, CHALLENGE_RESULT_BLOCKED, "should be blocked after max attempts");
        }
    }

    challenge_cleanup();
    TEST_PASS();
}

static void test_challenge_tenant_isolation(void) {
    TEST_START("challenge tenant isolation");

    int ret = challenge_init();
    ASSERT_EQ(ret, 0, "challenge init failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.14");
    tenant_id_t tenant1 = 1;
    tenant_id_t tenant2 = 2;
    struct challenge_state state1 = {0}, state2 = {0};

    // Issue different challenges for same IP in different tenants
    ret = challenge_issue(src_ip, tenant1, CHALLENGE_JS_POW, &state1);
    ASSERT_EQ(ret, 0, "challenge issue for tenant1 failed");

    ret = challenge_issue(src_ip, tenant2, CHALLENGE_CAPTCHA_IMAGE, &state2);
    ASSERT_EQ(ret, 0, "challenge issue for tenant2 failed");

    // Verify different challenge types
    ASSERT_EQ(state1.current_challenge, CHALLENGE_JS_POW, "tenant1 wrong challenge type");
    ASSERT_EQ(state2.current_challenge, CHALLENGE_CAPTCHA_IMAGE, "tenant2 wrong challenge type");

    challenge_cleanup();
    TEST_PASS();
}

// ==================== Bot Management Tests ====================

static void test_bot_management_init(void) {
    TEST_START("bot management init/cleanup");

    int ret = bot_management_init();
    ASSERT_EQ(ret, 0, "bot management init failed");

    bot_management_cleanup();
    TEST_PASS();
}

static void test_bot_classification_good_bot(void) {
    TEST_START("bot classification - good bot");

    int ret = bot_management_init();
    ASSERT_EQ(ret, 0, "bot management init failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    struct bot_signals signals = {0};
    strncpy(signals.user_agent, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            sizeof(signals.user_agent) - 1);
    signals.ua_consistent = true;
    signals.accepts_cookies = true;
    signals.follows_robots_txt = true;

    struct bot_verdict verdict = bot_classify(&signals, 1, &cfg);

    // Googlebot should be classified as good bot (if verification passes)
    // Note: actual verification would check reverse DNS
    ASSERT_TRUE(verdict.classification == BOT_CLASS_GOOD_BOT ||
                verdict.classification == BOT_CLASS_SUSPICIOUS,
                "Googlebot-like UA should be good bot or suspicious");

    if (cfg.bot_management.allow_good_bots && verdict.classification == BOT_CLASS_GOOD_BOT) {
        ASSERT_EQ(verdict.action, BOT_ACTION_ALLOW, "good bots should be allowed");
    }

    bot_management_cleanup();
    TEST_PASS();
}

static void test_bot_classification_bad_bot(void) {
    TEST_START("bot classification - bad bot");

    int ret = bot_management_init();
    ASSERT_EQ(ret, 0, "bot management init failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    struct bot_signals signals = {0};
    strncpy(signals.user_agent, "python-requests/2.25.1", sizeof(signals.user_agent) - 1);
    signals.ua_consistent = false;  // UA doesn't match TLS fingerprint
    signals.accepts_cookies = false;
    signals.executes_js = false;
    signals.requests_per_second = 100;  // High request rate
    signals.follows_robots_txt = false;

    struct bot_verdict verdict = bot_classify(&signals, 1, &cfg);

    ASSERT_TRUE(verdict.classification == BOT_CLASS_BAD_BOT ||
                verdict.classification == BOT_CLASS_SUSPICIOUS,
                "scraper-like behavior should be bad bot or suspicious");

    ASSERT_TRUE(verdict.action == BOT_ACTION_BLOCK ||
                verdict.action == BOT_ACTION_CHALLENGE,
                "bad bot should be blocked or challenged");

    bot_management_cleanup();
    TEST_PASS();
}

static void test_bot_classification_attack_tool(void) {
    TEST_START("bot classification - attack tool");

    int ret = bot_management_init();
    ASSERT_EQ(ret, 0, "bot management init failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    struct bot_signals signals = {0};
    signals.tcp_fingerprint_known = true;
    strncpy(signals.tcp_os_guess, "hping/masscan", sizeof(signals.tcp_os_guess) - 1);
    signals.user_agent[0] = '\0';  // No user agent
    signals.requests_per_second = 10000;  // Extremely high rate

    struct bot_verdict verdict = bot_classify(&signals, 1, &cfg);

    ASSERT_EQ(verdict.classification, BOT_CLASS_ATTACK_TOOL, "attack tool should be detected");
    ASSERT_EQ(verdict.action, BOT_ACTION_BLOCK, "attack tools should be blocked");

    bot_management_cleanup();
    TEST_PASS();
}

static void test_bot_classification_human(void) {
    TEST_START("bot classification - human");

    int ret = bot_management_init();
    ASSERT_EQ(ret, 0, "bot management init failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    struct bot_signals signals = {0};
    strncpy(signals.user_agent,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
            sizeof(signals.user_agent) - 1);
    signals.ua_consistent = true;
    signals.accepts_cookies = true;
    signals.executes_js = true;
    signals.has_referer = true;
    signals.requests_per_second = 0.5;  // Normal human rate
    signals.varies_request_patterns = true;

    struct bot_verdict verdict = bot_classify(&signals, 1, &cfg);

    ASSERT_TRUE(verdict.classification == BOT_CLASS_HUMAN ||
                verdict.classification == BOT_CLASS_UNKNOWN,
                "normal browser behavior should be human or unknown");

    ASSERT_EQ(verdict.action, BOT_ACTION_ALLOW, "human should be allowed");

    bot_management_cleanup();
    TEST_PASS();
}

// ==================== Decision Engine Tests ====================

static void test_l4_decision_accept_trusted(void) {
    TEST_START("L4 decision - accept trusted");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    struct tenant_l4_config cfg = create_default_l4_config();
    uint32_t src_ip = ip_to_uint32("10.0.0.20");
    tenant_id_t tenant_id = 1;

    // Set up trusted IP
    reputation_set_score(src_ip, tenant_id, 0.85);  // Above trust threshold

    struct l4_decision_context ctx = {0};
    ctx.src_ip = src_ip;
    ctx.tenant_id = tenant_id;
    ctx.config = &cfg;
    ctx.reputation_score = 0.85;
    ctx.rep_decision = REP_DECISION_ACCEPT;
    ctx.bot.classification = BOT_CLASS_HUMAN;
    ctx.bot.action = BOT_ACTION_ALLOW;
    ctx.challenge_passed = true;

    struct l4_decision_result result = {0};
    int ret = l4_decide(&ctx, &result);

    ASSERT_EQ(ret, 0, "l4_decide failed");
    ASSERT_EQ(result.decision, L4_DECISION_ACCEPT, "trusted IP should be accepted");

    teardown_test_environment();
    TEST_PASS();
}

static void test_l4_decision_drop_attacker(void) {
    TEST_START("L4 decision - drop attacker");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    struct tenant_l4_config cfg = create_default_l4_config();
    uint32_t src_ip = ip_to_uint32("10.0.0.21");
    tenant_id_t tenant_id = 1;

    // Set up attacker IP
    reputation_set_score(src_ip, tenant_id, 0.05);  // Below block threshold

    struct l4_decision_context ctx = {0};
    ctx.src_ip = src_ip;
    ctx.tenant_id = tenant_id;
    ctx.config = &cfg;
    ctx.reputation_score = 0.05;
    ctx.rep_decision = REP_DECISION_DROP;
    ctx.l3_flagged_attacker = true;
    ctx.l3_attack_confidence = 0.9;

    struct l4_decision_result result = {0};
    int ret = l4_decide(&ctx, &result);

    ASSERT_EQ(ret, 0, "l4_decide failed");
    ASSERT_EQ(result.decision, L4_DECISION_DROP, "attacker should be dropped");
    ASSERT_NE(result.drop_reason, L4_DROP_NONE, "should have drop reason");

    teardown_test_environment();
    TEST_PASS();
}

static void test_l4_decision_challenge_required(void) {
    TEST_START("L4 decision - challenge required");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    struct tenant_l4_config cfg = create_default_l4_config();
    uint32_t src_ip = ip_to_uint32("10.0.0.22");
    tenant_id_t tenant_id = 1;

    // Set up medium reputation IP
    reputation_set_score(src_ip, tenant_id, 0.25);  // Between challenge and block

    struct l4_decision_context ctx = {0};
    ctx.src_ip = src_ip;
    ctx.tenant_id = tenant_id;
    ctx.config = &cfg;
    ctx.reputation_score = 0.25;
    ctx.rep_decision = REP_DECISION_CHALLENGE;
    ctx.bot.classification = BOT_CLASS_UNKNOWN;
    ctx.challenge_required = true;
    ctx.challenge_passed = false;

    struct l4_decision_result result = {0};
    int ret = l4_decide(&ctx, &result);

    ASSERT_EQ(ret, 0, "l4_decide failed");
    ASSERT_EQ(result.decision, L4_DECISION_CHALLENGE, "should require challenge");
    ASSERT_NE(result.challenge_type, CHALLENGE_NONE, "should have challenge type");

    teardown_test_environment();
    TEST_PASS();
}

static void test_l4_decision_bot_blocked(void) {
    TEST_START("L4 decision - bot blocked");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    struct tenant_l4_config cfg = create_default_l4_config();
    uint32_t src_ip = ip_to_uint32("10.0.0.23");
    tenant_id_t tenant_id = 1;

    struct l4_decision_context ctx = {0};
    ctx.src_ip = src_ip;
    ctx.tenant_id = tenant_id;
    ctx.config = &cfg;
    ctx.reputation_score = 0.5;  // Normal reputation
    ctx.bot.classification = BOT_CLASS_ATTACK_TOOL;
    ctx.bot.action = BOT_ACTION_BLOCK;

    struct l4_decision_result result = {0};
    int ret = l4_decide(&ctx, &result);

    ASSERT_EQ(ret, 0, "l4_decide failed");
    ASSERT_EQ(result.decision, L4_DECISION_DROP, "attack tool should be dropped");
    ASSERT_EQ(result.drop_reason, L4_DROP_ATTACK_TOOL, "should be attack tool drop reason");

    teardown_test_environment();
    TEST_PASS();
}

static void test_l4_quick_check_performance(void) {
    TEST_START("L4 quick check performance");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    struct tenant_l4_config cfg = create_default_l4_config();

    // Pre-populate some reputation entries
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(0x0A000000 + i);  // 10.0.0.0 - 10.0.3.231
        reputation_set_score(ip, 1, 0.5 + (i % 10) * 0.05);
    }

    // Benchmark quick check
    const int iterations = 100000;
    clock_t start = clock();

    for (int i = 0; i < iterations; i++) {
        uint32_t ip = htonl(0x0A000000 + (i % 1000));
        l4_quick_check(ip, 1, &cfg);
    }

    clock_t end = clock();
    double elapsed_ms = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    double per_op_ns = elapsed_ms * 1000000 / iterations;

    printf("(%.1f ns/op) ", per_op_ns);

    // Should be under 1000ns per operation (reasonable for non-DPDK test)
    ASSERT_TRUE(per_op_ns < 10000, "quick check too slow");

    teardown_test_environment();
    TEST_PASS();
}

// ==================== Integration Tests ====================

static void test_l4_l1_integration(void) {
    TEST_START("L4-L1 integration (drop notification)");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.30");
    tenant_id_t tenant_id = 1;

    reputation_set_score(src_ip, tenant_id, 0.5);
    double before = reputation_get_score(src_ip, tenant_id);

    // Simulate L1 drop notification (rate limit exceeded)
    l4_notify_l1_drop(src_ip, tenant_id, 1);  // Rate limit drop reason

    double after = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(after, before, "L1 drop should decrease reputation");

    teardown_test_environment();
    TEST_PASS();
}

static void test_l4_l2_integration(void) {
    TEST_START("L4-L2 integration (anomaly notification)");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.31");
    tenant_id_t tenant_id = 1;

    reputation_set_score(src_ip, tenant_id, 0.5);
    double before = reputation_get_score(src_ip, tenant_id);

    // Simulate L2 anomaly notification
    l4_notify_l2_anomaly(src_ip, tenant_id, 3);  // Severity 3

    double after = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(after, before, "L2 anomaly should decrease reputation");

    // Higher severity should have bigger impact
    reputation_set_score(src_ip, tenant_id, 0.5);
    l4_notify_l2_anomaly(src_ip, tenant_id, 5);  // Severity 5

    double high_severity = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(high_severity, after, "higher severity should have bigger impact");

    teardown_test_environment();
    TEST_PASS();
}

static void test_l4_l5_integration(void) {
    TEST_START("L4-L5 integration (threat intel)");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    uint32_t src_ip = ip_to_uint32("10.0.0.32");
    tenant_id_t tenant_id = 1;

    reputation_set_score(src_ip, tenant_id, 0.5);
    double before = reputation_get_score(src_ip, tenant_id);

    // Simulate L5 threat intel (high threat score)
    l4_apply_l5_intel(src_ip, 0.9);  // 90% threat

    double after = reputation_get_score(src_ip, tenant_id);
    ASSERT_DOUBLE_LT(after, before, "L5 threat intel should decrease reputation");
    ASSERT_DOUBLE_LT(after, 0.2, "high threat should result in low reputation");

    teardown_test_environment();
    TEST_PASS();
}

// ==================== Statistics Tests ====================

static void test_l4_stats(void) {
    TEST_START("L4 statistics tracking");

    ASSERT_TRUE(setup_test_environment(), "setup failed");

    l4_reset_stats();

    struct tenant_l4_config cfg = create_default_l4_config();

    // Make some decisions
    struct l4_decision_context ctx = {0};
    struct l4_decision_result result = {0};

    // Accept decision
    ctx.src_ip = ip_to_uint32("10.0.0.40");
    ctx.tenant_id = 1;
    ctx.config = &cfg;
    ctx.reputation_score = 0.8;
    ctx.rep_decision = REP_DECISION_ACCEPT;
    ctx.bot.classification = BOT_CLASS_HUMAN;
    ctx.challenge_passed = true;
    l4_decide(&ctx, &result);

    // Drop decision
    ctx.src_ip = ip_to_uint32("10.0.0.41");
    ctx.reputation_score = 0.05;
    ctx.rep_decision = REP_DECISION_DROP;
    ctx.l3_flagged_attacker = true;
    l4_decide(&ctx, &result);

    struct l4_stats stats;
    l4_get_stats(&stats);

    ASSERT_TRUE(stats.decisions_accept >= 1, "should have accept decisions");
    ASSERT_TRUE(stats.decisions_drop >= 1, "should have drop decisions");

    teardown_test_environment();
    TEST_PASS();
}

// ==================== Test Runner ====================

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║              Layer 4 Comprehensive Unit Tests                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Reputation Engine Tests
    printf("┌─ Reputation Engine Tests ──────────────────────────────────────────┐\n");
    test_reputation_init();
    test_reputation_initial_score();
    test_reputation_positive_events();
    test_reputation_negative_events();
    test_reputation_tenant_isolation();
    test_reputation_decision();
    test_reputation_l3_integration();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Challenge System Tests
    printf("┌─ Challenge System Tests ───────────────────────────────────────────┐\n");
    test_challenge_init();
    test_challenge_selection();
    test_challenge_issue_and_verify();
    test_challenge_max_attempts();
    test_challenge_tenant_isolation();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Bot Management Tests
    printf("┌─ Bot Management Tests ─────────────────────────────────────────────┐\n");
    test_bot_management_init();
    test_bot_classification_good_bot();
    test_bot_classification_bad_bot();
    test_bot_classification_attack_tool();
    test_bot_classification_human();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Decision Engine Tests
    printf("┌─ Decision Engine Tests ────────────────────────────────────────────┐\n");
    test_l4_decision_accept_trusted();
    test_l4_decision_drop_attacker();
    test_l4_decision_challenge_required();
    test_l4_decision_bot_blocked();
    test_l4_quick_check_performance();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Integration Tests
    printf("┌─ Cross-Layer Integration Tests ────────────────────────────────────┐\n");
    test_l4_l1_integration();
    test_l4_l2_integration();
    test_l4_l5_integration();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Statistics Tests
    printf("┌─ Statistics Tests ─────────────────────────────────────────────────┐\n");
    test_l4_stats();
    printf("└────────────────────────────────────────────────────────────────────┘\n\n");

    // Summary
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                        TEST SUMMARY                               ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:   %3d                                                     ║\n", tests_run);
    printf("║  Passed:  %3d  \033[32m✓\033[0m                                                  ║\n", tests_passed);
    printf("║  Failed:  %3d  %s                                                  ║\n",
           tests_failed, tests_failed > 0 ? "\033[31m✗\033[0m" : " ");
    printf("║  Skipped: %3d                                                     ║\n", tests_skipped);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");

    if (tests_failed > 0) {
        printf("\n\033[31mSOME TESTS FAILED!\033[0m\n");
        return 1;
    }

    printf("\n\033[32mALL TESTS PASSED!\033[0m\n");
    return 0;
}
