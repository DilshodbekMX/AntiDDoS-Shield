/**
 * @file tenant.c
 * @brief Enterprise Multi-Tenant Registry Implementation
 *
 * Thread-safe implementation of the tenant registry with:
 * - LPM-based IP-to-tenant lookup using DPDK rte_lpm
 * - Read-write locks for concurrent access
 * - Hash-based lookups for name and external_id
 * - Atomic usage updates for lock-free fast path
 */

#include "tenant.h"
#include "../external/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include <rte_lpm.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_atomic.h>

// Forward declarations for L1 protected subnet integration (weak symbols so tenant unit tests link even without DPDK L1)
int ip_protected_subnet_add(uint32_t ip_prefix, uint8_t depth) __attribute__((weak));
int ip_protected_subnet_remove(uint32_t ip_prefix, uint8_t depth) __attribute__((weak));

// ==================== Internal Structures ====================

// LPM configuration
#define TENANT_LPM_NAME         "tenant_ip_lpm"
#define TENANT_LPM_MAX_RULES    (MAX_TENANTS * MAX_PROTECTED_IPS_PER_TENANT)

// Hash table configuration
#define TENANT_HASH_ENTRIES     (MAX_TENANTS * 2) // Load factor ~0.5

// Global registry instance
static struct tenant_registry g_registry;
static bool g_initialized = false;

// ==================== String Constants ====================

static const char *status_names[] = {
    [TENANT_STATUS_DISABLED]     = "disabled",
    [TENANT_STATUS_PROVISIONING] = "provisioning",
    [TENANT_STATUS_ACTIVE]       = "active",
    [TENANT_STATUS_SUSPENDED]    = "suspended",
    [TENANT_STATUS_ATTACK_MODE]  = "attack_mode",
    [TENANT_STATUS_MAINTENANCE]  = "maintenance",
    [TENANT_STATUS_MIGRATING]    = "migrating",
};

static const char *tier_names[] = {
    [TENANT_TIER_FREE]       = "free",
    [TENANT_TIER_BASIC]      = "basic",
    [TENANT_TIER_STANDARD]   = "standard",
    [TENANT_TIER_PREMIUM]    = "premium",
    [TENANT_TIER_ENTERPRISE] = "enterprise",
    [TENANT_TIER_CUSTOM]     = "custom",
};

static const char *type_names[] = {
    [TENANT_TYPE_DIRECT]   = "direct",
    [TENANT_TYPE_RESELLER] = "reseller",
    [TENANT_TYPE_MANAGED]  = "managed",
    [TENANT_TYPE_TRIAL]    = "trial",
    [TENANT_TYPE_INTERNAL] = "internal",
};

// ==================== JSON Parsing Helpers ====================

static tenant_status_t parse_status_string(const char *str) {
    if (!str) return TENANT_STATUS_DISABLED;
    for (int i = 0; i < TENANT_STATUS_COUNT; i++) {
        if (strcasecmp(str, status_names[i]) == 0) {
            return (tenant_status_t)i;
        }
    }
    return TENANT_STATUS_DISABLED;
}

static tenant_tier_t parse_tier_string(const char *str) {
    if (!str) return TENANT_TIER_FREE;
    for (int i = 0; i < TENANT_TIER_COUNT; i++) {
        if (strcasecmp(str, tier_names[i]) == 0) {
            return (tenant_tier_t)i;
        }
    }
    return TENANT_TIER_FREE;
}

static tenant_type_t parse_type_string(const char *str) {
    if (!str) return TENANT_TYPE_DIRECT;
    for (int i = 0; i < TENANT_TYPE_COUNT; i++) {
        if (strcasecmp(str, type_names[i]) == 0) {
            return (tenant_type_t)i;
        }
    }
    return TENANT_TYPE_DIRECT;
}

// Parse IP address from string (e.g., "192.168.1.0/24")
static int parse_cidr(const char *cidr, uint32_t *ip_out, uint8_t *prefix_out) {
    if (!cidr || !ip_out || !prefix_out) return -1;

    char ip_str[INET_ADDRSTRLEN];
    int prefix = 32;

    // Find the '/' separator
    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t ip_len = (size_t)(slash - cidr);
        if (ip_len >= INET_ADDRSTRLEN) return -1;
        strncpy(ip_str, cidr, ip_len);
        ip_str[ip_len] = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 8 || prefix > 32) return -1;
    } else {
        strncpy(ip_str, cidr, INET_ADDRSTRLEN - 1);
        ip_str[INET_ADDRSTRLEN - 1] = '\0';
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }

    *ip_out = ntohl(addr.s_addr);  // Convert to host byte order
    *prefix_out = (uint8_t)prefix;
    return 0;
}

// Parse a single tenant from a cJSON object
static int parse_tenant_object(const cJSON *json, struct tenant *t) {
    if (!cJSON_IsObject(json) || !t) {
        return TENANT_ERR_INVALID;
    }

    memset(t, 0, sizeof(struct tenant));
    t->id = TENANT_ID_INVALID;

    // Required: name
    cJSON *name = cJSON_GetObjectItem(json, "name");
    if (!cJSON_IsString(name) || !name->valuestring) {
        fprintf(stderr, "Tenant missing required 'name' field\n");
        return TENANT_ERR_INVALID;
    }
    strncpy(t->name, name->valuestring, MAX_TENANT_NAME_LEN - 1);

    // Optional: id (auto-assigned if not provided)
    cJSON *id = cJSON_GetObjectItem(json, "id");
    if (cJSON_IsNumber(id)) {
        t->id = (tenant_id_t)id->valueint;
    }

    // Optional: external_id
    cJSON *ext_id = cJSON_GetObjectItem(json, "external_id");
    if (cJSON_IsString(ext_id) && ext_id->valuestring) {
        strncpy(t->external_id, ext_id->valuestring, MAX_TENANT_EXTERNAL_ID_LEN - 1);
    }

    // Optional: status (default: active)
    cJSON *status = cJSON_GetObjectItem(json, "status");
    if (cJSON_IsString(status) && status->valuestring) {
        t->status = parse_status_string(status->valuestring);
    } else {
        t->status = TENANT_STATUS_ACTIVE;
    }

    // Optional: tier (default: free)
    cJSON *tier = cJSON_GetObjectItem(json, "tier");
    if (cJSON_IsString(tier) && tier->valuestring) {
        t->tier = parse_tier_string(tier->valuestring);
    } else {
        t->tier = TENANT_TIER_FREE;
    }

    // Optional: type (default: direct)
    cJSON *type = cJSON_GetObjectItem(json, "type");
    if (cJSON_IsString(type) && type->valuestring) {
        t->type = parse_type_string(type->valuestring);
    } else {
        t->type = TENANT_TYPE_DIRECT;
    }

    // Optional: parent_id
    cJSON *parent = cJSON_GetObjectItem(json, "parent_id");
    if (cJSON_IsNumber(parent)) {
        t->parent_id = (tenant_id_t)parent->valueint;
    }

    // Optional: protected_networks (array of CIDR strings)
    cJSON *networks = cJSON_GetObjectItem(json, "protected_networks");
    if (cJSON_IsArray(networks)) {
        cJSON *net = NULL;
        cJSON_ArrayForEach(net, networks) {
            if (t->protected_count >= MAX_PROTECTED_IPS_PER_TENANT) {
                fprintf(stderr, "Tenant %s: too many protected networks (max %d)\n",
                        t->name, MAX_PROTECTED_IPS_PER_TENANT);
                break;
            }

            if (cJSON_IsString(net) && net->valuestring) {
                uint32_t ip;
                uint8_t prefix;
                if (parse_cidr(net->valuestring, &ip, &prefix) == 0) {
                    struct tenant_protected_network *pn = &t->protected_networks[t->protected_count];
                    pn->ip = ip;
                    pn->prefix = prefix;
                    pn->priority = 0;
                    pn->active = true;
                    t->protected_count++;
                } else {
                    fprintf(stderr, "Tenant %s: invalid CIDR '%s'\n",
                            t->name, net->valuestring);
                }
            }
        }
    }

    // Optional: quotas (object)
    cJSON *quotas = cJSON_GetObjectItem(json, "quotas");
    if (cJSON_IsObject(quotas)) {
        cJSON *item;

        item = cJSON_GetObjectItem(quotas, "max_clean_bps");
        if (cJSON_IsNumber(item)) t->quotas.max_clean_bps = (uint64_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_attack_bps");
        if (cJSON_IsNumber(item)) t->quotas.max_attack_bps = (uint64_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_clean_pps");
        if (cJSON_IsNumber(item)) t->quotas.max_clean_pps = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_attack_pps");
        if (cJSON_IsNumber(item)) t->quotas.max_attack_pps = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_flows");
        if (cJSON_IsNumber(item)) t->quotas.max_flows = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_connections");
        if (cJSON_IsNumber(item)) t->quotas.max_connections = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_policies");
        if (cJSON_IsNumber(item)) t->quotas.max_policies = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_blacklist");
        if (cJSON_IsNumber(item)) t->quotas.max_blacklist = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_whitelist");
        if (cJSON_IsNumber(item)) t->quotas.max_whitelist = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_custom_signatures");
        if (cJSON_IsNumber(item)) t->quotas.max_custom_signatures = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "api_requests_per_minute");
        if (cJSON_IsNumber(item)) t->quotas.api_requests_per_minute = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "api_requests_per_hour");
        if (cJSON_IsNumber(item)) t->quotas.api_requests_per_hour = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "max_api_tokens");
        if (cJSON_IsNumber(item)) t->quotas.max_api_tokens = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "features_enabled");
        if (cJSON_IsNumber(item)) t->quotas.features_enabled = (uint64_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "burst_pps_multiplier");
        if (cJSON_IsNumber(item)) t->quotas.burst_pps_multiplier = (uint32_t)item->valuedouble;

        item = cJSON_GetObjectItem(quotas, "burst_duration_sec");
        if (cJSON_IsNumber(item)) t->quotas.burst_duration_sec = (uint32_t)item->valuedouble;
    }

    // Optional: alert_email
    cJSON *email = cJSON_GetObjectItem(json, "alert_email");
    if (cJSON_IsString(email) && email->valuestring) {
        strncpy(t->alert_email, email->valuestring, MAX_TENANT_ALERT_EMAIL_LEN - 1);
    }

    // Optional: alert_webhook
    cJSON *webhook = cJSON_GetObjectItem(json, "alert_webhook");
    if (cJSON_IsString(webhook) && webhook->valuestring) {
        strncpy(t->alert_webhook, webhook->valuestring, MAX_TENANT_ALERT_WEBHOOK_LEN - 1);
    }

    // Optional: alert_throttle_sec
    cJSON *throttle = cJSON_GetObjectItem(json, "alert_throttle_sec");
    if (cJSON_IsNumber(throttle)) {
        t->alert_throttle_sec = (uint64_t)throttle->valuedouble;
    }

    return TENANT_OK;
}

// Default quotas per tier
static const struct tenant_quotas tier_default_quotas[] = {
    [TENANT_TIER_FREE] = {
        .max_clean_bps = 100000000ULL,    // 100 Mbps
        .max_attack_bps = 1000000000ULL,  // 1 Gbps
        .max_clean_pps = 100000,          // 100K PPS
        .max_attack_pps = 500000,         // 500K PPS
        .max_flows = 10000,
        .max_connections = 1000,
        .max_policies = 10,
        .max_blacklist = 100,
        .max_whitelist = 100,
        .max_custom_signatures = 0,
        .api_requests_per_minute = 10,
        .api_requests_per_hour = 100,
        .max_api_tokens = 1,
        .features_enabled = TENANT_FEATURES_FREE,
        .burst_pps_multiplier = 1,
        .burst_duration_sec = 0,
    },
    [TENANT_TIER_BASIC] = {
        .max_clean_bps = 1000000000ULL,   // 1 Gbps
        .max_attack_bps = 5000000000ULL,  // 5 Gbps
        .max_clean_pps = 500000,          // 500K PPS
        .max_attack_pps = 2000000,        // 2M PPS
        .max_flows = 50000,
        .max_connections = 10000,
        .max_policies = 50,
        .max_blacklist = 1000,
        .max_whitelist = 1000,
        .max_custom_signatures = 0,
        .api_requests_per_minute = 60,
        .api_requests_per_hour = 1000,
        .max_api_tokens = 5,
        .features_enabled = TENANT_FEATURES_BASIC,
        .burst_pps_multiplier = 2,
        .burst_duration_sec = 10,
    },
    [TENANT_TIER_STANDARD] = {
        .max_clean_bps = 5000000000ULL,    // 5 Gbps
        .max_attack_bps = 20000000000ULL,  // 20 Gbps
        .max_clean_pps = 2000000,          // 2M PPS
        .max_attack_pps = 10000000,        // 10M PPS
        .max_flows = 200000,
        .max_connections = 50000,
        .max_policies = 200,
        .max_blacklist = 5000,
        .max_whitelist = 5000,
        .max_custom_signatures = 10,
        .api_requests_per_minute = 120,
        .api_requests_per_hour = 5000,
        .max_api_tokens = 10,
        .features_enabled = TENANT_FEATURES_STANDARD,
        .burst_pps_multiplier = 2,
        .burst_duration_sec = 30,
    },
    [TENANT_TIER_PREMIUM] = {
        .max_clean_bps = 20000000000ULL,    // 20 Gbps
        .max_attack_bps = 100000000000ULL,  // 100 Gbps
        .max_clean_pps = 10000000,          // 10M PPS
        .max_attack_pps = 50000000,         // 50M PPS
        .max_flows = 500000,
        .max_connections = 200000,
        .max_policies = 500,
        .max_blacklist = 20000,
        .max_whitelist = 20000,
        .max_custom_signatures = 50,
        .api_requests_per_minute = 300,
        .api_requests_per_hour = 10000,
        .max_api_tokens = 25,
        .features_enabled = TENANT_FEATURES_PREMIUM,
        .burst_pps_multiplier = 3,
        .burst_duration_sec = 60,
    },
    [TENANT_TIER_ENTERPRISE] = {
        .max_clean_bps = 100000000000ULL,    // 100 Gbps
        .max_attack_bps = 500000000000ULL,   // 500 Gbps
        .max_clean_pps = 50000000,           // 50M PPS
        .max_attack_pps = 200000000,         // 200M PPS
        .max_flows = 2000000,
        .max_connections = 1000000,
        .max_policies = 2000,
        .max_blacklist = 100000,
        .max_whitelist = 100000,
        .max_custom_signatures = 200,
        .api_requests_per_minute = 1000,
        .api_requests_per_hour = 50000,
        .max_api_tokens = 100,
        .features_enabled = TENANT_FEATURES_ENTERPRISE,
        .burst_pps_multiplier = 5,
        .burst_duration_sec = 120,
    },
    [TENANT_TIER_CUSTOM] = {
        // Custom tier uses tenant-specific quotas
        .features_enabled = TENANT_FEATURES_ENTERPRISE,
    },
};

// ==================== Internal Helpers ====================

static inline uint64_t get_current_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
}

static inline bool is_valid_tenant_id(tenant_id_t id) {
    return id >= TENANT_ID_MIN_USER && id <= TENANT_ID_MAX_USER;
}

static inline bool is_valid_prefix(uint8_t prefix) {
    return prefix >= 8 && prefix <= 32;
}

// Find free tenant slot
static int find_free_slot(tenant_id_t *out_id) {
    for (tenant_id_t i = TENANT_ID_MIN_USER; i <= TENANT_ID_MAX_USER; i++) {
        if (g_registry.tenants[i].id == TENANT_ID_INVALID ||
            (g_registry.tenants[i].internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
            *out_id = i;
            return TENANT_OK;
        }
    }
    return TENANT_ERR_FULL;
}

// Update the default tenant cache for single-tenant optimization
// Must be called while holding the write lock
static void update_default_tenant_cache(void) {
    uint32_t count = g_registry.active_count;

    if (count == 1) {
        // Find the single active tenant
        for (tenant_id_t i = TENANT_ID_MIN_USER; i <= TENANT_ID_MAX_USER; i++) {
            const struct tenant *t = &g_registry.tenants[i];
            if (t->id != TENANT_ID_INVALID &&
                !(t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
                __atomic_store_n(&g_registry.default_tenant_id, i, __ATOMIC_RELEASE);
                return;
            }
        }
    }

    // Not in single-tenant mode - invalidate cache
    __atomic_store_n(&g_registry.default_tenant_id, TENANT_ID_INVALID, __ATOMIC_RELEASE);
}

// Update LPM table for a tenant
static int update_lpm_for_tenant(tenant_id_t id, bool add) {
    struct rte_lpm *lpm = (struct rte_lpm *)g_registry.ip_to_tenant_lpm;
    if (!lpm) return TENANT_ERR_MEMORY;

    const struct tenant *t = &g_registry.tenants[id];

    for (uint32_t i = 0; i < t->protected_count; i++) {
        const struct tenant_protected_network *net = &t->protected_networks[i];
        if (!net->active) continue;

        // Convert to network byte order for LPM
        uint32_t ip_be = htonl(net->ip);

        if (add) {
            int ret = rte_lpm_add(lpm, ip_be, net->prefix, id);
            if (ret < 0 && ret != -EEXIST) {
                fprintf(stderr, "Failed to add LPM rule for tenant %u: %d\n", id, ret);
                return TENANT_ERR_MEMORY;
            }
        } else {
            rte_lpm_delete(lpm, ip_be, net->prefix);
        }
    }

    return TENANT_OK;
}

// ==================== Initialization API ====================

int tenant_registry_init(void) {
    if (g_initialized) {
        return TENANT_OK;
    }

    memset(&g_registry, 0, sizeof(g_registry));

    // Initialize all tenants as invalid
    for (int i = 0; i < MAX_TENANTS; i++) {
        g_registry.tenants[i].id = TENANT_ID_INVALID;
    }

    // Initialize single-tenant optimization cache
    g_registry.default_tenant_id = TENANT_ID_INVALID;

    // Initialize read-write lock
    if (pthread_rwlock_init(&g_registry.lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize tenant registry lock\n");
        return TENANT_ERR_MEMORY;
    }

    // Create LPM table
    struct rte_lpm_config lpm_config = {
        .max_rules = TENANT_LPM_MAX_RULES,
        .number_tbl8s = 256,
        .flags = 0,
    };
    g_registry.ip_to_tenant_lpm = rte_lpm_create(TENANT_LPM_NAME, SOCKET_ID_ANY, &lpm_config);
    if (!g_registry.ip_to_tenant_lpm) {
        fprintf(stderr, "Failed to create tenant LPM table\n");
        pthread_rwlock_destroy(&g_registry.lock);
        return TENANT_ERR_MEMORY;
    }

    // Create name hash table
    struct rte_hash_parameters hash_params = {
        .name = "tenant_name_hash",
        .entries = TENANT_HASH_ENTRIES,
        .key_len = MAX_TENANT_NAME_LEN,
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = SOCKET_ID_ANY,
    };
    g_registry.name_to_tenant_hash = rte_hash_create(&hash_params);
    if (!g_registry.name_to_tenant_hash) {
        fprintf(stderr, "Failed to create tenant name hash table\n");
        rte_lpm_free((struct rte_lpm *)g_registry.ip_to_tenant_lpm);
        pthread_rwlock_destroy(&g_registry.lock);
        return TENANT_ERR_MEMORY;
    }

    // Create external_id hash table
    hash_params.name = "tenant_extid_hash";
    hash_params.key_len = MAX_TENANT_EXTERNAL_ID_LEN;
    g_registry.extid_to_tenant_hash = rte_hash_create(&hash_params);
    if (!g_registry.extid_to_tenant_hash) {
        fprintf(stderr, "Failed to create tenant external_id hash table\n");
        rte_hash_free((struct rte_hash *)g_registry.name_to_tenant_hash);
        rte_lpm_free((struct rte_lpm *)g_registry.ip_to_tenant_lpm);
        pthread_rwlock_destroy(&g_registry.lock);
        return TENANT_ERR_MEMORY;
    }

    g_registry.version = 1;
    g_initialized = true;

    printf("Tenant registry initialized: max_tenants=%d, max_ips_per_tenant=%d\n",
           MAX_TENANTS, MAX_PROTECTED_IPS_PER_TENANT);

    return TENANT_OK;
}

void tenant_registry_cleanup(void) {
    if (!g_initialized) return;

    pthread_rwlock_wrlock(&g_registry.lock);

    if (g_registry.extid_to_tenant_hash) {
        rte_hash_free((struct rte_hash *)g_registry.extid_to_tenant_hash);
        g_registry.extid_to_tenant_hash = NULL;
    }

    if (g_registry.name_to_tenant_hash) {
        rte_hash_free((struct rte_hash *)g_registry.name_to_tenant_hash);
        g_registry.name_to_tenant_hash = NULL;
    }

    if (g_registry.ip_to_tenant_lpm) {
        rte_lpm_free((struct rte_lpm *)g_registry.ip_to_tenant_lpm);
        g_registry.ip_to_tenant_lpm = NULL;
    }

    pthread_rwlock_unlock(&g_registry.lock);
    pthread_rwlock_destroy(&g_registry.lock);

    g_initialized = false;
    printf("Tenant registry cleaned up\n");
}

int tenant_registry_load(const char *config_path) {
    if (!config_path) {
        return TENANT_ERR_INVALID;
    }

    // Open and read the config file
    FILE *fp = fopen(config_path, "rb");
    if (!fp) {
        // File doesn't exist is OK - start with empty registry
        if (errno == ENOENT) {
            printf("Tenant config file not found: %s (starting with empty registry)\n", config_path);
            return TENANT_OK;
        }
        fprintf(stderr, "Failed to open tenant config file: %s (error: %s)\n",
                config_path, strerror(errno));
        return TENANT_ERR_IO;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 10 * 1024 * 1024) {  // Max 10MB
        fprintf(stderr, "Invalid tenant config file size: %ld\n", file_size);
        fclose(fp);
        return TENANT_ERR_CONFIG;
    }

    // Allocate buffer and read file
    char *json_buf = malloc((size_t)file_size + 1);
    if (!json_buf) {
        fprintf(stderr, "Failed to allocate memory for config file\n");
        fclose(fp);
        return TENANT_ERR_MEMORY;
    }

    size_t bytes_read = fread(json_buf, 1, (size_t)file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Failed to read complete config file\n");
        free(json_buf);
        return TENANT_ERR_IO;
    }
    json_buf[file_size] = '\0';

    // Parse JSON
    cJSON *root = cJSON_Parse(json_buf);
    free(json_buf);

    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        fprintf(stderr, "JSON parse error: %s\n", error_ptr ? error_ptr : "unknown");
        return TENANT_ERR_CONFIG;
    }

    // Expect a "tenants" array
    cJSON *tenants_arr = cJSON_GetObjectItem(root, "tenants");
    if (!cJSON_IsArray(tenants_arr)) {
        fprintf(stderr, "Config file missing 'tenants' array\n");
        cJSON_Delete(root);
        return TENANT_ERR_CONFIG;
    }

    // Parse each tenant
    int loaded_count = 0;
    int error_count = 0;
    cJSON *tenant_json = NULL;

    cJSON_ArrayForEach(tenant_json, tenants_arr) {
        struct tenant t;

        if (parse_tenant_object(tenant_json, &t) != TENANT_OK) {
            error_count++;
            continue;
        }

        // Create the tenant in the registry
        tenant_id_t out_id;
        int ret = tenant_create(&t, &out_id);

        if (ret == TENANT_OK) {
            loaded_count++;
        } else if (ret == TENANT_ERR_EXISTS) {
            // Update existing tenant
            ret = tenant_update(t.id, &t);
            if (ret == TENANT_OK) {
                loaded_count++;
            } else {
                fprintf(stderr, "Failed to update tenant %s: %d\n", t.name, ret);
                error_count++;
            }
        } else {
            fprintf(stderr, "Failed to create tenant %s: %d\n", t.name, ret);
            error_count++;
        }
    }

    cJSON_Delete(root);

    printf("Tenant config loaded: %d tenants loaded, %d errors\n", loaded_count, error_count);

    if (error_count > 0 && loaded_count == 0) {
        return TENANT_ERR_CONFIG;
    }

    return TENANT_OK;
}

int tenant_registry_reload(void) {
    if (!g_initialized) return TENANT_ERR_INVALID;

    pthread_rwlock_wrlock(&g_registry.lock);
    g_registry.version++;
    g_registry.stats.config_reloads++;
    pthread_rwlock_unlock(&g_registry.lock);

    return TENANT_OK;
}

uint64_t tenant_registry_get_version(void) {
    return __atomic_load_n(&g_registry.version, __ATOMIC_ACQUIRE);
}

// ==================== Lookup API (Fast Path) ====================

const struct tenant* tenant_lookup(tenant_id_t id) {
    if (!g_initialized || !is_valid_tenant_id(id)) {
        return NULL;
    }

    __atomic_add_fetch(&g_registry.stats.lookups_by_id, 1, __ATOMIC_RELAXED);

    const struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID ||
        (t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        return NULL;
    }

    return t;
}

const struct tenant* tenant_lookup_by_ip(uint32_t dst_ip) {
    if (!g_initialized || !g_registry.ip_to_tenant_lpm) {
        return NULL;
    }

    __atomic_add_fetch(&g_registry.stats.lookups_by_ip, 1, __ATOMIC_RELAXED);

    struct rte_lpm *lpm = (struct rte_lpm *)g_registry.ip_to_tenant_lpm;
    uint32_t next_hop;

    // LPM lookup - dst_ip should be in network byte order
    if (rte_lpm_lookup(lpm, dst_ip, &next_hop) == 0) {
        tenant_id_t id = (tenant_id_t)next_hop;
        return tenant_lookup(id);
    }

    return NULL;
}

const struct tenant* tenant_lookup_by_name(const char *name) {
    if (!g_initialized || !name || !g_registry.name_to_tenant_hash) {
        return NULL;
    }

    __atomic_add_fetch(&g_registry.stats.lookups_by_name, 1, __ATOMIC_RELAXED);

    // Pad name to fixed length for hash lookup
    char key[MAX_TENANT_NAME_LEN] = {0};
    strncpy(key, name, MAX_TENANT_NAME_LEN - 1);

    pthread_rwlock_rdlock(&g_registry.lock);

    struct rte_hash *hash = (struct rte_hash *)g_registry.name_to_tenant_hash;
    int ret = rte_hash_lookup(hash, key);

    pthread_rwlock_unlock(&g_registry.lock);

    if (ret >= 0) {
        return tenant_lookup((tenant_id_t)ret);
    }

    return NULL;
}

const struct tenant* tenant_lookup_by_external_id(const char *external_id) {
    if (!g_initialized || !external_id || !g_registry.extid_to_tenant_hash) {
        return NULL;
    }

    char key[MAX_TENANT_EXTERNAL_ID_LEN] = {0};
    strncpy(key, external_id, MAX_TENANT_EXTERNAL_ID_LEN - 1);

    pthread_rwlock_rdlock(&g_registry.lock);

    struct rte_hash *hash = (struct rte_hash *)g_registry.extid_to_tenant_hash;
    int ret = rte_hash_lookup(hash, key);

    pthread_rwlock_unlock(&g_registry.lock);

    if (ret >= 0) {
        return tenant_lookup((tenant_id_t)ret);
    }

    return NULL;
}

tenant_id_t tenant_ip_to_id(uint32_t dst_ip) {
    if (!g_initialized || !g_registry.ip_to_tenant_lpm) {
        return TENANT_ID_INVALID;
    }

    struct rte_lpm *lpm = (struct rte_lpm *)g_registry.ip_to_tenant_lpm;
    uint32_t next_hop;

    if (rte_lpm_lookup(lpm, dst_ip, &next_hop) == 0) {
        tenant_id_t id = (tenant_id_t)next_hop;
        const struct tenant *t = &g_registry.tenants[id];

        // Quick validity check
        if (t->id != TENANT_ID_INVALID &&
            !(t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
            return id;
        }
    }

    return TENANT_ID_INVALID;
}

bool tenant_has_feature(tenant_id_t id, uint64_t feature) {
    const struct tenant *t = tenant_lookup(id);
    if (!t) return false;
    return (t->quotas.features_enabled & feature) != 0;
}

bool tenant_is_active(tenant_id_t id) {
    const struct tenant *t = tenant_lookup(id);
    if (!t) return false;
    return t->status == TENANT_STATUS_ACTIVE ||
           t->status == TENANT_STATUS_ATTACK_MODE;
}

// ==================== CRUD API (Control Path) ====================

int tenant_create(const struct tenant *t, tenant_id_t *out_id) {
    if (!g_initialized || !t || !out_id) {
        return TENANT_ERR_INVALID;
    }

    // Validate
    char errors[256];
    if (tenant_validate(t, errors, sizeof(errors)) != TENANT_OK) {
        fprintf(stderr, "Tenant validation failed: %s\n", errors);
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    tenant_id_t id;
    int ret;

    // Assign ID if not specified
    if (t->id == TENANT_ID_INVALID || t->id == 0) {
        ret = find_free_slot(&id);
        if (ret != TENANT_OK) {
            pthread_rwlock_unlock(&g_registry.lock);
            return ret;
        }
    } else {
        id = t->id;
        if (!is_valid_tenant_id(id)) {
            pthread_rwlock_unlock(&g_registry.lock);
            return TENANT_ERR_INVALID;
        }
        // Check if slot is free
        if (g_registry.tenants[id].id != TENANT_ID_INVALID &&
            !(g_registry.tenants[id].internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
            pthread_rwlock_unlock(&g_registry.lock);
            return TENANT_ERR_EXISTS;
        }
    }

    // Copy tenant data
    struct tenant *new_t = &g_registry.tenants[id];
    memcpy(new_t, t, sizeof(struct tenant));
    new_t->id = id;
    new_t->created_at = get_current_time_sec();
    new_t->updated_at = new_t->created_at;
    new_t->internal_flags = 0;

    // Apply tier defaults if quotas not specified
    if (new_t->quotas.max_flows == 0 && new_t->tier < TENANT_TIER_COUNT) {
        memcpy(&new_t->quotas, &tier_default_quotas[new_t->tier], sizeof(struct tenant_quotas));
    }

    // Add to hash tables
    if (strlen(new_t->name) > 0) {
        char key[MAX_TENANT_NAME_LEN] = {0};
        strncpy(key, new_t->name, MAX_TENANT_NAME_LEN - 1);
        rte_hash_add_key_data((struct rte_hash *)g_registry.name_to_tenant_hash, key, (void *)(uintptr_t)id);
    }

    if (strlen(new_t->external_id) > 0) {
        char key[MAX_TENANT_EXTERNAL_ID_LEN] = {0};
        strncpy(key, new_t->external_id, MAX_TENANT_EXTERNAL_ID_LEN - 1);
        rte_hash_add_key_data((struct rte_hash *)g_registry.extid_to_tenant_hash, key, (void *)(uintptr_t)id);
    }

    // Update LPM table
    update_lpm_for_tenant(id, true);

    g_registry.active_count++;
    g_registry.version++;
    *out_id = id;

    // Update single-tenant optimization cache
    update_default_tenant_cache();

    pthread_rwlock_unlock(&g_registry.lock);

    printf("Created tenant %u: %s (tier=%s)\n", id, new_t->name, tenant_tier_to_string(new_t->tier));
    return TENANT_OK;
}

int tenant_update(tenant_id_t id, const struct tenant *t) {
    if (!g_initialized || !t || !is_valid_tenant_id(id)) {
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    struct tenant *existing = &g_registry.tenants[id];
    if (existing->id == TENANT_ID_INVALID ||
        (existing->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    // Check if CARPET_BOMB_DETECT feature flag was toggled
    uint64_t old_flags = existing->quotas.features_enabled;
    uint64_t new_flags = t->quotas.features_enabled;
    if ((old_flags & TENANT_FEATURE_CARPET_BOMB_DETECT) != (new_flags & TENANT_FEATURE_CARPET_BOMB_DETECT)) {
        bool now_enabled = (new_flags & TENANT_FEATURE_CARPET_BOMB_DETECT) != 0;
        for (uint32_t i = 0; i < existing->protected_count; i++) {
            if (existing->protected_networks[i].prefix < 32 && existing->protected_networks[i].active) {
                if (now_enabled && ip_protected_subnet_add) {
                    ip_protected_subnet_add(existing->protected_networks[i].ip, existing->protected_networks[i].prefix);
                } else if (!now_enabled && ip_protected_subnet_remove) {
                    ip_protected_subnet_remove(existing->protected_networks[i].ip, existing->protected_networks[i].prefix);
                }
            }
        }
    }

    // Update fields (preserve id, created_at, usage, attack_state)
    strncpy(existing->name, t->name, MAX_TENANT_NAME_LEN - 1);
    strncpy(existing->external_id, t->external_id, MAX_TENANT_EXTERNAL_ID_LEN - 1);
    existing->status = t->status;
    existing->tier = t->tier;
    existing->type = t->type;
    existing->parent_id = t->parent_id;
    memcpy(&existing->quotas, &t->quotas, sizeof(struct tenant_quotas));
    strncpy(existing->alert_email, t->alert_email, MAX_TENANT_ALERT_EMAIL_LEN - 1);
    strncpy(existing->alert_webhook, t->alert_webhook, MAX_TENANT_ALERT_WEBHOOK_LEN - 1);
    existing->alert_throttle_sec = t->alert_throttle_sec;
    existing->updated_at = get_current_time_sec();

    g_registry.version++;

    pthread_rwlock_unlock(&g_registry.lock);

    return TENANT_OK;
}

int tenant_delete(tenant_id_t id) {
    if (!g_initialized || !is_valid_tenant_id(id)) {
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID ||
        (t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    // Remove from LPM
    update_lpm_for_tenant(id, false);

    // Remove from hash tables
    if (strlen(t->name) > 0) {
        char key[MAX_TENANT_NAME_LEN] = {0};
        strncpy(key, t->name, MAX_TENANT_NAME_LEN - 1);
        rte_hash_del_key((struct rte_hash *)g_registry.name_to_tenant_hash, key);
    }

    if (strlen(t->external_id) > 0) {
        char key[MAX_TENANT_EXTERNAL_ID_LEN] = {0};
        strncpy(key, t->external_id, MAX_TENANT_EXTERNAL_ID_LEN - 1);
        rte_hash_del_key((struct rte_hash *)g_registry.extid_to_tenant_hash, key);
    }

    // Mark as deleted (actual cleanup on maintenance)
    t->internal_flags |= TENANT_INTERNAL_FLAG_DELETED;
    t->status = TENANT_STATUS_DISABLED;

    g_registry.active_count--;
    g_registry.version++;

    // Update single-tenant optimization cache
    update_default_tenant_cache();

    pthread_rwlock_unlock(&g_registry.lock);

    printf("Deleted tenant %u: %s\n", id, t->name);
    return TENANT_OK;
}

int tenant_set_status(tenant_id_t id, tenant_status_t status) {
    if (!g_initialized || !is_valid_tenant_id(id) || status >= TENANT_STATUS_COUNT) {
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID ||
        (t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    t->status = status;
    t->updated_at = get_current_time_sec();
    g_registry.version++;

    pthread_rwlock_unlock(&g_registry.lock);

    return TENANT_OK;
}

// ==================== Protected Network Management ====================

int tenant_add_network(tenant_id_t id, uint32_t ip, uint8_t prefix) {
    if (!g_initialized || !is_valid_tenant_id(id) || !is_valid_prefix(prefix)) {
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID ||
        (t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    if (t->protected_count >= MAX_PROTECTED_IPS_PER_TENANT) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_QUOTA;
    }

    // Check for duplicate
    for (uint32_t i = 0; i < t->protected_count; i++) {
        if (t->protected_networks[i].ip == ip &&
            t->protected_networks[i].prefix == prefix) {
            pthread_rwlock_unlock(&g_registry.lock);
            return TENANT_ERR_EXISTS;
        }
    }

    // Add network
    struct tenant_protected_network *net = &t->protected_networks[t->protected_count];
    net->ip = ip;
    net->prefix = prefix;
    net->priority = 0;
    net->active = true;
    t->protected_count++;

    // Update LPM
    struct rte_lpm *lpm = (struct rte_lpm *)g_registry.ip_to_tenant_lpm;
    uint32_t ip_be = htonl(ip);
    int ret = rte_lpm_add(lpm, ip_be, prefix, id);
    if (ret < 0 && ret != -EEXIST) {
        // Rollback
        t->protected_count--;
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_MEMORY;
    }

    // If prefix is a subnet (< 32) and tenant has CARPET_BOMB_DETECT enabled,
    // register into Layer 1 protected subnet tracking for aggregated carpet bomb detection
    if (prefix < 32 && (t->quotas.features_enabled & TENANT_FEATURE_CARPET_BOMB_DETECT)) {
        if (ip_protected_subnet_add) {
            ip_protected_subnet_add(ip, prefix);
        }
    }

    t->updated_at = get_current_time_sec();
    g_registry.version++;
    g_registry.stats.total_protected_ips++;

    pthread_rwlock_unlock(&g_registry.lock);

    char ip_str[INET_ADDRSTRLEN];
    uint32_t ip_net = htonl(ip);
    inet_ntop(AF_INET, &ip_net, ip_str, sizeof(ip_str));
    printf("Added network %s/%u to tenant %u\n", ip_str, prefix, id);

    return TENANT_OK;
}

int tenant_remove_network(tenant_id_t id, uint32_t ip, uint8_t prefix) {
    if (!g_initialized || !is_valid_tenant_id(id)) {
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID ||
        (t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    // Find network
    int found_idx = -1;
    for (uint32_t i = 0; i < t->protected_count; i++) {
        if (t->protected_networks[i].ip == ip &&
            t->protected_networks[i].prefix == prefix) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    // Remove from LPM
    struct rte_lpm *lpm = (struct rte_lpm *)g_registry.ip_to_tenant_lpm;
    uint32_t ip_be = htonl(ip);
    rte_lpm_delete(lpm, ip_be, prefix);

    // Remove from protected subnet tracking if prefix was a subnet
    if (prefix < 32 && (t->quotas.features_enabled & TENANT_FEATURE_CARPET_BOMB_DETECT)) {
        if (ip_protected_subnet_remove) {
            ip_protected_subnet_remove(ip, prefix);
        }
    }

    // Remove from array (shift remaining)
    for (uint32_t i = (uint32_t)found_idx; i < t->protected_count - 1; i++) {
        t->protected_networks[i] = t->protected_networks[i + 1];
    }
    t->protected_count--;

    t->updated_at = get_current_time_sec();
    g_registry.version++;
    g_registry.stats.total_protected_ips--;

    pthread_rwlock_unlock(&g_registry.lock);

    return TENANT_OK;
}

int tenant_set_network_active(tenant_id_t id, uint32_t ip, uint8_t prefix, bool active) {
    if (!g_initialized || !is_valid_tenant_id(id)) {
        return TENANT_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&g_registry.lock);

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID ||
        (t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
        pthread_rwlock_unlock(&g_registry.lock);
        return TENANT_ERR_NOT_FOUND;
    }

    // Find network
    for (uint32_t i = 0; i < t->protected_count; i++) {
        if (t->protected_networks[i].ip == ip &&
            t->protected_networks[i].prefix == prefix) {

            if (t->protected_networks[i].active == active) {
                pthread_rwlock_unlock(&g_registry.lock);
                return TENANT_OK; // No change needed
            }

            t->protected_networks[i].active = active;

            // Update LPM
            struct rte_lpm *lpm = (struct rte_lpm *)g_registry.ip_to_tenant_lpm;
            uint32_t ip_be = htonl(ip);

            if (active) {
                rte_lpm_add(lpm, ip_be, prefix, id);
            } else {
                rte_lpm_delete(lpm, ip_be, prefix);
            }

            t->updated_at = get_current_time_sec();
            g_registry.version++;

            pthread_rwlock_unlock(&g_registry.lock);
            return TENANT_OK;
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);
    return TENANT_ERR_NOT_FOUND;
}

// ==================== Usage & Attack State ====================

void tenant_update_usage(tenant_id_t id, uint64_t bytes, uint32_t packets) {
    if (!g_initialized || !is_valid_tenant_id(id)) return;

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID) return;

    // Atomic updates for lock-free fast path
    __atomic_add_fetch(&t->usage.total_bytes_24h, bytes, __ATOMIC_RELAXED);
    __atomic_add_fetch(&t->usage.total_packets_24h, packets, __ATOMIC_RELAXED);
    __atomic_store_n(&t->last_active_at, get_current_time_sec(), __ATOMIC_RELAXED);
}

bool tenant_check_quota(tenant_id_t id, uint64_t bytes, uint32_t packets) {
    const struct tenant *t = tenant_lookup(id);
    if (!t) return false;

    // Check PPS limit
    if (t->quotas.max_clean_pps > 0 &&
        t->usage.current_pps + packets > t->quotas.max_clean_pps) {
        return false;
    }

    // Check BPS limit
    if (t->quotas.max_clean_bps > 0 &&
        t->usage.current_bps + (bytes * 8) > t->quotas.max_clean_bps) {
        return false;
    }

    return true;
}

void tenant_set_attack_state(tenant_id_t id, bool under_attack,
                             uint8_t severity, uint8_t attack_type) {
    if (!g_initialized || !is_valid_tenant_id(id)) return;

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID) return;

    bool was_under_attack = t->attack_state.under_attack;
    uint64_t now = get_current_time_sec();

    t->attack_state.under_attack = under_attack;
    t->attack_state.attack_severity = severity;
    t->attack_state.attack_type = attack_type;

    if (under_attack && !was_under_attack) {
        // Attack started
        t->attack_state.attack_start_ns = now * 1000000000ULL;
        t->attack_state.attack_peak_pps = 0;
        t->attack_state.attack_peak_bps = 0;
        t->attack_state.attacks_24h++;
        t->attack_state.attacks_total++;
        t->last_attack_at = now;

        // Elevate status
        if (t->status == TENANT_STATUS_ACTIVE) {
            t->status = TENANT_STATUS_ATTACK_MODE;
        }
    } else if (!under_attack && was_under_attack) {
        // Attack ended
        if (t->status == TENANT_STATUS_ATTACK_MODE) {
            t->status = TENANT_STATUS_ACTIVE;
        }
    }
}

void tenant_update_mitigation_stats(tenant_id_t id, uint64_t pps, uint64_t bps) {
    if (!g_initialized || !is_valid_tenant_id(id)) return;

    struct tenant *t = &g_registry.tenants[id];
    if (t->id == TENANT_ID_INVALID) return;

    t->attack_state.mitigated_pps = pps;
    t->attack_state.mitigated_bps = bps;

    // Update peaks
    if (pps > t->attack_state.attack_peak_pps) {
        t->attack_state.attack_peak_pps = pps;
    }
    if (bps > t->attack_state.attack_peak_bps) {
        t->attack_state.attack_peak_bps = bps;
    }
}

// ==================== Iteration & Bulk Operations ====================

void tenant_foreach(tenant_iterator_fn fn, void *ctx) {
    if (!g_initialized || !fn) return;

    pthread_rwlock_rdlock(&g_registry.lock);

    for (int i = TENANT_ID_MIN_USER; i <= TENANT_ID_MAX_USER; i++) {
        const struct tenant *t = &g_registry.tenants[i];
        if (t->id != TENANT_ID_INVALID &&
            !(t->internal_flags & TENANT_INTERNAL_FLAG_DELETED)) {
            fn(t, ctx);
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);
}

uint32_t tenant_get_active_count(void) {
    return __atomic_load_n(&g_registry.active_count, __ATOMIC_RELAXED);
}

void tenant_get_stats(struct tenant_registry_stats *stats) {
    if (!g_initialized || !stats) return;
    memcpy(stats, &g_registry.stats, sizeof(struct tenant_registry_stats));
    stats->active_count = g_registry.active_count;
}

void tenant_reset_stats(void) {
    if (!g_initialized) return;

    pthread_rwlock_wrlock(&g_registry.lock);

    g_registry.stats.lookups_by_id = 0;
    g_registry.stats.lookups_by_ip = 0;
    g_registry.stats.lookups_by_name = 0;
    g_registry.stats.cache_hits = 0;
    g_registry.stats.cache_misses = 0;
    g_registry.stats.lock_contentions = 0;

    pthread_rwlock_unlock(&g_registry.lock);
}

// ==================== Single-Tenant Optimization API ====================

bool tenant_is_single_mode(void) {
    if (!g_initialized) return false;
    return __atomic_load_n(&g_registry.active_count, __ATOMIC_ACQUIRE) == 1;
}

tenant_id_t tenant_get_default_id(void) {
    if (!g_initialized) return TENANT_ID_INVALID;

    // Fast path: check if we're in single-tenant mode
    if (__atomic_load_n(&g_registry.active_count, __ATOMIC_ACQUIRE) != 1) {
        return TENANT_ID_INVALID;
    }

    return __atomic_load_n(&g_registry.default_tenant_id, __ATOMIC_ACQUIRE);
}

const struct tenant* tenant_get_default(void) {
    tenant_id_t id = tenant_get_default_id();
    if (id == TENANT_ID_INVALID) {
        return NULL;
    }
    return tenant_lookup(id);
}

// ==================== Serialization ====================

int tenant_to_json(const struct tenant *t, char *buf, size_t buf_size) {
    if (!t || !buf || buf_size < 256) {
        return TENANT_ERR_INVALID;
    }

    // Basic JSON serialization (simplified)
    int len = snprintf(buf, buf_size,
        "{"
        "\"id\":%u,"
        "\"name\":\"%s\","
        "\"external_id\":\"%s\","
        "\"status\":\"%s\","
        "\"tier\":\"%s\","
        "\"type\":\"%s\","
        "\"protected_count\":%u,"
        "\"features_enabled\":%lu"
        "}",
        t->id,
        t->name,
        t->external_id,
        tenant_status_to_string(t->status),
        tenant_tier_to_string(t->tier),
        tenant_type_to_string(t->type),
        t->protected_count,
        (unsigned long)t->quotas.features_enabled
    );

    return len;
}

int tenant_from_json(const char *json, struct tenant *t) {
    if (!json || !t) {
        return TENANT_ERR_INVALID;
    }

    cJSON *root = cJSON_Parse(json);
    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        fprintf(stderr, "JSON parse error in tenant_from_json: %s\n",
                error_ptr ? error_ptr : "unknown");
        return TENANT_ERR_CONFIG;
    }

    int ret = parse_tenant_object(root, t);
    cJSON_Delete(root);

    return ret;
}

// ==================== Utility Functions ====================

const char* tenant_status_to_string(tenant_status_t status) {
    if (status >= TENANT_STATUS_COUNT) return "unknown";
    return status_names[status];
}

const char* tenant_tier_to_string(tenant_tier_t tier) {
    if (tier >= TENANT_TIER_COUNT) return "unknown";
    return tier_names[tier];
}

const char* tenant_type_to_string(tenant_type_t type) {
    if (type >= TENANT_TYPE_COUNT) return "unknown";
    return type_names[type];
}

void tenant_get_tier_default_quotas(tenant_tier_t tier, struct tenant_quotas *quotas) {
    if (!quotas) return;

    if (tier >= TENANT_TIER_COUNT) {
        tier = TENANT_TIER_FREE;
    }

    memcpy(quotas, &tier_default_quotas[tier], sizeof(struct tenant_quotas));
}

int tenant_validate(const struct tenant *t, char *errors, size_t errors_size) {
    if (!t) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "tenant is NULL");
        }
        return TENANT_ERR_INVALID;
    }

    // Validate name
    if (strlen(t->name) == 0) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "name is required");
        }
        return TENANT_ERR_INVALID;
    }

    // Validate status
    if (t->status >= TENANT_STATUS_COUNT) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "invalid status: %d", t->status);
        }
        return TENANT_ERR_INVALID;
    }

    // Validate tier
    if (t->tier >= TENANT_TIER_COUNT) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "invalid tier: %d", t->tier);
        }
        return TENANT_ERR_INVALID;
    }

    // Validate type
    if (t->type >= TENANT_TYPE_COUNT) {
        if (errors && errors_size > 0) {
            snprintf(errors, errors_size, "invalid type: %d", t->type);
        }
        return TENANT_ERR_INVALID;
    }

    // Validate protected networks
    for (uint32_t i = 0; i < t->protected_count; i++) {
        if (!is_valid_prefix(t->protected_networks[i].prefix)) {
            if (errors && errors_size > 0) {
                snprintf(errors, errors_size, "invalid prefix %u for network %u",
                         t->protected_networks[i].prefix, i);
            }
            return TENANT_ERR_INVALID;
        }
    }

    return TENANT_OK;
}

void tenant_print(const struct tenant *t) {
    if (!t) return;

    printf("Tenant %u:\n", t->id);
    printf("  Name: %s\n", t->name);
    printf("  External ID: %s\n", t->external_id);
    printf("  Status: %s\n", tenant_status_to_string(t->status));
    printf("  Tier: %s\n", tenant_tier_to_string(t->tier));
    printf("  Type: %s\n", tenant_type_to_string(t->type));
    printf("  Protected networks: %u\n", t->protected_count);

    for (uint32_t i = 0; i < t->protected_count; i++) {
        char ip_str[INET_ADDRSTRLEN];
        uint32_t ip_net = htonl(t->protected_networks[i].ip);
        inet_ntop(AF_INET, &ip_net, ip_str, sizeof(ip_str));
        printf("    %s/%u %s\n", ip_str, t->protected_networks[i].prefix,
               t->protected_networks[i].active ? "(active)" : "(inactive)");
    }

    printf("  Features: 0x%lx\n", (unsigned long)t->quotas.features_enabled);
    printf("  Under attack: %s\n", t->attack_state.under_attack ? "yes" : "no");
}

void tenant_print_registry_summary(void) {
    if (!g_initialized) {
        printf("Tenant registry not initialized\n");
        return;
    }

    printf("=== Tenant Registry Summary ===\n");
    printf("Active tenants: %u / %d\n", g_registry.active_count, MAX_TENANTS);
    printf("Protected IPs: %lu\n", (unsigned long)g_registry.stats.total_protected_ips);
    printf("Config version: %lu\n", (unsigned long)g_registry.version);
    printf("Lookups - ID: %lu, IP: %lu, Name: %lu\n",
           (unsigned long)g_registry.stats.lookups_by_id,
           (unsigned long)g_registry.stats.lookups_by_ip,
           (unsigned long)g_registry.stats.lookups_by_name);
    printf("Config reloads: %lu\n", (unsigned long)g_registry.stats.config_reloads);
}
