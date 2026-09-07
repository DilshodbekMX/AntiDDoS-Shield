/**
 * @file organization.c
 * @brief Single-organization configuration implementation
 */

#include "organization.h"
#include "../external/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#ifdef USE_DPDK
#include <rte_lpm.h>
#include <rte_lpm6.h>
#endif

/* Global organization config */
struct organization_config g_org_config;

#ifdef USE_DPDK
/* LPM table for fast protected IP lookup (DPDK) */
static struct rte_lpm *g_protected_lpm = NULL;
static struct rte_lpm6 *g_protected_lpm6 = NULL;
#endif

/* Lock for config updates (reads are lock-free via LPM) */
static pthread_rwlock_t g_config_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Config file path for reload */
static char g_config_path[256] = {0};

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int parse_cidr(const char *cidr, uint32_t *network, uint8_t *prefix_len)
{
    char buf[64];
    char *slash;
    struct in_addr addr;

    if (!cidr || !network || !prefix_len)
        return -1;

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        *prefix_len = (uint8_t)atoi(slash + 1);
        if (*prefix_len > 32)
            return -1;
    } else {
        *prefix_len = 32;  /* Single IP */
    }

    if (inet_pton(AF_INET, buf, &addr) != 1)
        return -1;

    *network = ntohl(addr.s_addr);
    return 0;
}

#ifdef USE_DPDK
static int rebuild_lpm(void)
{
    struct rte_lpm_config lpm_config = {
        .max_rules = MAX_PROTECTED_NETWORKS,
        .number_tbl8s = 256,
        .flags = 0
    };

    /* Destroy old LPM if exists */
    if (g_protected_lpm) {
        rte_lpm_free(g_protected_lpm);
        g_protected_lpm = NULL;
    }

    /* Create new LPM */
    g_protected_lpm = rte_lpm_create("protected_lpm", SOCKET_ID_ANY, &lpm_config);
    if (!g_protected_lpm) {
        fprintf(stderr, "Failed to create LPM table\n");
        return -1;
    }

    /* Add all active networks */
    for (uint32_t i = 0; i < g_org_config.network_count; i++) {
        struct protected_network *net = &g_org_config.networks[i];
        if (net->active) {
            int ret = rte_lpm_add(g_protected_lpm, net->network, net->prefix_len, 1);
            if (ret < 0) {
                fprintf(stderr, "Failed to add network to LPM: %d\n", ret);
            }
        }
    }

    return 0;
}
#else
/* Non-DPDK fallback: simple linear search (OK for small number of networks) */
static int rebuild_lpm(void)
{
    /* No LPM table needed - use linear search in org_is_protected_ip() */
    return 0;
}
#endif

/* ============================================================================
 * Initialization
 * ============================================================================ */

int org_config_init(const char *config_path)
{
    FILE *fp;
    char *json_buf;
    long file_size;
    int ret;

    if (!config_path)
        return -1;

    /* Save path for reload */
    strncpy(g_config_path, config_path, sizeof(g_config_path) - 1);

    /* Initialize defaults */
    memset(&g_org_config, 0, sizeof(g_org_config));
    strncpy(g_org_config.name, "Default Organization", MAX_ORG_NAME_LEN);

    /* Default limits */
    g_org_config.limits.max_bps = 10000000000ULL;  /* 10 Gbps */
    g_org_config.limits.max_pps = 10000000;         /* 10 Mpps */
    g_org_config.limits.max_flows = 4000000;
    g_org_config.limits.max_connections = 2000000;
    g_org_config.limits.max_blacklist = 100000;
    g_org_config.limits.max_whitelist = 10000;
    g_org_config.limits.max_policies = 10000;
    g_org_config.limits.max_signatures = 256;

    /* Read config file */
    fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "Warning: Cannot open config file %s: %s\n",
                config_path, strerror(errno));
        fprintf(stderr, "Using default configuration\n");
        return rebuild_lpm();
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 1024 * 1024) {  /* Max 1MB */
        fclose(fp);
        return -1;
    }

    json_buf = malloc(file_size + 1);
    if (!json_buf) {
        fclose(fp);
        return -1;
    }

    if (fread(json_buf, 1, file_size, fp) != (size_t)file_size) {
        free(json_buf);
        fclose(fp);
        return -1;
    }
    json_buf[file_size] = '\0';
    fclose(fp);

    ret = org_config_from_json(json_buf);
    free(json_buf);

    if (ret < 0)
        return ret;

    g_org_config.config_loaded_at = get_time_ns();

    return rebuild_lpm();
}

void org_config_cleanup(void)
{
    pthread_rwlock_wrlock(&g_config_lock);

#ifdef USE_DPDK
    if (g_protected_lpm) {
        rte_lpm_free(g_protected_lpm);
        g_protected_lpm = NULL;
    }

    if (g_protected_lpm6) {
        rte_lpm6_free(g_protected_lpm6);
        g_protected_lpm6 = NULL;
    }
#endif

    memset(&g_org_config, 0, sizeof(g_org_config));

    pthread_rwlock_unlock(&g_config_lock);
}

int org_config_reload(void)
{
    if (g_config_path[0] == '\0')
        return -1;

    pthread_rwlock_wrlock(&g_config_lock);

    /* Re-initialize from same path */
    int ret = org_config_init(g_config_path);

    pthread_rwlock_unlock(&g_config_lock);

    return ret;
}

/* ============================================================================
 * Protected Network Management
 * ============================================================================ */

/* Helper: check if IP matches a CIDR network */
static inline bool ip_matches_network(uint32_t ip, uint32_t network, uint8_t prefix_len)
{
    if (prefix_len == 0)
        return true;
    if (prefix_len >= 32)
        return ip == network;
    uint32_t mask = ~((1U << (32 - prefix_len)) - 1);
    return (ip & mask) == (network & mask);
}

bool org_is_protected_ip(uint32_t ip)
{
#ifdef USE_DPDK
    uint32_t next_hop;

    if (!g_protected_lpm)
        return false;

    /* LPM lookup is lock-free and thread-safe */
    if (rte_lpm_lookup(g_protected_lpm, ip, &next_hop) == 0) {
        return true;
    }

    return false;
#else
    /* Non-DPDK fallback: linear search through networks */
    for (uint32_t i = 0; i < g_org_config.network_count; i++) {
        struct protected_network *net = &g_org_config.networks[i];
        if (net->active && ip_matches_network(ip, net->network, net->prefix_len)) {
            return true;
        }
    }
    return false;
#endif
}

bool org_is_protected_ip_v6(const uint8_t *ip)
{
#ifdef USE_DPDK
    uint32_t next_hop;

    if (!g_protected_lpm6 || !ip)
        return false;

    if (rte_lpm6_lookup(g_protected_lpm6, ip, &next_hop) == 0) {
        return true;
    }

    return false;
#else
    /* Non-DPDK fallback: linear search (IPv6 not fully implemented) */
    (void)ip;
    return false;
#endif
}

int org_add_network(uint32_t network, uint8_t prefix_len, const char *description)
{
    int ret = 0;

    if (prefix_len > 32)
        return -1;

    pthread_rwlock_wrlock(&g_config_lock);

    if (g_org_config.network_count >= MAX_PROTECTED_NETWORKS) {
        pthread_rwlock_unlock(&g_config_lock);
        return -1;
    }

    /* Check for duplicate */
    for (uint32_t i = 0; i < g_org_config.network_count; i++) {
        if (g_org_config.networks[i].network == network &&
            g_org_config.networks[i].prefix_len == prefix_len) {
            pthread_rwlock_unlock(&g_config_lock);
            return -1;  /* Already exists */
        }
    }

    /* Add new network */
    struct protected_network *net = &g_org_config.networks[g_org_config.network_count];
    net->network = network;
    net->prefix_len = prefix_len;
    net->active = true;
    if (description) {
        strncpy(net->description, description, MAX_DESCRIPTION_LEN - 1);
    }
    g_org_config.network_count++;

#ifdef USE_DPDK
    /* Update LPM */
    if (g_protected_lpm) {
        ret = rte_lpm_add(g_protected_lpm, network, prefix_len, 1);
    }
#endif

    pthread_rwlock_unlock(&g_config_lock);

    return ret >= 0 ? 0 : -1;
}

int org_remove_network(uint32_t network, uint8_t prefix_len)
{
    bool found = false;

    pthread_rwlock_wrlock(&g_config_lock);

    for (uint32_t i = 0; i < g_org_config.network_count; i++) {
        if (g_org_config.networks[i].network == network &&
            g_org_config.networks[i].prefix_len == prefix_len) {
#ifdef USE_DPDK
            /* Remove from LPM */
            if (g_protected_lpm) {
                rte_lpm_delete(g_protected_lpm, network, prefix_len);
            }
#endif
            /* Shift remaining entries */
            memmove(&g_org_config.networks[i],
                    &g_org_config.networks[i + 1],
                    (g_org_config.network_count - i - 1) * sizeof(struct protected_network));
            g_org_config.network_count--;
            found = true;
            break;
        }
    }

    pthread_rwlock_unlock(&g_config_lock);

    return found ? 0 : -1;
}

uint32_t org_get_network_count(void)
{
    return g_org_config.network_count;
}

/* ============================================================================
 * Usage & Attack State
 * ============================================================================ */

void org_update_usage(uint64_t bps, uint32_t pps, uint32_t flows, uint32_t connections)
{
    /* Atomic updates - no lock needed */
    __atomic_store_n(&g_org_config.usage.current_bps, bps, __ATOMIC_RELAXED);
    __atomic_store_n(&g_org_config.usage.current_pps, pps, __ATOMIC_RELAXED);
    __atomic_store_n(&g_org_config.usage.active_flows, flows, __ATOMIC_RELAXED);
    __atomic_store_n(&g_org_config.usage.active_connections, connections, __ATOMIC_RELAXED);
}

void org_set_attack_state(bool under_attack, uint8_t severity, uint8_t attack_type)
{
    bool was_under_attack = g_org_config.attack_state.under_attack;

    __atomic_store_n(&g_org_config.attack_state.under_attack, under_attack, __ATOMIC_RELAXED);
    __atomic_store_n(&g_org_config.attack_state.attack_severity, severity, __ATOMIC_RELAXED);
    __atomic_store_n(&g_org_config.attack_state.attack_type, attack_type, __ATOMIC_RELAXED);

    if (under_attack && !was_under_attack) {
        /* Attack just started */
        uint64_t now = get_time_ns();
        __atomic_store_n(&g_org_config.attack_state.attack_start_ns, now, __ATOMIC_RELAXED);
        __atomic_fetch_add(&g_org_config.attack_state.attacks_24h, 1, __ATOMIC_RELAXED);
    }

    if (!under_attack && was_under_attack) {
        /* Attack ended */
        __atomic_store_n(&g_org_config.last_attack_at, get_time_ns(), __ATOMIC_RELAXED);
        __atomic_store_n(&g_org_config.attack_state.attack_peak_pps, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&g_org_config.attack_state.attack_peak_bps, 0, __ATOMIC_RELAXED);
    }

    /* Update peak if under attack */
    if (under_attack) {
        uint32_t current_pps = g_org_config.usage.current_pps;
        uint64_t current_bps = g_org_config.usage.current_bps;
        uint64_t peak_pps = g_org_config.attack_state.attack_peak_pps;
        uint64_t peak_bps = g_org_config.attack_state.attack_peak_bps;

        if (current_pps > peak_pps) {
            __atomic_store_n(&g_org_config.attack_state.attack_peak_pps, current_pps, __ATOMIC_RELAXED);
        }
        if (current_bps > peak_bps) {
            __atomic_store_n(&g_org_config.attack_state.attack_peak_bps, current_bps, __ATOMIC_RELAXED);
        }
    }
}

bool org_is_under_attack(void)
{
    return __atomic_load_n(&g_org_config.attack_state.under_attack, __ATOMIC_RELAXED);
}

uint8_t org_get_attack_severity(void)
{
    if (!org_is_under_attack())
        return 0;
    return __atomic_load_n(&g_org_config.attack_state.attack_severity, __ATOMIC_RELAXED);
}

/* ============================================================================
 * JSON Serialization
 * ============================================================================ */

int org_config_from_json(const char *json)
{
    cJSON *root, *org, *networks, *item;

    if (!json)
        return -1;

    root = cJSON_Parse(json);
    if (!root) {
        fprintf(stderr, "JSON parse error: %s\n", cJSON_GetErrorPtr());
        return -1;
    }

    /* Organization info */
    org = cJSON_GetObjectItem(root, "organization");
    if (org) {
        cJSON *name = cJSON_GetObjectItem(org, "name");
        cJSON *email = cJSON_GetObjectItem(org, "contact_email");
        cJSON *webhook = cJSON_GetObjectItem(org, "alert_webhook");

        if (name && cJSON_IsString(name)) {
            strncpy(g_org_config.name, name->valuestring, MAX_ORG_NAME_LEN - 1);
        }
        if (email && cJSON_IsString(email)) {
            strncpy(g_org_config.contact_email, email->valuestring, 127);
        }
        if (webhook && cJSON_IsString(webhook)) {
            strncpy(g_org_config.alert_webhook, webhook->valuestring, 255);
        }
    }

    /* Protected networks */
    networks = cJSON_GetObjectItem(root, "protected_networks");
    if (networks && cJSON_IsArray(networks)) {
        g_org_config.network_count = 0;
        cJSON_ArrayForEach(item, networks) {
            if (g_org_config.network_count >= MAX_PROTECTED_NETWORKS)
                break;

            cJSON *net_str = cJSON_GetObjectItem(item, "network");
            cJSON *desc = cJSON_GetObjectItem(item, "description");

            if (net_str && cJSON_IsString(net_str)) {
                uint32_t network;
                uint8_t prefix_len;

                if (parse_cidr(net_str->valuestring, &network, &prefix_len) == 0) {
                    struct protected_network *net =
                        &g_org_config.networks[g_org_config.network_count];
                    net->network = network;
                    net->prefix_len = prefix_len;
                    net->active = true;
                    if (desc && cJSON_IsString(desc)) {
                        strncpy(net->description, desc->valuestring, MAX_DESCRIPTION_LEN - 1);
                    }
                    g_org_config.network_count++;
                }
            }
        }
    }

    cJSON_Delete(root);
    return 0;
}

int org_config_to_json(char *buf, size_t buf_size)
{
    cJSON *root, *org, *networks, *net_item;
    char *json_str;
    int len;

    root = cJSON_CreateObject();
    if (!root)
        return -1;

    /* Organization */
    org = cJSON_AddObjectToObject(root, "organization");
    cJSON_AddStringToObject(org, "name", g_org_config.name);
    cJSON_AddStringToObject(org, "contact_email", g_org_config.contact_email);
    cJSON_AddStringToObject(org, "alert_webhook", g_org_config.alert_webhook);

    /* Protected networks */
    networks = cJSON_AddArrayToObject(root, "protected_networks");
    for (uint32_t i = 0; i < g_org_config.network_count; i++) {
        struct protected_network *net = &g_org_config.networks[i];
        char cidr[32];
        struct in_addr addr;

        addr.s_addr = htonl(net->network);
        snprintf(cidr, sizeof(cidr), "%s/%u", inet_ntoa(addr), net->prefix_len);

        net_item = cJSON_CreateObject();
        cJSON_AddStringToObject(net_item, "network", cidr);
        cJSON_AddStringToObject(net_item, "description", net->description);
        cJSON_AddBoolToObject(net_item, "active", net->active);
        cJSON_AddItemToArray(networks, net_item);
    }

    /* Usage (read-only info) */
    cJSON *usage = cJSON_AddObjectToObject(root, "current_usage");
    cJSON_AddNumberToObject(usage, "bps", g_org_config.usage.current_bps);
    cJSON_AddNumberToObject(usage, "pps", g_org_config.usage.current_pps);
    cJSON_AddNumberToObject(usage, "active_flows", g_org_config.usage.active_flows);
    cJSON_AddNumberToObject(usage, "active_connections", g_org_config.usage.active_connections);

    /* Attack state */
    cJSON *attack = cJSON_AddObjectToObject(root, "attack_state");
    cJSON_AddBoolToObject(attack, "under_attack", g_org_config.attack_state.under_attack);
    cJSON_AddNumberToObject(attack, "severity", g_org_config.attack_state.attack_severity);
    cJSON_AddNumberToObject(attack, "attacks_24h", g_org_config.attack_state.attacks_24h);

    json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        return -1;
    }

    len = strlen(json_str);
    if ((size_t)len >= buf_size) {
        free(json_str);
        cJSON_Delete(root);
        return -1;
    }

    strcpy(buf, json_str);
    free(json_str);
    cJSON_Delete(root);

    return len;
}
