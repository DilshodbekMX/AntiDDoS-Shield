/**
 * L7 Protocol Validator
 *
 * Application-layer validation for DNS, NTP, and HTTP.
 * Runs after L4 validation in the pipeline (Stage 4f).
 *
 * DNS/NTP: Full header validation (single UDP packet).
 * HTTP: First-packet method/version check only (no TCP reassembly).
 */

#ifndef LAYER1_L7_VALIDATOR_H
#define LAYER1_L7_VALIDATOR_H

#include <rte_mbuf.h>
#include "../../common/types.h"

// ==================== Return Codes ====================

#define L7_VALIDATE_OK                  0

// DNS errors (40-54)
#define L7_ERR_DNS_TOO_SHORT           40
#define L7_ERR_DNS_INVALID_OPCODE      41
#define L7_ERR_DNS_QR_MISMATCH         42
#define L7_ERR_DNS_QDCOUNT             43
#define L7_ERR_DNS_BOTH_PORT53         44
#define L7_ERR_DNS_AXFR_UDP            45
#define L7_ERR_DNS_LABEL_TOO_LONG      46
#define L7_ERR_DNS_NAME_TOO_LONG       47
#define L7_ERR_DNS_POINTER_LOOP        48
#define L7_ERR_DNS_MSG_TOO_LONG        49

// NTP errors (55-64)
#define L7_ERR_NTP_TOO_SHORT           55
#define L7_ERR_NTP_INVALID_VERSION     56
#define L7_ERR_NTP_INVALID_MODE        57
#define L7_ERR_NTP_INVALID_STRATUM     58
#define L7_ERR_NTP_MONLIST             59
#define L7_ERR_NTP_CONTROL             60
#define L7_ERR_NTP_SIZE_MISMATCH       61

// HTTP errors (65-69)
#define L7_ERR_HTTP_INVALID_METHOD     65
#define L7_ERR_HTTP_INVALID_VERSION    66
#define L7_ERR_HTTP_LINE_TOO_LONG      67
#define L7_ERR_HTTP_NON_ASCII          68

// ICMP errors (70-79)
#define L7_ERR_ICMP_REDIRECT           70
#define L7_ERR_ICMP_ROUTER_ADVERT      71
#define L7_ERR_ICMP_ROUTER_SOLICIT     72
#define L7_ERR_ICMP_TIMESTAMP          73
#define L7_ERR_ICMP_ADDRESS_MASK       74
#define L7_ERR_ICMP_INFO               75
#define L7_ERR_ICMP_SOURCE_QUENCH      76
#define L7_ERR_ICMP_RATE_LIMITED       77

// ==================== Public API ====================

/**
 * Validate L7 protocol headers.
 *
 * Dispatches to DNS/NTP/HTTP validators based on protocol and port.
 * Checks config toggles internally -- returns L7_VALIDATE_OK immediately
 * if the relevant protocol validation is disabled.
 *
 * @param m         Packet mbuf (for payload access)
 * @param features  Parsed L3/L4 features (protocol, ports, lengths)
 * @return L7_VALIDATE_OK (0) or error code (>0)
 */
int validate_l7_packet(struct rte_mbuf *m, const struct packet_features *features);

/**
 * Get human-readable error string for L7 error code.
 */
const char *l7_error_str(int code);

#endif /* LAYER1_L7_VALIDATOR_H */
