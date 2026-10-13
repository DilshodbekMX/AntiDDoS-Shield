/**
 * @file pcap_replay.h
 * @brief PCAP Replay Integration Test Framework
 *
 * Provides utilities for replaying pcap files through the Anti-DDoS
 * packet processing pipeline for integration testing.
 */

#ifndef TESTS_PCAP_REPLAY_H
#define TESTS_PCAP_REPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== Test Result Structures ==================== */

/**
 * Per-packet processing result
 */
struct pcap_pkt_result {
    uint32_t pkt_num;           /* Packet number in pcap */
    uint32_t pkt_len;           /* Original packet length */
    int      parse_result;      /* parse_packet() return value */
    int      validate_result;   /* validate_packet() return value */
    uint8_t  protocol;          /* Parsed protocol */
    uint8_t  tcp_flags;         /* TCP flags if TCP */
    bool     is_ipv6;           /* IPv6 packet? */
    bool     dropped;           /* Would be dropped? */
    char     drop_reason[32];   /* Drop reason string */
};

/**
 * Aggregate test statistics
 */
struct pcap_test_stats {
    /* Packet counts */
    uint64_t total_packets;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t non_ip_packets;

    /* Parse results */
    uint64_t parse_ok;
    uint64_t parse_malformed;
    uint64_t parse_unsupported;

    /* Validation results */
    uint64_t validate_ok;
    uint64_t validate_failed;
    uint64_t validation_errors[32];   /* Per-error-code counts */

    /* Protocol breakdown */
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_proto_packets;

    /* TCP flag breakdown */
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t ack_only_packets;
    uint64_t rst_packets;
    uint64_t fin_packets;

    /* Drop statistics */
    uint64_t dropped_total;
    uint64_t dropped_blacklist;
    uint64_t dropped_rate_limit;
    uint64_t dropped_syn_flood;
    uint64_t dropped_validation;
    uint64_t dropped_geo;

    /* Performance */
    uint64_t total_bytes;
    uint64_t processing_cycles;
    double   packets_per_sec;     /* Estimated throughput */
};

/**
 * Attack scenario test expectations
 */
struct attack_test_spec {
    const char *name;           /* Test name */
    const char *pcap_file;      /* Path to pcap file */

    /* Expected attack characteristics */
    uint64_t min_packets;       /* Minimum packets expected */
    uint64_t max_packets;       /* Maximum packets (0=unlimited) */

    /* Protocol expectations */
    uint8_t  expected_protocol; /* Primary protocol (0=any) */
    double   min_proto_ratio;   /* Minimum ratio of expected protocol */

    /* Attack detection expectations */
    bool     expect_syn_flood;  /* Should detect SYN flood? */
    bool     expect_udp_flood;  /* Should detect UDP flood? */
    bool     expect_amplification;
    double   min_drop_ratio;    /* Minimum packets that should be dropped */
    double   max_drop_ratio;    /* Maximum packets that should be dropped */

    /* Validation expectations */
    double   min_malformed_ratio;  /* Minimum malformed packets (for fuzzing) */
    uint32_t expected_validation_errors;  /* Bitmask of expected errors */
};

/* ==================== Initialization ==================== */

/**
 * Initialize DPDK EAL for testing (minimal configuration)
 *
 * @return 0 on success, -1 on error
 */
int pcap_test_init_eal(void);

/**
 * Initialize packet processing subsystems for testing
 *
 * @return 0 on success, -1 on error
 */
int pcap_test_init_layer1(void);

/**
 * Cleanup test environment
 */
void pcap_test_cleanup(void);

/* ==================== PCAP Replay Functions ==================== */

/**
 * Replay a pcap file through the packet parser
 *
 * @param pcap_path   Path to pcap or pcapng file
 * @param stats       Output statistics (can be NULL)
 * @param max_packets Maximum packets to process (0=unlimited)
 * @return Number of packets processed, -1 on error
 */
int64_t pcap_replay_file(const char *pcap_path,
                         struct pcap_test_stats *stats,
                         uint64_t max_packets);

/**
 * Replay pcap with per-packet callback
 *
 * @param pcap_path   Path to pcap file
 * @param callback    Function called for each packet result
 * @param user_data   User data passed to callback
 * @param max_packets Maximum packets to process (0=unlimited)
 * @return Number of packets processed, -1 on error
 */
typedef void (*pcap_pkt_callback)(const struct pcap_pkt_result *result,
                                  void *user_data);

int64_t pcap_replay_with_callback(const char *pcap_path,
                                  pcap_pkt_callback callback,
                                  void *user_data,
                                  uint64_t max_packets);

/* ==================== Test Execution ==================== */

/**
 * Run a single attack scenario test
 *
 * @param spec  Test specification
 * @param stats Output statistics
 * @return true if test passed, false if failed
 */
bool pcap_run_attack_test(const struct attack_test_spec *spec,
                          struct pcap_test_stats *stats);

/**
 * Run all registered attack scenario tests
 *
 * @return Number of tests passed
 */
int pcap_run_all_tests(void);

/* ==================== Utility Functions ==================== */

/**
 * Create an mbuf from raw packet data (for testing without libpcap)
 *
 * @param data     Raw packet data (starting from Ethernet header)
 * @param len      Length of packet data
 * @return mbuf or NULL on error (caller must free)
 */
struct rte_mbuf *pcap_create_mbuf(const uint8_t *data, uint16_t len);

/**
 * Free an mbuf created by pcap_create_mbuf
 */
void pcap_free_mbuf(struct rte_mbuf *m);

/**
 * Print test statistics summary
 *
 * @param stats  Statistics to print
 */
void pcap_print_stats(const struct pcap_test_stats *stats);

/**
 * Reset statistics structure
 */
void pcap_reset_stats(struct pcap_test_stats *stats);

/**
 * Generate synthetic attack packets
 *
 * @param type      Attack type ("syn_flood", "udp_flood", "icmp_flood", etc.)
 * @param count     Number of packets to generate
 * @param dst_ip    Target IP (network byte order)
 * @param callback  Callback for each generated packet
 * @param user_data User data for callback
 * @return Number of packets generated
 */
int pcap_generate_attack(const char *type,
                         uint32_t count,
                         uint32_t dst_ip,
                         pcap_pkt_callback callback,
                         void *user_data);

/* ==================== Attack Scenarios ==================== */

/**
 * Pre-defined attack scenario specifications
 */
extern const struct attack_test_spec attack_syn_flood_spec;
extern const struct attack_test_spec attack_udp_flood_spec;
extern const struct attack_test_spec attack_dns_amplification_spec;
extern const struct attack_test_spec attack_ntp_amplification_spec;
extern const struct attack_test_spec attack_tcp_xmas_spec;
extern const struct attack_test_spec attack_tcp_null_spec;
extern const struct attack_test_spec attack_land_spec;
extern const struct attack_test_spec attack_smurf_spec;
extern const struct attack_test_spec attack_fraggle_spec;
extern const struct attack_test_spec attack_slowloris_spec;

#ifdef __cplusplus
}
#endif

#endif /* TESTS_PCAP_REPLAY_H */
