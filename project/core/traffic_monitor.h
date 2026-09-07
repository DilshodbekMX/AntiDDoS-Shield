#ifndef TRAFFIC_MONITOR_H
#define TRAFFIC_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>

#define TRAFFIC_PORT 9998
#define TRAFFIC_INTERVAL_MS 100
#define TRAFFIC_MAGIC 0x5452464B  // "TRFK"
#define MAX_TRAFFIC_SAMPLES 100

// Protocol types
#define PROTO_UNKNOWN 0
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

#pragma pack(push, 1)

struct traffic_entry {
    uint64_t timestamp_ms;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t flags;  // TCP flags
    uint16_t pkt_len;
    uint16_t port_id;
    uint8_t direction;  // 0=RX, 1=TX
    uint8_t _pad[1];
};  // 32 bytes

struct traffic_packet {
    uint32_t magic;
    uint32_t length;
    uint64_t timestamp_ms;
    uint16_t entry_count;
    uint16_t _pad;
    struct traffic_entry entries[MAX_TRAFFIC_SAMPLES];
};  // 16 + 32*100 = 3216 bytes

#pragma pack(pop)

// Ring buffer for inter-core communication
struct traffic_ring {
    struct traffic_entry entries[MAX_TRAFFIC_SAMPLES * 4];
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t size;
} __rte_cache_aligned;

// Traffic analysis functions
int traffic_monitor_init(void);
void traffic_monitor_cleanup(void);
int traffic_monitor_launch(void *arg);
void traffic_capture_packet(struct rte_mbuf *m, uint16_t port_id, uint8_t direction);

#endif
