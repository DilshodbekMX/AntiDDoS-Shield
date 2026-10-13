#include "traffic_monitor.h"
#include "dpdk_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_lcore.h>

// Global ring buffer for packet samples
static struct traffic_ring *traffic_ring_buf = NULL;
static pthread_t traffic_thread;
static volatile bool traffic_running = false;
static int traffic_server_fd = -1;
static int traffic_client_fd = -1;

static uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Ring buffer operations
static inline bool ring_is_full(struct traffic_ring *ring) {
    return ((ring->head + 1) % ring->size) == ring->tail;
}

static inline bool ring_is_empty(struct traffic_ring *ring) {
    return ring->head == ring->tail;
}

static inline bool ring_enqueue(struct traffic_ring *ring, struct traffic_entry *entry) {
    if (ring_is_full(ring)) {
        return false;
    }
    uint32_t head = ring->head;
    ring->entries[head] = *entry;
    __atomic_store_n(&ring->head, (head + 1) % ring->size, __ATOMIC_RELEASE);
    return true;
}

static inline bool ring_dequeue(struct traffic_ring *ring, struct traffic_entry *entry) {
    if (ring_is_empty(ring)) {
        return false;
    }
    uint32_t tail = ring->tail;
    *entry = ring->entries[tail];
    __atomic_store_n(&ring->tail, (tail + 1) % ring->size, __ATOMIC_RELEASE);
    return true;
}

// Parse packet and extract key fields (src_ip, dst_ip, protocol, ports)
void traffic_capture_packet(struct rte_mbuf *m, uint16_t port_id, uint8_t direction) {
    if (!traffic_ring_buf || !traffic_running) {
        return;
    }

    struct traffic_entry entry;
    memset(&entry, 0, sizeof(entry));

    entry.timestamp_ms = get_timestamp_ms();
    entry.port_id = port_id;
    entry.direction = direction;
    entry.pkt_len = m->pkt_len;
    entry.protocol = PROTO_UNKNOWN;

    // Parse Ethernet header
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    // Only process IPv4 packets
    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return;
    }

    // Parse IP header
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));

    entry.src_ip = rte_be_to_cpu_32(ip->src_addr);
    entry.dst_ip = rte_be_to_cpu_32(ip->dst_addr);
    entry.protocol = ip->next_proto_id;

    // Parse transport layer
    uint8_t *l4_hdr = (uint8_t *)ip + (ip->version_ihl & 0x0F) * 4;

    switch (entry.protocol) {
        case PROTO_TCP: {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            entry.src_port = rte_be_to_cpu_16(tcp->src_port);
            entry.dst_port = rte_be_to_cpu_16(tcp->dst_port);
            entry.flags = tcp->tcp_flags;
            break;
        }
        case PROTO_UDP: {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            entry.src_port = rte_be_to_cpu_16(udp->src_port);
            entry.dst_port = rte_be_to_cpu_16(udp->dst_port);
            break;
        }
        case PROTO_ICMP:
            entry.src_port = 0;
            entry.dst_port = 0;
            break;
        default:
            entry.src_port = 0;
            entry.dst_port = 0;
            break;
    }

    // Try to enqueue (drop if full)
    ring_enqueue(traffic_ring_buf, &entry);
}

// Send traffic data to connected client
static int send_traffic_data(void) {
    if (traffic_client_fd < 0) {
        return -1;
    }

    struct traffic_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.magic = TRAFFIC_MAGIC;
    pkt.timestamp_ms = get_timestamp_ms();
    pkt.entry_count = 0;

    // Dequeue up to MAX_TRAFFIC_SAMPLES entries
    while (pkt.entry_count < MAX_TRAFFIC_SAMPLES) {
        if (!ring_dequeue(traffic_ring_buf, &pkt.entries[pkt.entry_count])) {
            break;
        }
        pkt.entry_count++;
    }

    // Only send if we have data
    if (pkt.entry_count == 0) {
        return 0;
    }

    pkt.length = sizeof(pkt);

    ssize_t sent = send(traffic_client_fd, &pkt, sizeof(pkt), MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EPIPE || errno == ECONNRESET) {
            printf("[Traffic] Client disconnected\n");
            close(traffic_client_fd);
            traffic_client_fd = -1;
        }
        return -1;
    }

    return 0;
}

// Traffic monitor thread function
static void *traffic_thread_func(void *arg) {
    (void)arg;
    struct sockaddr_in addr;

    traffic_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (traffic_server_fd < 0) {
        perror("[Traffic] socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(traffic_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(traffic_server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(TRAFFIC_PORT);

    if (bind(traffic_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[Traffic] bind");
        close(traffic_server_fd);
        return NULL;
    }

    if (listen(traffic_server_fd, 1) < 0) {
        perror("[Traffic] listen");
        close(traffic_server_fd);
        return NULL;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(traffic_server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("[Traffic] Listening on 127.0.0.1:%d\n", TRAFFIC_PORT);
    printf("[Traffic] sizeof(traffic_entry) = %zu\n", sizeof(struct traffic_entry));
    printf("[Traffic] sizeof(traffic_packet) = %zu\n", sizeof(struct traffic_packet));

    while (traffic_running) {
        // Accept new connections
        if (traffic_client_fd < 0) {
            traffic_client_fd = accept(traffic_server_fd, NULL, NULL);
            if (traffic_client_fd >= 0) {
                int flag = 1;
                setsockopt(traffic_client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                printf("[Traffic] Backend connected\n");
            }
        }

        // Send traffic data
        send_traffic_data();

        usleep(TRAFFIC_INTERVAL_MS * 1000);
    }

    return NULL;
}

int traffic_monitor_init(void) {
    // Allocate ring buffer
    traffic_ring_buf = calloc(1, sizeof(struct traffic_ring));
    if (!traffic_ring_buf) {
        fprintf(stderr, "[Traffic] Failed to allocate ring buffer\n");
        return -1;
    }

    traffic_ring_buf->head = 0;
    traffic_ring_buf->tail = 0;
    traffic_ring_buf->size = MAX_TRAFFIC_SAMPLES * 4;

    traffic_running = true;

    if (pthread_create(&traffic_thread, NULL, traffic_thread_func, NULL) != 0) {
        perror("[Traffic] pthread_create");
        free(traffic_ring_buf);
        return -1;
    }

    pthread_setname_np(traffic_thread, "dpdk-traffic");
    printf("[Traffic] Monitor initialized (ring size: %u)\n", traffic_ring_buf->size);
    return 0;
}

void traffic_monitor_cleanup(void) {
    traffic_running = false;

    if (traffic_thread) {
        pthread_join(traffic_thread, NULL);
    }

    if (traffic_client_fd >= 0) close(traffic_client_fd);
    if (traffic_server_fd >= 0) close(traffic_server_fd);

    if (traffic_ring_buf) {
        free(traffic_ring_buf);
        traffic_ring_buf = NULL;
    }

    printf("[Traffic] Cleaned up\n");
}

// Dedicated lcore function (not used in this implementation - integrated into main loop)
int traffic_monitor_launch(void *arg) {
    (void)arg;
    // This would be used if we had a dedicated core for traffic processing
    // For now, we integrate into the main packet processing loop
    return 0;
}
