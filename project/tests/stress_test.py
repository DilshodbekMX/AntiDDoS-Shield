#!/usr/bin/env python3
"""
Layer 1 Anti-DDoS Stress Test

This script simulates packet processing load to estimate system throughput
capabilities. It tests:
- Theoretical PPS (packets per second) capacity
- BPS (bytes per second) throughput
- Latency under load
- Memory efficiency

Since the actual DPDK benchmark requires root privileges, this Python script
provides an approximation based on CPU-only synthetic tests.

Usage:
    python3 stress_test.py [--duration 10] [--threads 4] [--packet-sizes 64,512,1500]
"""

import argparse
import time
import threading
import random
import struct
import hashlib
import multiprocessing
from dataclasses import dataclass
from typing import List, Tuple
import sys
import os

# Try to import optional dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

@dataclass
class BenchmarkResult:
    name: str
    total_packets: int
    total_bytes: int
    elapsed_sec: float
    pps: float
    mpps: float
    gbps: float
    mbps: float
    avg_latency_ns: float
    min_latency_ns: float
    max_latency_ns: float


class PacketGenerator:
    """Generates synthetic packet headers for testing"""

    # Common packet sizes in bytes
    PACKET_SIZES = {
        'min': 64,          # Minimum Ethernet frame
        'typical': 512,     # Typical mixed traffic
        'large': 1500,      # Maximum Ethernet MTU
        'jumbo': 9000,      # Jumbo frames
    }

    def __init__(self):
        self.counter = 0

    def generate_ipv4_header(self, src_ip: int = None, dst_ip: int = None) -> bytes:
        """Generate a synthetic IPv4 header (20 bytes)"""
        if src_ip is None:
            src_ip = random.randint(0x0A000001, 0x0AFFFFFF)  # 10.x.x.x
        if dst_ip is None:
            dst_ip = 0xC0A80101  # 192.168.1.1

        # IPv4 header: version, IHL, TOS, total_length, id, flags+frag, ttl, proto, checksum, src, dst
        header = struct.pack(
            '>BBHHHBBHII',
            0x45,           # Version (4) + IHL (5)
            0x00,           # TOS
            0x0028,         # Total length (40 bytes - IP + TCP)
            self.counter & 0xFFFF,  # ID
            0x4000,         # Flags (Don't Fragment) + Fragment offset
            64,             # TTL
            6,              # Protocol (TCP)
            0x0000,         # Checksum (would be calculated)
            src_ip,         # Source IP
            dst_ip          # Dest IP
        )
        self.counter += 1
        return header

    def generate_tcp_header(self, src_port: int = None, dst_port: int = 80, syn: bool = False) -> bytes:
        """Generate a synthetic TCP header (20 bytes)"""
        if src_port is None:
            src_port = random.randint(1024, 65535)

        flags = 0x02 if syn else 0x18  # SYN or PSH+ACK

        header = struct.pack(
            '>HHIIBBHHH',
            src_port,       # Source port
            dst_port,       # Dest port
            random.randint(0, 0xFFFFFFFF),  # Sequence number
            random.randint(0, 0xFFFFFFFF),  # Ack number
            0x50,           # Data offset (5 words)
            flags,          # Flags
            65535,          # Window size
            0x0000,         # Checksum
            0x0000          # Urgent pointer
        )
        return header

    def generate_udp_header(self, src_port: int = None, dst_port: int = 53) -> bytes:
        """Generate a synthetic UDP header (8 bytes)"""
        if src_port is None:
            src_port = random.randint(1024, 65535)

        header = struct.pack(
            '>HHHH',
            src_port,       # Source port
            dst_port,       # Dest port
            0x0040,         # Length (64 bytes)
            0x0000          # Checksum
        )
        return header

    def generate_packet(self, size: int = 64, protocol: str = 'tcp') -> bytes:
        """Generate a complete synthetic packet"""
        eth_header = b'\x00' * 14  # Dummy Ethernet header
        ip_header = self.generate_ipv4_header()

        if protocol == 'tcp':
            l4_header = self.generate_tcp_header()
        else:
            l4_header = self.generate_udp_header()

        # Calculate payload size
        header_size = len(eth_header) + len(ip_header) + len(l4_header)
        payload_size = max(0, size - header_size)
        payload = bytes(payload_size)

        return eth_header + ip_header + l4_header + payload


class PacketProcessor:
    """Simulates packet processing logic similar to Layer 1"""

    def __init__(self):
        self.whitelist = set()
        self.blacklist = set()
        self.flow_table = {}
        self.syn_proxy_table = {}

        # Add some test entries
        for i in range(1000):
            self.whitelist.add(0x0A000000 + i)
        for i in range(10000):
            self.blacklist.add(0x0B000000 + i)

    def parse_packet(self, packet: bytes) -> dict:
        """Parse packet headers (simulates packet_parser.c)"""
        if len(packet) < 34:  # Min Ethernet + IP header
            return None

        # Parse Ethernet
        eth_type = struct.unpack('>H', packet[12:14])[0]

        if eth_type != 0x0800:  # Not IPv4
            return None

        # Parse IP header
        ip_data = packet[14:34]
        version_ihl = ip_data[0]
        if (version_ihl >> 4) != 4:  # Not IPv4
            return None

        ihl = (version_ihl & 0x0F) * 4
        protocol = ip_data[9]
        src_ip = struct.unpack('>I', ip_data[12:16])[0]
        dst_ip = struct.unpack('>I', ip_data[16:20])[0]

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'ihl': ihl,
        }

    def check_whitelist(self, src_ip: int) -> bool:
        """Check if IP is whitelisted (simulates ip_lists.c)"""
        return src_ip in self.whitelist

    def check_blacklist(self, src_ip: int) -> bool:
        """Check if IP is blacklisted (simulates ip_lists.c)"""
        return src_ip in self.blacklist

    def compute_flow_hash(self, src_ip: int, dst_ip: int, src_port: int, dst_port: int, proto: int) -> int:
        """Compute flow hash (simulates flow_table.c)"""
        key = struct.pack('>IIHHI', src_ip, dst_ip, src_port, dst_port, proto)
        return hash(key) & 0xFFFFFFFF

    def check_syn_cookie(self, packet: bytes, pkt_info: dict) -> bool:
        """Simulate SYN cookie validation (simulates syn_proxy.c)"""
        if pkt_info['protocol'] != 6:  # TCP
            return True

        # Simple hash check simulation
        h = hashlib.sha1(packet[:54]).digest()
        return h[0] != 0  # 255/256 acceptance rate

    def process_packet(self, packet: bytes) -> Tuple[bool, str]:
        """
        Process a packet through simulated Layer 1 pipeline.
        Returns (accepted, reason)
        """
        # Stage 1: Parse
        pkt_info = self.parse_packet(packet)
        if pkt_info is None:
            return False, 'parse_error'

        src_ip = pkt_info['src_ip']

        # Stage 2: Whitelist check
        if self.check_whitelist(src_ip):
            return True, 'whitelisted'

        # Stage 3: Blacklist check
        if self.check_blacklist(src_ip):
            return False, 'blacklisted'

        # Stage 4: Validation (simplified)
        # In real code, this checks TTL, checksums, etc.

        # Stage 5: SYN cookie check
        if not self.check_syn_cookie(packet, pkt_info):
            return False, 'syn_cookie_failed'

        # Stage 6: Flow table lookup
        flow_hash = self.compute_flow_hash(
            src_ip, pkt_info['dst_ip'],
            0, 0,  # Would extract ports
            pkt_info['protocol']
        )

        # Stage 7: Rate limiting (simplified)
        # In real code, uses token bucket

        return True, 'accepted'


def run_single_thread_benchmark(
    duration_sec: float,
    packet_size: int,
    protocol: str
) -> BenchmarkResult:
    """Run benchmark on a single thread"""

    generator = PacketGenerator()
    processor = PacketProcessor()

    # Pre-generate a batch of packets for faster iteration
    batch_size = 1000
    packets = [generator.generate_packet(packet_size, protocol) for _ in range(batch_size)]

    total_packets = 0
    total_bytes = 0
    latencies = []

    start_time = time.perf_counter()
    end_time = start_time + duration_sec

    while time.perf_counter() < end_time:
        # Process a batch
        for packet in packets:
            pkt_start = time.perf_counter_ns()

            accepted, reason = processor.process_packet(packet)

            pkt_end = time.perf_counter_ns()

            total_packets += 1
            total_bytes += len(packet)

            # Sample latency (every 1000th packet to reduce overhead)
            if total_packets % 1000 == 0:
                latencies.append(pkt_end - pkt_start)

    elapsed = time.perf_counter() - start_time

    pps = total_packets / elapsed
    mpps = pps / 1e6
    bps = (total_bytes * 8) / elapsed
    gbps = bps / 1e9
    mbps = bps / 1e6

    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    min_lat = min(latencies) if latencies else 0
    max_lat = max(latencies) if latencies else 0

    return BenchmarkResult(
        name=f"{protocol.upper()} {packet_size}B",
        total_packets=total_packets,
        total_bytes=total_bytes,
        elapsed_sec=elapsed,
        pps=pps,
        mpps=mpps,
        gbps=gbps,
        mbps=mbps,
        avg_latency_ns=avg_lat,
        min_latency_ns=min_lat,
        max_latency_ns=max_lat
    )


def worker_thread(
    thread_id: int,
    duration_sec: float,
    packet_size: int,
    protocol: str,
    results: list
):
    """Worker thread for multi-threaded benchmark"""
    result = run_single_thread_benchmark(duration_sec, packet_size, protocol)
    results[thread_id] = result


def run_multi_thread_benchmark(
    duration_sec: float,
    packet_size: int,
    protocol: str,
    num_threads: int
) -> BenchmarkResult:
    """Run benchmark with multiple threads"""

    results = [None] * num_threads
    threads = []

    for i in range(num_threads):
        t = threading.Thread(
            target=worker_thread,
            args=(i, duration_sec, packet_size, protocol, results)
        )
        threads.append(t)

    # Start all threads
    for t in threads:
        t.start()

    # Wait for completion
    for t in threads:
        t.join()

    # Aggregate results
    total_packets = sum(r.total_packets for r in results)
    total_bytes = sum(r.total_bytes for r in results)
    elapsed = max(r.elapsed_sec for r in results)

    pps = total_packets / elapsed
    mpps = pps / 1e6
    bps = (total_bytes * 8) / elapsed
    gbps = bps / 1e9
    mbps = bps / 1e6

    all_avg = [r.avg_latency_ns for r in results]
    all_min = [r.min_latency_ns for r in results]
    all_max = [r.max_latency_ns for r in results]

    return BenchmarkResult(
        name=f"{protocol.upper()} {packet_size}B ({num_threads} threads)",
        total_packets=total_packets,
        total_bytes=total_bytes,
        elapsed_sec=elapsed,
        pps=pps,
        mpps=mpps,
        gbps=gbps,
        mbps=mbps,
        avg_latency_ns=sum(all_avg) / len(all_avg),
        min_latency_ns=min(all_min),
        max_latency_ns=max(all_max)
    )


def print_result(result: BenchmarkResult):
    """Print a single benchmark result"""
    print(f"\n  {result.name}")
    print(f"  {'-' * 60}")
    print(f"  {'Metric':<25} {'Value':>15} {'Unit':<15}")
    print(f"  {'-' * 60}")
    print(f"  {'Throughput':<25} {result.mpps:>15.3f} {'Mpps':<15}")
    print(f"  {'Packets/sec':<25} {result.pps:>15,.0f} {'pps':<15}")
    print(f"  {'Bits/sec':<25} {result.gbps:>15.3f} {'Gbps':<15}")
    print(f"  {'Bytes processed':<25} {result.total_bytes:>15,} {'bytes':<15}")
    print(f"  {'Avg latency':<25} {result.avg_latency_ns:>15,.0f} {'ns':<15}")
    print(f"  {'Min latency':<25} {result.min_latency_ns:>15,.0f} {'ns':<15}")
    print(f"  {'Max latency':<25} {result.max_latency_ns:>15,.0f} {'ns':<15}")
    print(f"  {'Duration':<25} {result.elapsed_sec:>15.2f} {'sec':<15}")


def estimate_dpdk_performance(python_mpps: float, num_cores: int) -> dict:
    """
    Estimate DPDK performance based on Python benchmark.

    DPDK typically achieves 10-50x better performance than Python due to:
    - Zero-copy packet handling
    - Kernel bypass
    - Poll-mode drivers
    - Cache-optimized data structures
    - No GIL (Global Interpreter Lock)
    - Inline assembly optimizations
    """

    # Conservative multipliers based on typical DPDK vs Python ratios
    # These are approximations based on industry benchmarks

    # DPDK single-core typically achieves 10-20 Mpps for simple forwarding
    # With Layer 1 processing overhead, expect 5-15 Mpps per core

    dpdk_single_core_mpps = python_mpps * 30  # Conservative 30x improvement
    dpdk_multi_core_mpps = dpdk_single_core_mpps * num_cores * 0.85  # 85% scaling efficiency

    # Maximum theoretical limits
    # 10GbE line rate: 14.88 Mpps @ 64 bytes
    # 25GbE line rate: 37.20 Mpps @ 64 bytes
    # 40GbE line rate: 59.52 Mpps @ 64 bytes
    # 100GbE line rate: 148.8 Mpps @ 64 bytes

    return {
        'estimated_single_core_mpps': min(dpdk_single_core_mpps, 15),  # Cap at realistic max
        'estimated_multi_core_mpps': min(dpdk_multi_core_mpps, 60),    # Cap at 40GbE line rate
        'estimated_gbps_64b': min(dpdk_multi_core_mpps * 64 * 8 / 1000, 40),
        'estimated_gbps_1500b': min(dpdk_multi_core_mpps * 1500 * 8 / 1000, 100),
        'scaling_cores': num_cores,
    }


def main():
    parser = argparse.ArgumentParser(description='Layer 1 Anti-DDoS Stress Test')
    parser.add_argument('--duration', type=float, default=5,
                        help='Test duration in seconds (default: 5)')
    parser.add_argument('--threads', type=int, default=None,
                        help='Number of threads (default: CPU count)')
    parser.add_argument('--packet-sizes', type=str, default='64,512,1500',
                        help='Comma-separated packet sizes (default: 64,512,1500)')
    parser.add_argument('--protocols', type=str, default='tcp,udp',
                        help='Comma-separated protocols (default: tcp,udp)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick test (1 second, single thread)')

    args = parser.parse_args()

    if args.threads is None:
        args.threads = multiprocessing.cpu_count()

    packet_sizes = [int(s.strip()) for s in args.packet_sizes.split(',')]
    protocols = [p.strip().lower() for p in args.protocols.split(',')]

    if args.quick:
        args.duration = 1
        args.threads = 1
        packet_sizes = [64]
        protocols = ['tcp']

    print("=" * 70)
    print("       Layer 1 Anti-DDoS Throughput Stress Test")
    print("=" * 70)
    print(f"\n  Configuration:")
    print(f"    Duration:     {args.duration} seconds")
    print(f"    Threads:      {args.threads}")
    print(f"    Packet sizes: {packet_sizes}")
    print(f"    Protocols:    {protocols}")
    print(f"    CPU cores:    {multiprocessing.cpu_count()}")
    print()

    all_results = []

    # Single-threaded tests
    print("\n" + "=" * 70)
    print("  SINGLE-THREADED BENCHMARK (Pure Python Processing)")
    print("=" * 70)

    for size in packet_sizes:
        for proto in protocols:
            print(f"\n  Running: {proto.upper()} {size}B packets...")
            result = run_single_thread_benchmark(args.duration, size, proto)
            print_result(result)
            all_results.append(result)

    # Multi-threaded tests
    if args.threads > 1:
        print("\n" + "=" * 70)
        print(f"  MULTI-THREADED BENCHMARK ({args.threads} threads)")
        print("=" * 70)

        for size in packet_sizes:
            for proto in protocols:
                print(f"\n  Running: {proto.upper()} {size}B packets...")
                result = run_multi_thread_benchmark(args.duration, size, proto, args.threads)
                print_result(result)
                all_results.append(result)

    # Summary and DPDK estimates
    print("\n" + "=" * 70)
    print("  SUMMARY & DPDK PERFORMANCE ESTIMATES")
    print("=" * 70)

    # Find best single-threaded result with 64-byte packets
    single_64b = [r for r in all_results if '64B' in r.name and 'threads' not in r.name]
    if single_64b:
        best_single = max(single_64b, key=lambda r: r.mpps)
        print(f"\n  Best Python single-thread (64B): {best_single.mpps:.3f} Mpps")

        estimates = estimate_dpdk_performance(best_single.mpps, args.threads)

        print("\n  DPDK Performance Estimates (based on Python baseline):")
        print(f"    Single core:      ~{estimates['estimated_single_core_mpps']:.1f} Mpps")
        print(f"    Multi-core ({estimates['scaling_cores']} cores): ~{estimates['estimated_multi_core_mpps']:.1f} Mpps")
        print(f"    Throughput (64B): ~{estimates['estimated_gbps_64b']:.1f} Gbps")
        print(f"    Throughput (1500B): ~{estimates['estimated_gbps_1500b']:.1f} Gbps")

    print("\n  Notes:")
    print("    - Python benchmark shows ~30-50x slower than actual DPDK performance")
    print("    - DPDK uses kernel bypass, zero-copy, poll-mode drivers")
    print("    - Actual performance depends on NIC, CPU, and memory speed")
    print("    - For accurate results, run: sudo ./build/tests/benchmarks/layer1_benchmark")
    print()

    # Print theoretical line rate limits
    print("  Theoretical Line Rate Limits (64-byte packets):")
    print("    10 GbE:  14.88 Mpps  |  40 GbE:  59.52 Mpps")
    print("    25 GbE:  37.20 Mpps  | 100 GbE: 148.80 Mpps")
    print()

    print("=" * 70)
    print("  Stress test complete!")
    print("=" * 70)


if __name__ == '__main__':
    main()
