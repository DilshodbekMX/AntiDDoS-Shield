project('l2fwd', 'c',
  version: '0.1.0',
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'warning_level=2',
    'optimization=3',
    'b_lto=true',           # Link-time optimization
  ],
)

# DPDK is required for the full data-plane engine (Layer 1 + l2fwd executable). It is made
# optional so the DPDK-free Layer-2 module unit tests (conformal_combine, routed_fdr,
# conformal_live) still configure and run in environments without DPDK (CI, dev sandboxes).
dpdk_dep = dependency('libdpdk', required: false)
sqlite3_dep = dependency('sqlite3', required: true)
# libm as a proper dependency so -flto-generated objects resolve math symbols (log/sqrt)
# regardless of link order; the bare '-lm' link_arg is dropped before LTO ltrans objects.
m_dep = meson.get_compiler('c').find_library('m', required: true)

# Aggressive optimization flags - must be before any build targets
add_project_arguments([
  '-D_GNU_SOURCE',
  '-march=native',          # Use all CPU features
  '-mtune=native',
  '-funroll-loops',         # Unroll loops
  '-flto',                  # Link-time optimization
  # SECURITY: Re-enabled stack protection. While -fno-stack-protector saves ~2-5 cycles
  # per function call, a security product should not disable security features.
  # The overhead is negligible compared to the protection provided.
  '-fstack-protector-strong',
], language: 'c')

# NOTE: -ffast-math was removed because it can cause incorrect results in:
# - Entropy calculations (layer2 detection)
# - Statistical computations (z-score, variance)
# - Floating point comparisons (threshold checks)
# The performance benefit (~5-10%) is not worth the accuracy risk.

# cJSON - embedded as source (MIT license)
libcjson = static_library('cjson',
  sources: ['external/cJSON.c'],
  include_directories: include_directories('external'),
)

# --- DPDK-dependent build targets (Layer 1 data plane + full engine) ---
# Skipped entirely when DPDK is absent; the DPDK-free Layer-2 unit tests still build below.
if dpdk_dep.found()

# Common data structures library (header-only, but we create empty lib for linking consistency)
libcommon = static_library('common',
  sources: [],  # Header-only library
  include_directories: include_directories('common'),
  dependencies: [dpdk_dep],
)

# Layer 1 Anti-DDoS library
layer1_src = [
  'layer1/layer1.c',
  'layer1/config/layer1_config.c',
  'layer1/config/config_protobuf.c',  # Secure JSON parser (replaces cJSON vulnerabilities)
  'layer1/datapath/packet_parser.c',
  'layer1/datapath/packet_parser_v6.c',  # IPv6 dual-stack packet parser
  'layer1/datapath/packet_features.c',
  'layer1/tables/flow_table.c',
  'layer1/tables/flow_table_v6.c',  # IPv6 flow table (stub for now)
  'layer1/tables/ip_lists.c',
  'layer1/tables/ip_lists_v6.c',  # IPv6 whitelist/blacklist with LPM6
  'layer1/tables/syn_proxy.c',
  'layer1/tables/syn_proxy_v6.c',  # IPv6 SYN proxy with 128-bit cookies
  'layer1/tables/connection_limits.c',
  'layer1/tables/count_min_sketch.c',
  'layer1/tables/udp_gatekeeper.c',
  'layer1/tables/geo_blocking.c',
  'layer1/tables/geo_blocking_v6.c',  # IPv6 geo-blocking with LPM6
  'layer1/tables/other_protocols.c',
  'layer1/tables/signatures.c',
  'layer1/tables/tcp_fingerprint.c',
  'layer1/tables/tcp_abuse_detection.c',  # TCP protocol abuse detection
  'layer1/tables/tcp_flag_rate_limit.c',  # Per-TCP-flag rate limiting
  'layer1/datapath/l7_validator.c',       # Layer 7 protocol validation
  'layer1/interlayer/shared_memory.c',
  'layer1/interlayer/policy_interface.c',
  'layer1/interlayer/reputation_interface.c',
  'layer1/interlayer/dynamic_signatures.c',
  'layer1/interlayer/packet_ring.c',
  'layer1/interlayer/src_ip_stats.c',
  'layer1/telemetry/telemetry_exporter.c',
  'layer1/telemetry/hyperloglog.c',
  'layer1/telemetry/per_ip_features.c',
  'layer1/telemetry/dpdk_telemetry.c',
  'layer1/telemetry/realtime_telemetry.c',
  'layer1/telemetry/window_stats.c',
  'layer1/telemetry/spike_detector.c',
  'layer1/telemetry/latency_histogram.c',
  'layer1/telemetry/heavy_hitter_export.c',
  'layer1/telemetry/per_ip_features_v6.c',  # IPv6 per-IP features with 128-bit keys
]

liblayer1 = static_library('layer1',
  sources: layer1_src,
  include_directories: include_directories('common', 'external', 'layer1', 'layer1/config', 'layer1/interlayer', 'layer1/datapath', 'layer1/tables', 'layer1/telemetry'),
  dependencies: [dpdk_dep, sqlite3_dep],
  link_with: [libcommon, libcjson],
  link_args: ['-lm'],  # Link math library for entropy calculation
)

# Layer 2 Behavioral Monitor library
layer2_src = [
  'layer2/layer2.c',
  'layer2/baselines.c',
  'layer2/detection.c',
  'layer2/advanced_detection.c',
  'layer2/attack_classification.c',
  'layer2/adaptive_threshold.c',
  'layer2/fast_detection.c',
  'layer2/conformal_combine.c',
  'layer2/conformal_live.c',
  'layer2/routed_fdr.c',
  'layer2/routed_live.c',
  'layer2/innovation_gate.c',
  'layer2/config/layer2_config.c',
]

liblayer2 = static_library('layer2',
  sources: layer2_src,
  include_directories: include_directories('common', 'external', 'layer1', 'layer1/interlayer', 'layer2', 'layer2/config'),
  dependencies: [dpdk_dep],
  link_with: [liblayer1, libcjson],
  link_args: ['-lm', '-lpthread'],
)

# Core DPDK processing library
core_src = [
  'core/dpdk_core.c',
  'core/stats_socket.c',
  'core/traffic_monitor.c',
  'core/control_socket.c',
  'core/control_socket_security.c',  # Security enhancements for control socket
  'core/system_monitor.c',
  'core/prometheus_exporter.c',
  'core/packet_pipeline.c',  # Modular packet processing pipeline abstraction
]

libcore = static_library('core',
  sources: core_src,
  include_directories: include_directories('common', 'external', 'layer1', 'layer1/config', 'layer1/interlayer', 'layer1/datapath', 'layer1/tables', 'layer1/telemetry', 'layer2', 'layer2/config', 'core'),
  dependencies: [dpdk_dep, sqlite3_dep],
  link_with: [liblayer1, liblayer2, libcommon, libcjson],
)

# Main executable
executable('l2fwd',
  sources: ['main.c'],
  include_directories: include_directories('common', 'external', 'layer1', 'layer1/config', 'layer1/interlayer', 'layer1/datapath', 'layer1/tables', 'layer1/telemetry', 'layer2', 'layer2/config', 'core'),
  dependencies: [dpdk_dep, sqlite3_dep, m_dep],
  link_with: [libcore, liblayer1, liblayer2, libcommon, libcjson],
  link_args: ['-flto', '-lpthread', '-lm', '-lsqlite3'],
  install: true,
)

# Export libs for tests
layer1_lib = liblayer1
core_lib = libcore

endif  # dpdk_dep.found()

# Tests — tests/unit builds the DPDK-free module tests unconditionally and guards the
# DPDK-linking tests internally with dpdk_dep.found().
if get_option('build_tests')
  subdir('tests/unit')
  if dpdk_dep.found()
    subdir('tests/integration')
  endif
endif

# Benchmarks (DPDK-dependent)
if dpdk_dep.found() and get_option('build_benchmarks')
  subdir('tests/benchmarks')
endif

# Fuzz tests (requires clang with libFuzzer)
if get_option('build_fuzz')
  subdir('tests/fuzz')
endif
