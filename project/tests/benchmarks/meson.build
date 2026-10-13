# Layer 1 Benchmark Build Configuration
#
# Build with: meson compile -C builddir layer1_benchmark
#
# Note: This benchmark requires DPDK and must be run as root or with
# appropriate hugepage permissions.

benchmark_sources = files('layer1_benchmark.c')

# Layer 1 benchmark executable
layer1_benchmark = executable(
    'layer1_benchmark',
    benchmark_sources,
    dependencies: [dpdk_dep, sqlite3_dep],
    link_with: [core_lib, layer1_lib, libcommon, libcjson],
    include_directories: include_directories('../../common', '../../external', '../../layer1', '../../layer1/config', '../../layer1/interlayer', '../../layer1/datapath', '../../layer1/tables', '../../layer1/telemetry', '../../core'),
    link_args: ['-lm', '-lpthread', '-lsqlite3'],
    install: false,
)
