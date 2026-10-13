# ============================================================
# Ultra-Fast DPDK L2FWD Makefile
# ============================================================

# Build directory
BUILD_DIR = build

# Default target
all: $(BUILD_DIR)/l2fwd

# Setup and build with meson/ninja
$(BUILD_DIR)/l2fwd: meson.build main.c core/dpdk_core.c core/traffic_monitor.c
	@if [ ! -d $(BUILD_DIR) ]; then \
		echo "=== Setting up build directory ==="; \
		meson setup $(BUILD_DIR) --buildtype=release; \
	fi
	@echo "=== Building ==="
	ninja -C $(BUILD_DIR)

# Force rebuild
rebuild:
	rm -rf $(BUILD_DIR)
	meson setup $(BUILD_DIR) --buildtype=release
	ninja -C $(BUILD_DIR)

# Run with default settings (2 ports, 4 cores)
run: $(BUILD_DIR)/l2fwd
	sudo ./$(BUILD_DIR)/l2fwd -l 0-3 -n 4 -- -p 0x3 -P --no-mac-updating

# Run with MAC updating enabled
run-mac: $(BUILD_DIR)/l2fwd
	sudo ./$(BUILD_DIR)/l2fwd -l 0-3 -n 4 -- -p 0x3 -P

# Run with single core (for testing)
run-single: $(BUILD_DIR)/l2fwd
	sudo ./$(BUILD_DIR)/l2fwd -l 0 -n 4 -- -p 0x3 -P --no-mac-updating

# Run with all available cores
run-all: $(BUILD_DIR)/l2fwd
	sudo ./$(BUILD_DIR)/l2fwd -l 0-7 -n 4 -- -p 0x3 -P --no-mac-updating

# Run with GDB debugger
run-gdb: $(BUILD_DIR)/l2fwd
	sudo gdb --args ./$(BUILD_DIR)/l2fwd -l 0-3 -n 4 -- -p 0x3 -P --no-mac-updating

# Run with perf profiling
run-perf: $(BUILD_DIR)/l2fwd
	sudo perf record -g ./$(BUILD_DIR)/l2fwd -l 0-3 -n 4 -- -p 0x3 -P --no-mac-updating
	sudo perf report

# Run with perf stat (quick performance overview)
run-stat: $(BUILD_DIR)/l2fwd
	sudo perf stat -e cycles,instructions,cache-misses,cache-references \
		./$(BUILD_DIR)/l2fwd -l 0-3 -n 4 -- -p 0x3 -P --no-mac-updating

# Debug build
debug:
	rm -rf $(BUILD_DIR)
	meson setup $(BUILD_DIR) --buildtype=debug
	ninja -C $(BUILD_DIR)

# Build with sanitizers (for debugging memory issues)
sanitize:
	rm -rf $(BUILD_DIR)
	meson setup $(BUILD_DIR) --buildtype=debug -Db_sanitize=address,undefined
	ninja -C $(BUILD_DIR)

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)

# Deep clean (including meson cache)
distclean:
	rm -rf $(BUILD_DIR) .ninja_log .ninja_deps subprojects

# Check DPDK installation
check-dpdk:
	@echo "=== DPDK Info ==="
	@pkg-config --modversion libdpdk || echo "DPDK not found!"
	@echo ""
	@echo "=== DPDK Libs ==="
	@pkg-config --libs libdpdk | tr ' ' '\n' | head -20
	@echo ""
	@echo "=== Hugepages ==="
	@cat /proc/meminfo | grep Huge
	@echo ""
	@echo "=== DPDK Ports ==="
	@sudo dpdk-devbind.py --status 2>/dev/null || echo "dpdk-devbind.py not found"

# Setup hugepages (2MB pages)
setup-hugepages:
	@echo "=== Setting up 1024 x 2MB hugepages ==="
	sudo sh -c 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
	sudo mkdir -p /mnt/huge
	sudo mount -t hugetlbfs nodev /mnt/huge 2>/dev/null || true
	@echo "Done. Current hugepages:"
	@cat /proc/meminfo | grep Huge

# Setup hugepages (1GB pages - better for high performance)
setup-hugepages-1g:
	@echo "=== Setting up 4 x 1GB hugepages ==="
	sudo sh -c 'echo 4 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages'
	sudo mkdir -p /mnt/huge_1gb
	sudo mount -t hugetlbfs -o pagesize=1G nodev /mnt/huge_1gb 2>/dev/null || true
	@echo "Done."

# Bind NIC to DPDK (example: bind eth1 and eth2)
# Usage: make bind-nic NIC=0000:03:00.0
bind-nic:
	@if [ -z "$(NIC)" ]; then \
		echo "Usage: make bind-nic NIC=0000:03:00.0"; \
		echo ""; \
		echo "Available NICs:"; \
		sudo dpdk-devbind.py --status; \
	else \
		sudo dpdk-devbind.py --bind=vfio-pci $(NIC); \
		echo "Bound $(NIC) to vfio-pci"; \
	fi

# Unbind NIC from DPDK
unbind-nic:
	@if [ -z "$(NIC)" ]; then \
		echo "Usage: make unbind-nic NIC=0000:03:00.0"; \
	else \
		sudo dpdk-devbind.py --unbind $(NIC); \
		echo "Unbound $(NIC)"; \
	fi

# Show NIC status
nic-status:
	sudo dpdk-devbind.py --status

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		meson \
		ninja-build \
		python3-pyelftools \
		libnuma-dev \
		libpcap-dev \
		linux-headers-$(shell uname -r)

# Performance tuning recommendations
perf-tips:
	@echo "=============================================="
	@echo "  DPDK Performance Tuning Tips"
	@echo "=============================================="
	@echo ""
	@echo "1. CPU Isolation (add to /etc/default/grub):"
	@echo "   GRUB_CMDLINE_LINUX=\"isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7\""
	@echo ""
	@echo "2. Disable CPU frequency scaling:"
	@echo "   sudo cpupower frequency-set -g performance"
	@echo ""
	@echo "3. Use 1GB hugepages:"
	@echo "   make setup-hugepages-1g"
	@echo ""
	@echo "4. Disable IOMMU if not needed:"
	@echo "   Add 'iommu=off' to kernel cmdline"
	@echo ""
	@echo "5. Set IRQ affinity to non-DPDK cores:"
	@echo "   echo 1 > /proc/irq/<IRQ>/smp_affinity"
	@echo ""
	@echo "6. Run with --no-mac-updating for max speed"
	@echo ""
	@echo "=============================================="

# Build with tests
build-tests:
	rm -rf $(BUILD_DIR)
	meson setup $(BUILD_DIR) --buildtype=release -Dbuild_tests=true -Dbuild_benchmarks=true
	ninja -C $(BUILD_DIR)

# Run unit tests
test: build-tests
	cd $(BUILD_DIR) && meson test --verbose

# Run specific test
test-parser: build-tests
	sudo ./$(BUILD_DIR)/tests/unit/test_packet_parser --no-huge

# Run benchmarks (requires hugepages - run 'make setup-hugepages' first)
benchmark: build-tests
	sudo ./$(BUILD_DIR)/tests/benchmarks/layer1_benchmark -l 0 -n 4

# Help
help:
	@echo "=============================================="
	@echo "  DPDK Ultra-Fast L2FWD Build System"
	@echo "=============================================="
	@echo ""
	@echo "Build targets:"
	@echo "  all            - Build the project (default)"
	@echo "  rebuild        - Clean and rebuild"
	@echo "  debug          - Build with debug symbols"
	@echo "  sanitize       - Build with address sanitizer"
	@echo "  clean          - Remove build directory"
	@echo "  distclean      - Deep clean"
	@echo ""
	@echo "Run targets:"
	@echo "  run            - Run with default settings"
	@echo "  run-mac        - Run with MAC updating"
	@echo "  run-single     - Run on single core"
	@echo "  run-all        - Run on all cores (0-7)"
	@echo "  run-gdb        - Run with GDB debugger"
	@echo "  run-perf       - Run with perf profiling"
	@echo "  run-stat       - Run with perf stat"
	@echo ""
	@echo "Test targets:"
	@echo "  build-tests    - Build with tests enabled"
	@echo "  test           - Run all unit tests"
	@echo "  test-parser    - Run packet parser tests"
	@echo "  benchmark      - Run Layer 1 benchmarks"
	@echo ""
	@echo "Setup targets:"
	@echo "  check-dpdk     - Check DPDK installation"
	@echo "  setup-hugepages    - Setup 2MB hugepages"
	@echo "  setup-hugepages-1g - Setup 1GB hugepages"
	@echo "  bind-nic NIC=xxx   - Bind NIC to DPDK"
	@echo "  unbind-nic NIC=xxx - Unbind NIC from DPDK"
	@echo "  nic-status     - Show NIC status"
	@echo "  install-deps   - Install build dependencies"
	@echo ""
	@echo "Info targets:"
	@echo "  perf-tips      - Show performance tuning tips"
	@echo "  help           - Show this help"
	@echo ""

.PHONY: all rebuild run run-mac run-single run-all run-gdb run-perf run-stat \
        debug sanitize clean distclean check-dpdk setup-hugepages \
        setup-hugepages-1g bind-nic unbind-nic nic-status install-deps \
        perf-tips help build-tests test test-parser benchmark