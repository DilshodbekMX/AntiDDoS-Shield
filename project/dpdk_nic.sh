#!/bin/bash

set -e  # Exit on any error
set -x  # Print commands for debugging

# Load vfio-pci module
modprobe vfio-pci

# Bring interfaces down before binding (optional, but usually needed)
ip link set ens34 down || true
ip link set ens37 down || true

# Set path to DPDK devbind tool
DPDK_BIND="dpdk-devbind.py"

# Enable vfio no-IOMMU mode (must be supported in your kernel)
# SECURITY WARNING: no-IOMMU mode bypasses DMA isolation. A compromised DPDK
# process can read/write arbitrary physical memory. Use IOMMU mode in production
# (requires VT-d / AMD-Vi enabled in BIOS). Only use no-IOMMU for dev/testing.
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

# Bind interfaces to vfio-pci with no-IOMMU mode
$DPDK_BIND --bind=vfio-pci --noiommu-mode 0000:02:02.0
$DPDK_BIND --bind=vfio-pci --noiommu-mode 0000:02:05.0

# Setup hugepages
mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages

# Allocate 2048 hugepages on node0
echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

