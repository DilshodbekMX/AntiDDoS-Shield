# Anti-DDoS System - Installation & Run Guide

Step-by-step guide to install and run this system on a **fresh Ubuntu 22.04 or 24.04** machine.
Every command is exact and copy-pasteable. Nothing is assumed pre-installed.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Step 1 - Update the System](#2-step-1---update-the-system)
3. [Step 2 - Install Build Tools and System Libraries](#3-step-2---install-build-tools-and-system-libraries)
4. [Step 3 - Install Python 3.10+](#4-step-3---install-python-310)
5. [Step 4 - Install Node.js 24.13.0](#5-step-4---install-nodejs-24130)
6. [Step 5 - Install DPDK from Source](#6-step-5---install-dpdk-from-source)
7. [Step 6 - Clone the Project](#7-step-6---clone-the-project)
8. [Step 7 - Build the C Data Plane](#8-step-7---build-the-c-data-plane)
9. [Step 8 - Configure Hugepages](#9-step-8---configure-hugepages)
10. [Step 9 - Setup IOMMU and Bind NICs to DPDK](#10-step-9---setup-iommu-and-bind-nics-to-dpdk)
11. [Step 10 - Setup Python Virtual Environment and Backend](#11-step-10---setup-python-virtual-environment-and-backend)
12. [Step 11 - Install Layer 3 ML Engine](#12-step-11---install-layer-3-ml-engine)
13. [Step 12 - Install Dashboard](#13-step-12---install-dashboard)
14. [Step 13 - Create Required Directories and Config Files](#14-step-13---create-required-directories-and-config-files)
15. [Step 14 - Run the System](#15-step-14---run-the-system)
16. [Step 15 - Verify Everything Works](#16-step-15---verify-everything-works)
17. [Running Without DPDK (Dashboard Only)](#17-running-without-dpdk-dashboard-only)
18. [Running Tests](#18-running-tests)
19. [Optional: Redis Cache](#19-optional-redis-cache)
20. [Optional: GeoIP Database](#20-optional-geoip-database)
21. [Optional: Persistent Hugepages Across Reboots](#21-optional-persistent-hugepages-across-reboots)
22. [Optional: Performance Tuning for Production](#22-optional-performance-tuning-for-production)
23. [Troubleshooting A-Z](#23-troubleshooting-a-z)
24. [Quick Reference](#24-quick-reference)
25. [Architecture Overview](#25-architecture-overview)

---

## 1. System Requirements

| Component   | Minimum              | Recommended                |
|-------------|----------------------|----------------------------|
| OS          | Ubuntu 22.04 LTS     | Ubuntu 22.04 / 24.04 LTS  |
| Architecture| x86_64 (AMD64) only  | x86_64 with SSE4.2+       |
| CPU         | 4 cores              | 8+ cores                   |
| RAM         | 8 GB                 | 16+ GB                     |
| Storage     | 20 GB free           | 50+ GB SSD                 |
| NIC (for DPDK) | Any DPDK-supported NIC | Intel X710, 82599, Mellanox ConnectX |
| Internet    | Required during install | For downloading packages |

**Important notes:**
- You need **at least 2 network interfaces** if running DPDK: one for management/SSH, one (or two) for DPDK packet processing. DPDK takes full control of its NICs away from the kernel - you will lose SSH if you bind your management NIC.
- If you only want to run the dashboard/API without DPDK (for development or remote management), you do NOT need a DPDK-compatible NIC.
- All commands below assume you are logged in as a regular user with `sudo` privileges.

---

## 2. Step 1 - Update the System

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo reboot
```

After reboot, log back in and continue.

---

## 3. Step 2 - Install Build Tools and System Libraries

This installs everything needed to compile DPDK and the Anti-DDoS C code.

```bash
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    meson \
    ninja-build \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    python3-pyelftools \
    python3-setuptools \
    libnuma-dev \
    libpcap-dev \
    libsqlite3-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    linux-headers-$(uname -r) \
    git \
    curl \
    wget \
    unzip \
    net-tools \
    pciutils \
    hwloc \
    numactl
```

**Verify they installed correctly:**

```bash
gcc --version
# Expected: gcc (Ubuntu 11.x or 12.x or 13.x) ...

meson --version
# Expected: 0.61+ (Ubuntu 22.04 ships 0.61, Ubuntu 24.04 ships 1.3+)

ninja --version
# Expected: 1.10+

python3 --version
# Expected: Python 3.10+ (Ubuntu 22.04 = 3.10, Ubuntu 24.04 = 3.12)

pkg-config --version
# Expected: 0.29+
```

**If meson version is too old (below 0.60):**

```bash
pip3 install --user meson
# Then add to PATH:
export PATH="$HOME/.local/bin:$PATH"
# Make permanent:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
meson --version
```

---

## 4. Step 3 - Install Python 3.10+

Ubuntu 22.04 ships Python 3.10 and Ubuntu 24.04 ships Python 3.12, so this should already be done. Verify:

```bash
python3 --version
```

If for some reason python3 is missing or too old:

```bash
sudo apt-get install -y software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
# Use python3.11 instead of python3 in all commands below
```

Also ensure pip is up to date:

```bash
python3 -m pip install --upgrade pip
```

If pip is not installed:

```bash
sudo apt-get install -y python3-pip
```

---

## 5. Step 4 - Install Node.js 24.13.0

Ubuntu's default Node.js is usually too old (v12). We'll use nvm (Node Version Manager) to install Node.js 24.13.0:

```bash
# Remove old nodejs if present (optional)
sudo apt-get remove -y nodejs npm 2>/dev/null || true

# Install nvm (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash

# Load nvm in current shell
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Install Node.js 24.13.0
nvm install 24.13.0

# Set as default
nvm alias default 24.13.0
```

**Verify:**

```bash
node --version
# Expected: v24.13.0

npm --version
# Expected: 11.6.2
```

**For new terminal sessions:**

nvm is automatically loaded via your `~/.bashrc`. If you need to load it manually:

```bash
source ~/.bashrc
```

Or in a new terminal, nvm will be available automatically.

If `curl: command not found`:
```bash
sudo apt-get install -y curl
```

---

## 6. Step 5 - Install DPDK from Source

The project requires DPDK. We build from source for maximum compatibility.

### 6.1 Download and extract DPDK

```bash
cd /tmp

# Download DPDK 23.11 LTS (stable, well-tested)
wget https://fast.dpdk.org/rel/dpdk-23.11.tar.xz

# Extract
tar xf dpdk-23.11.tar.xz
cd dpdk-23.11
```

> **Note:** You can also use newer versions like 24.11 or 25.03. The project works with DPDK 22.11+.

### 6.2 Build DPDK

```bash
meson setup build
ninja -C build
```

This takes 2-10 minutes depending on your CPU.

**If you get errors:**

- `pyelftools not found` -> `sudo apt-get install -y python3-pyelftools`
- `libnuma not found` -> `sudo apt-get install -y libnuma-dev`
- `kernel headers not found` -> `sudo apt-get install -y linux-headers-$(uname -r)`

### 6.3 Install DPDK system-wide

```bash
sudo ninja -C build install
sudo ldconfig
```

### 6.4 Set PKG_CONFIG_PATH

DPDK installs its pkg-config files to `/usr/local/lib/x86_64-linux-gnu/pkgconfig/`.
You **must** make sure pkg-config can find them:

```bash
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
```

**Make this permanent** (critical - without this, `make` will fail with "libdpdk not found"):

```bash
echo 'export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH' >> ~/.bashrc
source ~/.bashrc
```

### 6.5 Update library cache

```bash
# Ensure the linker can find DPDK shared libraries
echo '/usr/local/lib/x86_64-linux-gnu' | sudo tee /etc/ld.so.conf.d/dpdk.conf
sudo ldconfig
```

### 6.6 Verify DPDK installed correctly

```bash
pkg-config --modversion libdpdk
# Expected: 23.11.0 (or whatever version you installed)

pkg-config --libs libdpdk | head -c 100
# Expected: -L/usr/local/lib/x86_64-linux-gnu -Wl,--as-needed -lrte_node ...
```

If `pkg-config --modversion libdpdk` prints nothing or errors, go back to step 6.4.

### 6.7 Verify dpdk-devbind.py is available

```bash
which dpdk-devbind.py
# Expected: /usr/local/bin/dpdk-devbind.py

# If not found, find it:
sudo find / -name "dpdk-devbind.py" 2>/dev/null
# Then add its directory to PATH or create a symlink:
# sudo ln -s /path/to/dpdk-devbind.py /usr/local/bin/dpdk-devbind.py
```

### 6.8 Cleanup

```bash
cd ~
rm -rf /tmp/dpdk-23.11 /tmp/dpdk-23.11.tar.xz
```

---

## 7. Step 6 - Clone the Project

```bash
cd ~
git clone <repository-url> antiddos
cd antiddos/project
```

If you already have the project:

```bash
cd ~/antiddos/project   # or wherever your project is
```

All remaining commands assume you are in the `project/` directory — the build root that
holds the `Makefile`, `backend/`, `dashboard/`, `layer1/`, `layer2/`, and `start.sh`.
(The repository root above `project/` contains the paper, docs, and evaluation harness.)

---

## 8. Step 7 - Build the C Data Plane

### 8.1 Production build (multi-tenant)

```bash
make all
```

**Expected output:**

```
=== Setting up build directory ===
...
=== Building ===
[XX/XX] Linking target l2fwd
```

### 8.2 Verify the binary was created

```bash
ls -lh build/l2fwd
# Expected: a file of ~1-5 MB
```

### 8.3 Common build errors and fixes

**Error: `dependency 'libdpdk' not found`**

```bash
# Fix: set PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH

# Then rebuild
make rebuild
```

**Error: `dependency 'sqlite3' not found`**

```bash
sudo apt-get install -y libsqlite3-dev
make rebuild
```

**Error: `dependency 'libcurl' not found`**

```bash
sudo apt-get install -y libcurl4-openssl-dev
make rebuild
```

**Error: `rte_config.h: No such file or directory`**

DPDK headers are not found. Check:

```bash
ls /usr/local/include/rte_config.h
# If missing, DPDK was not installed. Re-run step 6.3.
```

**Error: `cannot find -lrte_*`**

DPDK libraries are not in the linker path:

```bash
echo '/usr/local/lib/x86_64-linux-gnu' | sudo tee /etc/ld.so.conf.d/dpdk.conf
sudo ldconfig
make rebuild
```

### 8.4 Other build variants

```bash
make debug          # Debug build (with -g, no optimization)
make single-org     # Single-tenant mode (~2x faster, no multi-tenant)
make sanitize       # Build with AddressSanitizer (finds memory bugs)
make rebuild        # Clean + rebuild from scratch
make clean          # Delete build directory
```

---

## 9. Step 8 - Configure Hugepages

DPDK uses hugepages for zero-copy packet buffers. Without hugepages, DPDK will not start.

### 9.1 Allocate 2MB hugepages (good for testing and development)

```bash
# Allocate 1024 hugepages of 2MB each (= 2GB total)
sudo sh -c 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'

# Create mount point
sudo mkdir -p /mnt/huge

# Mount the hugepage filesystem
sudo mount -t hugetlbfs nodev /mnt/huge
```

Or use the Makefile shortcut:

```bash
make setup-hugepages
```

### 9.2 Verify hugepages are allocated

```bash
cat /proc/meminfo | grep -i huge
```

**Expected output (should show non-zero Total and Free):**

```
HugePages_Total:    1024
HugePages_Free:     1024
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
```

**If HugePages_Total is 0:** Your system may not have enough free contiguous memory. Try:

```bash
# Free memory caches first
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
# Try again with fewer pages
sudo sh -c 'echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
```

### 9.3 Verify hugepages are mounted

```bash
mount | grep huge
# Expected: nodev on /mnt/huge type hugetlbfs (rw,relatime)
```

If you see nothing, mount them:

```bash
sudo mount -t hugetlbfs nodev /mnt/huge
```

---

## 10. Step 9 - Setup IOMMU and Bind NICs to DPDK

> **Skip this entire section if you only want to run the dashboard/API without DPDK.**
> DPDK NIC binding is only needed for the actual packet-processing data plane.

### 10.1 Enable IOMMU in BIOS and kernel

VFIO (the recommended DPDK driver) requires IOMMU.

**Check if IOMMU is already enabled:**

```bash
dmesg | grep -i iommu | head -5
```

If you see `DMAR: IOMMU enabled` or `AMD-Vi:`, IOMMU is active. If not:

**For Intel CPUs:** Edit GRUB to add `intel_iommu=on iommu=pt`:

```bash
sudo nano /etc/default/grub
# Find the line GRUB_CMDLINE_LINUX_DEFAULT="..."
# Change it to:
# GRUB_CMDLINE_LINUX_DEFAULT="quiet splash intel_iommu=on iommu=pt"

sudo update-grub
sudo reboot
```

**For AMD CPUs:** AMD IOMMU is usually enabled by default. If not:

```bash
sudo nano /etc/default/grub
# GRUB_CMDLINE_LINUX_DEFAULT="quiet splash amd_iommu=on iommu=pt"

sudo update-grub
sudo reboot
```

After reboot, verify:

```bash
dmesg | grep -i iommu | head -5
# Should show IOMMU enabled messages
```

### 10.2 Load the VFIO kernel module

```bash
sudo modprobe vfio-pci
```

Verify it loaded:

```bash
lsmod | grep vfio
# Expected: vfio_pci, vfio_iommu_type1, vfio
```

**If VFIO fails to load** (common in VMs or when IOMMU is not available), use UIO instead:

```bash
sudo modprobe uio_pci_generic
# Use uio_pci_generic instead of vfio-pci in the bind command below
```

### 10.3 Identify your NICs

```bash
# List all network interfaces and their PCI addresses
lspci | grep -i ethernet
```

**Example output:**

```
03:00.0 Ethernet controller: Intel Corporation 82599ES 10-Gigabit (rev 01)
03:00.1 Ethernet controller: Intel Corporation 82599ES 10-Gigabit (rev 01)
05:00.0 Ethernet controller: Intel Corporation I350 Gigabit (management)
```

In this example:
- `03:00.0` and `03:00.1` are the 10G NICs (use these for DPDK)
- `05:00.0` is the management NIC (do NOT touch this one)

**Find the full PCI address with domain:**

```bash
sudo dpdk-devbind.py --status
```

This shows which NICs are bound to kernel drivers and which are available for DPDK.

### 10.4 Bind NICs to DPDK

**WARNING: This will disconnect the NIC from Linux. Never bind your management/SSH NIC.**

```bash
# Step 1: Bring the interface down
sudo ip link set <interface_name> down
# Example: sudo ip link set enp3s0f0 down

# Step 2: Bind to DPDK (use the PCI address from step 10.3)
sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.0

# For a second port:
sudo ip link set <interface_name_2> down
sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.1
```

Or use the Makefile:

```bash
make bind-nic NIC=0000:03:00.0
```

**Verify the NICs are bound:**

```bash
sudo dpdk-devbind.py --status
```

Under "Network devices using DPDK-compatible driver" you should see your NICs.

### 10.5 To unbind NICs later (return to Linux)

```bash
sudo dpdk-devbind.py --unbind 0000:03:00.0
sudo dpdk-devbind.py --bind=ixgbe 0000:03:00.0   # rebind to kernel driver
sudo ip link set <interface_name> up
```

---

## 11. Step 10 - Setup Python Virtual Environment and Backend

### 11.1 Create a virtual environment

```bash
# From the project root directory
python3 -m venv venv
```

### 11.2 Activate it

```bash
source venv/bin/activate
```

Your prompt should change to show `(venv)` at the beginning.

> **You must run `source venv/bin/activate` every time you open a new terminal to work with the backend.**

### 11.3 Upgrade pip inside the venv

```bash
pip install --upgrade pip setuptools wheel
```

### 11.4 Install backend API dependencies

```bash
pip install -r backend/api/requirements.txt
```

**Expected:** Downloads and installs FastAPI, uvicorn, SQLAlchemy, PyJWT, bcrypt, etc.

**Common errors:**

- `error: Microsoft Visual C++ is required` -> You're on Linux, this shouldn't happen. If it does: `sudo apt-get install -y python3-dev`
- `Failed building wheel for bcrypt` -> `sudo apt-get install -y libffi-dev python3-dev`
- `error: pg_config not found` -> Ignore, we use SQLite not PostgreSQL

### 11.5 Configure the backend environment

```bash
cp backend/.env.example backend/.env
```

For local development/testing, the defaults work fine. For production, edit `backend/.env`:

```bash
nano backend/.env
```

Key settings to change for production:

```bash
# CHANGE these for production:
ANTIDDOS_ADMIN_USER=admin
ANTIDDOS_ADMIN_PASS=your_strong_password_here

# These paths must exist (we create them in Step 13):
ANTIDDOS_RULES_FILE=data/rules.json
ANTIDDOS_SOCKET_PATH=/var/run/antiddos/control.sock
ANTIDDOS_LAYER1_CONFIG=layer1/config/layer1_config.json
ANTIDDOS_LAYER2_CONFIG=layer2/config/layer2_config.json
ANTIDDOS_GEOIP_DB=/var/lib/antiddos/geoip/GeoLite2-Country.mmdb
```

---

## 12. Step 11 - Layer 3 anomaly detection (in-process)

Higher-layer anomaly scoring is served **in-process by the backend API** (the
`/api/v2/layer3` router, started together with the backend in Step 14) — there is no
separate ML engine to install or run, and no `python3 -m layer3.main` process. No extra
dependencies beyond the backend requirements (Step 10) are needed.

---

## 13. Step 12 - Install Dashboard

```bash
cd dashboard
npm install
cd ..
```

**Expected:** Downloads ~200MB of node_modules.

**Common errors:**

- `npm ERR! code EACCES` -> Don't run npm install with sudo. Fix permissions: `sudo chown -R $(whoami) ~/.npm`
- `npm ERR! engine` -> Your Node.js is too old. Go back to Step 4.
- `npm ERR! network` -> Check internet connection.

**Verify:**

```bash
ls dashboard/node_modules/.package-lock.json
# Should exist
```

---

## 14. Step 13 - Create Required Directories and Config Files

```bash
# Create runtime directories
sudo mkdir -p /var/run/antiddos
sudo chown $(whoami):$(whoami) /var/run/antiddos

sudo mkdir -p /var/lib/antiddos/geoip
sudo chown -R $(whoami):$(whoami) /var/lib/antiddos

sudo mkdir -p /etc/antiddos
sudo chown $(whoami):$(whoami) /etc/antiddos

# Create local data directories
mkdir -p backend/data
mkdir -p data

# Initialize data files (if they don't exist)
[ ! -f data/rules.json ] && echo '{"whitelist": {}, "blacklist": {}, "protected": {}}' > data/rules.json
[ ! -f data/baselines.json ] && echo '{}' > data/baselines.json

# Copy config files to system paths (optional, for production)
# cp layer1/config/layer1_config.json /etc/antiddos/layer1_config.json
# cp layer2/config/layer2_config.json /etc/antiddos/layer2_config.json
```

---

## 15. Step 14 - Run the System

### Option A: Full system (DPDK + Backend + Dashboard)

You need **4 terminals** (or use `tmux`/`screen`).

**Terminal 1 - DPDK data plane (requires root, hugepages, and bound NICs):**

```bash
cd ~/antiddos
sudo ./build/l2fwd -l 0-3 -n 4 -- -p 0x3 -P --no-mac-updating
```

Command breakdown:
- `-l 0-3` = use CPU cores 0,1,2,3
- `-n 4` = 4 memory channels
- `-p 0x3` = port mask 0x3 = binary 11 = use ports 0 and 1
- `-P` = promiscuous mode (receive all packets)
- `--no-mac-updating` = don't rewrite MAC addresses

Or use Makefile shortcuts:

```bash
make run          # 4 cores, 2 ports
make run-single   # 1 core (for testing)
make run-all      # 8 cores
```

**Terminal 2 - Backend API:**

```bash
cd ~/antiddos
source venv/bin/activate
cd backend
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Wait until you see: `Uvicorn running on http://0.0.0.0:8000`

(Layer 3 anomaly scoring runs inside this backend process — no separate terminal, see Step 11.)

**Terminal 3 - Dashboard:**

```bash
cd ~/antiddos/dashboard
npm run dev
```

Wait until you see: `Local: http://localhost:5173/`

### Option B: Quick start script (Backend + Dashboard only)

```bash
cd ~/antiddos
./start.sh
```

This starts the backend and dashboard but NOT the DPDK data plane.

### Services and ports

| Service            | URL / Port                    | Description               |
|--------------------|-------------------------------|---------------------------|
| Dashboard          | http://localhost:5173          | React management UI       |
| Backend API        | http://localhost:8000          | FastAPI REST API          |
| API Documentation  | http://localhost:8000/docs     | Swagger UI (interactive)  |
| API Documentation  | http://localhost:8000/redoc    | ReDoc (readable)          |
| Prometheus metrics | http://localhost:9100/metrics  | DPDK metrics (when running)|
| WebSocket          | ws://localhost:8000/api/v2/ws/ | Real-time updates         |

### Default credentials

- **Username:** `admin`
- **Password:** `REMOVED_DEV_DEFAULT`

---

## 16. Step 15 - Verify Everything Works

### Check 1: Backend is running

```bash
curl -s http://localhost:8000/docs | head -5
# Should return HTML (the Swagger UI page)
```

### Check 2: API health endpoint

```bash
curl -s http://localhost:8000/api/v2/system/health
# Should return JSON with system status
```

### Check 3: Login works

```bash
curl -s -X POST http://localhost:8000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "REMOVED_DEV_DEFAULT"}'
# Should return a JSON response with an access_token
```

### Check 4: Dashboard loads

Open http://localhost:5173 in your browser. You should see the login page.
Log in with `admin` / `REMOVED_DEV_DEFAULT`.

### Check 5: DPDK is processing (only if running)

```bash
curl -s http://localhost:8000/api/v2/tenants/default/stats
# Should return traffic statistics
```

---

## 17. Running Without DPDK (Dashboard Only)

If you don't have DPDK-compatible NICs (e.g., on a VM, laptop, or remote management server),
you can still run the dashboard and API:

```bash
# Terminal 1
cd ~/antiddos
source venv/bin/activate
cd backend
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2
cd ~/antiddos/dashboard
npm run dev
```

Or just:

```bash
./start.sh
```

The backend detects that DPDK is not running and operates in degraded mode.
You can still:
- Configure rules, IP lists, rate limits
- Manage tenants
- View and edit all layer configurations
- The live traffic graphs will show no data until DPDK starts

---

## 18. Running Tests

### C unit tests

```bash
make build-tests
make test
```

### Run a specific C test

```bash
# Packet parser test (no hugepages required with --no-huge)
sudo ./build/tests/unit/test_packet_parser --no-huge
```

### Python integration tests

```bash
source venv/bin/activate
pytest tests/integration/test_end_to_end.py -v
pytest tests/integration/test_api_comprehensive.py -v
```

### Benchmarks (requires hugepages)

```bash
make benchmark
```

---

## 19. Optional: Redis Cache

Redis improves API performance but is **not required**. The backend falls back to an in-memory cache.

```bash
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Verify
redis-cli ping
# Expected: PONG
```

---

## 20. Optional: GeoIP Database

For geo-blocking to work, you need a MaxMind GeoLite2 database.

1. Create a free account at https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-Country.mmdb
3. Place it:

```bash
sudo mkdir -p /var/lib/antiddos/geoip
sudo cp GeoLite2-Country.mmdb /var/lib/antiddos/geoip/
```

4. Enable in `layer1/config/layer1_config.json`:

```json
"geo_blocking": {
    "enabled": true,
    "database_path": "/var/lib/antiddos/geoip/GeoLite2-Country.mmdb"
}
```

---

## 21. Optional: Persistent Hugepages Across Reboots

By default, hugepages are lost after reboot. To make them persistent:

### Add to /etc/fstab

```bash
echo 'nodev /mnt/huge hugetlbfs defaults 0 0' | sudo tee -a /etc/fstab
```

### Add to /etc/sysctl.conf

```bash
echo 'vm.nr_hugepages = 1024' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Make VFIO module load at boot

```bash
echo 'vfio-pci' | sudo tee -a /etc/modules-load.d/dpdk.conf
```

---

## 22. Optional: Performance Tuning for Production

Run `make perf-tips` for a summary. Key recommendations:

### Isolate CPU cores for DPDK

Edit `/etc/default/grub`:

```bash
GRUB_CMDLINE_LINUX="isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7"
```

Then:

```bash
sudo update-grub
sudo reboot
```

### Use 1GB hugepages (better TLB performance)

```bash
make setup-hugepages-1g
```

Or in GRUB for boot-time allocation:

```bash
GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=4"
```

### Set CPU to performance mode

```bash
sudo apt-get install -y cpufrequtils
sudo cpupower frequency-set -g performance
```

### Disable IRQ balancing on DPDK cores

```bash
sudo systemctl stop irqbalance
# Or configure it to avoid DPDK cores
```

---

## 23. Troubleshooting A-Z

### Build: "dependency 'libdpdk' not found"

DPDK pkg-config files are not in the search path.

```bash
# Check if DPDK is installed:
pkg-config --modversion libdpdk

# If it prints nothing, set the path:
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH

# Make permanent:
echo 'export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH' >> ~/.bashrc
source ~/.bashrc

# Rebuild:
make rebuild
```

### Build: "sqlite3 not found"

```bash
sudo apt-get install -y libsqlite3-dev
make rebuild
```

### Build: "libcurl not found"

```bash
sudo apt-get install -y libcurl4-openssl-dev
make rebuild
```

### Build: "libnl-3/libnl-route-3 not found" (during DPDK build)

```bash
sudo apt-get install -y libnl-3-dev libnl-route-3-dev
```

### DPDK: "EAL: No free 2048 kB hugepages reported"

Hugepages are not allocated.

```bash
# Allocate them:
sudo sh -c 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'

# If that doesn't work, free memory first:
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
sudo sh -c 'echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'

# Verify:
cat /proc/meminfo | grep HugePages_Total
```

### DPDK: "EAL: No available hugepages reported in hugepages-2048kB"

Hugepages are allocated but not mounted.

```bash
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Verify:
mount | grep huge
```

### DPDK: "EAL: Cannot init VFIO" or "EAL: Detected 0 ports"

NICs are not bound to DPDK driver.

```bash
# Check NIC status:
sudo dpdk-devbind.py --status

# Load VFIO:
sudo modprobe vfio-pci

# If VFIO doesn't work (VMs, no IOMMU), use UIO:
sudo modprobe uio_pci_generic
sudo dpdk-devbind.py --bind=uio_pci_generic <PCI_ADDRESS>
```

### DPDK: "Permission denied"

DPDK requires root for hugepages and NIC access.

```bash
sudo ./build/l2fwd -l 0-3 -n 4 -- -p 0x3 -P --no-mac-updating
# OR
make run   # (Makefile already uses sudo)
```

### Backend: "ModuleNotFoundError: No module named 'fastapi'"

Virtual environment is not activated.

```bash
source venv/bin/activate
pip install -r backend/api/requirements.txt
```

### Backend: "Address already in use (port 8000)"

Another process is using port 8000.

```bash
# Find what's using it:
sudo lsof -i :8000

# Kill it:
sudo kill <PID>

# Or use a different port:
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8001
```

### Dashboard: "npm ERR! code ENOENT"

You're not in the dashboard directory.

```bash
cd ~/antiddos/dashboard
npm install
```

### Dashboard: "vite: command not found"

node_modules is missing.

```bash
cd ~/antiddos/dashboard
rm -rf node_modules package-lock.json
npm install
```

### Dashboard: Can't connect to API

The backend must be running on port 8000 before the dashboard can fetch data.
Start the backend first, then the dashboard.

### Python: "externally-managed-environment" error (Ubuntu 24.04)

Ubuntu 24.04 blocks system-wide pip installs. Always use a venv:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/api/requirements.txt
```

### Reset everything to clean state

```bash
./reset_data.sh
```

This clears: database, rules, baselines, IP lists, tenant config, ML models.

---

## 24. Quick Reference

```bash
# ============ BUILD ============
make all                 # Production build (multi-tenant)
make single-org          # Single-tenant build (~2x faster)
make debug               # Debug build
make sanitize            # Build with AddressSanitizer
make rebuild             # Clean + rebuild
make clean               # Delete build directory

# ============ DPDK SETUP ============
make check-dpdk          # Verify DPDK installation
make setup-hugepages     # Allocate 2MB hugepages
make setup-hugepages-1g  # Allocate 1GB hugepages (production)
make nic-status          # Show NIC bindings
make bind-nic NIC=0000:XX:XX.X    # Bind NIC to DPDK
make unbind-nic NIC=0000:XX:XX.X  # Return NIC to Linux

# ============ RUN ============
make run                 # Start DPDK (4 cores, 2 ports)
make run-single          # Start DPDK (1 core, testing)
make run-all             # Start DPDK (8 cores)
./start.sh               # Start backend + dashboard (no DPDK)

# ============ BACKEND ============
source venv/bin/activate
cd backend && python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# ============ DASHBOARD ============
cd dashboard && npm run dev          # Development
cd dashboard && npm run build        # Production build

# ============ TESTS ============
make build-tests         # Build with tests
make test                # Run unit tests
make benchmark           # Run benchmarks
pytest tests/integration/test_end_to_end.py -v   # Integration tests

# ============ UTILITIES ============
./reset_data.sh          # Reset all data to clean state
make perf-tips           # Performance tuning tips
make help                # Show all Makefile targets
```

---

## 25. Architecture Overview

```
                    Browser
                       |
              :5173 Dashboard (React/Vite)
                       |
              :8000 Backend API (FastAPI/Python)
                       |
                 Unix Domain Socket
                       |
    ┌──────────────────┴───────────────────┐
    |        DPDK Data Plane (C)           |
    |                                      |
    |  Layer 1: Deterministic Filtering    |
    |    IP lists, SYN proxy, rate limits  |
    |    geo-blocking, signatures          |
    |              |                       |
    |  Layer 2: Anomaly Detection          |
    |    EWMA baselines, z-score           |
    |              |                       |
    |  Layer 3: ML Detection (Python)      |
    |    XGBoost, Isolation Forest         |
    |              |                       |
    |  Layer 4: IP Reputation              |
    |    Scoring, challenges, bot detect   |
    |              |                       |
    |  Layer 5: Threat Intelligence        |
    |    Threat feeds, cross-tenant learn  |
    └──────────────────────────────────────┘
              |              |
         Client NIC     Server NIC
         (port 0)       (port 1)
```

**Data flow:** Packets arrive on port 0, pass through all layers, clean traffic exits on port 1.
Malicious packets are dropped at the earliest possible layer for maximum performance.
