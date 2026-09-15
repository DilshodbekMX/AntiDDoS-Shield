# project — AntiDDoS Shield research prototype

Source code of the AntiDDoS Shield research prototype, supplied as context for the manuscript and
not evaluated in it. Throughput and detection latency have not been measured. Build with Meson +
Ninja from this directory.

| Path | Contents |
|---|---|
| `layer1/` | DPDK datapath (`tables/ip_lists.{c,h}` — including L1 protected-subnet aggregation `ip_protected_subnet_add`; `tables/syn_proxy.{c,h}`; `tables/udp_gatekeeper.{c,h}`; `telemetry/per_ip_features.{c,h}`). |
| `layer2/` | 1 Hz statistical detector. `baselines.{c,h}` (39-feature `L2_FEAT_*` enum, three-tier EWMA, per-IP CUSUM+JSD state); `advanced_detection.c`; `adaptive_threshold.{c,h}`. |
| `common/` | Shared headers (`config_path.h`, `siphash.h`, `organization.h`). |
| `core/` | DPDK glue (`dpdk_core.{c,h}`, `control_socket.{c,h}`, `stats_socket.{c,h}`, `prometheus_exporter.{c,h}`). |
| `proto/`, `external/` | Protobuf schema; vendored cJSON. |
| `tests/` | `unit/` (C unit tests), `integration/` (cross-layer + carpet-bomb subnet), `benchmarks/`, **`unit_python/`** (7 Python test files: tier readiness, poison recovery, update regime, L1-subnet loader, adaptive timebase, innovation gate, tenant carpet-bomb toggle). `benchmarks/` holds benchmark programs; no throughput or latency result from them is reported. |
| `backend/` | FastAPI control API. See [`backend/README.md`](backend/README.md). |
| `dashboard/` | React + Vite UI. See [`dashboard/README.md`](dashboard/README.md). |
| `config/` | Single-org and multi-tenant orchestration configs (`single_org_config.json`, `tenants.json`). Per-layer JSON lives in `layer1/config/` and `layer2/config/`. |
| `meson.build`, `Makefile`, `main.c` | Top-level build entry. |

## Build

```bash
meson setup build -Dbuild_tests=true
ninja -C build
meson test -C build --print-errorlogs
```

## Python unit tests (no DPDK required)

```bash
python -m pytest tests/unit_python/
```

Covers invariants the C engine maintains and the evaluation harness mirrors.

## Configuration

Per-layer JSON lives in `layer1/config/` and `layer2/config/` (the `config/` directory
holds the single-org and multi-tenant orchestration files). `ANTIDDOS_CONFIG_DIR` overrides
the search path (resolver: `common/config_path.h::resolve_config_path()`).
The shared-memory ABI version is at
`layer1/interlayer/shared_memory.h::SHMEM_ABI_VERSION`.
