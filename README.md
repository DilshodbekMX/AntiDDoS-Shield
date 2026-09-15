# AntiDDoS Shield

This repository holds three things with different status.

## 1. `ComparisonResults/`: evaluation deposit

[`ComparisonResults/`](ComparisonResults/) is the deposit for the manuscript *An Evaluation
Protocol for Training-Free DDoS Detection: Three Corrections*, prepared for the MDPI *Journal of
Cybersecurity and Privacy*. It holds the evaluation runners, the baseline registry and the 39 JSON
result records from which the manuscript's detector results and test statistics are read. See
[`ComparisonResults/README.md`](ComparisonResults/README.md).

Verify the records against their manifest from inside `results/`:

```bash
cd ComparisonResults/results
sha256sum -c ../SHA256SUMS.results    # 39 lines, each ending in OK
```

`ComparisonResults/SHA256SUMS` is an earlier manifest of code and records; several of its entries
no longer match, and it is not the manuscript's manifest. The deposit contains neither the six
corpora nor the derived per-window feature tree the runners read, so apart from
`runners/run_joint_filter.py` the runners do not execute as deposited.

## 2. `project/`: the AntiDDoS Shield system (context only)

[`project/`](project/) is the AntiDDoS Shield system: a DPDK packet datapath (Layer 1), a 1 Hz
statistical anomaly detector in C (Layer 2), a FastAPI backend and a React/Vite dashboard. It is a
research prototype, supplied as context for the manuscript's engine figures and not an evaluated
contribution of it. Its throughput and detection latency have not been measured, and it contains no
machine-learning model. Build instructions are in [`INSTALL.md`](INSTALL.md).

## 3. `datasets/README.md`: corpus download pointers

[`datasets/README.md`](datasets/README.md) lists where to obtain the six public corpora. No corpus
data is committed to this repository.

## Quick start

1. **Build the C engine** — see [`INSTALL.md`](INSTALL.md):
   ```bash
   cd project
   meson setup build -Dbuild_tests=true
   ninja -C build
   ```
2. **Run the backend** — `cd project/backend && pip install -r api/requirements.txt && uvicorn api.main:app`.
3. **Run the dashboard** — `cd project/dashboard && npm install && npm run dev`.
4. **Check the evaluation deposit** — see [`ComparisonResults/README.md`](ComparisonResults/README.md) and [`datasets/README.md`](datasets/README.md).
5. **Run the fidelity unit tests**:
   ```bash
   python -m pytest project/tests/unit_python/
   ```

## License

The code is released under the MIT License (see [`LICENSE`](LICENSE)). Bundled
dataset-derived caches and results remain under their upstream corpus licenses
(CESNET, CIC-IDS-2017/2018, CIC-DDoS2019, CIC-IoT-2023, LITNET-2020); see each
dataset's terms.
