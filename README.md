# AntiDDoS Shield

A multi-layer DDoS detection and mitigation system. Combines a DPDK-accelerated
Layer-1 datapath, a 1-Hz Layer-2 statistical anomaly detector in C, a FastAPI
backend, and a React/Vite operator dashboard.

This repository accompanies the paper *Training-Free Streaming DDoS Detection:
Characterizing the Per-Window False-Alarm Floor in a Reproducible Six-Corpus
Study* (see [`paper/`](paper/)).

## Layout

| Folder | Contents |
|---|---|
| [`project/`](project/) | The production system — Layer 1 DPDK datapath, Layer 2 statistical detector, common headers, interlayer plumbing, FastAPI backend, React dashboard, C and Python tests, build files. Build with Meson + Ninja. |
| [`experiments/`](experiments/) | Paper-reproducibility code: per-IP and /24-subnet runners for the six evaluation datasets, iso-pipeline baselines, and committed result JSONs that every paper number reproduces from. |
| [`datasets/`](datasets/) | **Markdown only — no data.** Per-dataset download URLs, SHA-256 hashes, expected layout. |
| [`paper/`](paper/) | The paper itself (Markdown + DOCX + PDF + BibTeX references). |

## Quick start

1. **Build the C engine** — see [`INSTALL.md`](INSTALL.md):
   ```bash
   cd project
   meson setup build -Dbuild_tests=true
   ninja -C build
   ```
2. **Run the backend** — `cd project/backend && pip install -r api/requirements.txt && uvicorn api.main:app`.
3. **Run the dashboard** — `cd project/dashboard && npm install && npm run dev`.
4. **Reproduce paper headlines** — see [`experiments/README.md`](experiments/README.md) and [`datasets/README.md`](datasets/README.md).
5. **Run the fidelity unit tests**:
   ```bash
   python -m pytest project/tests/unit_python/
   ```

## License

The code is released under the MIT License (see [`LICENSE`](LICENSE)). Bundled
dataset-derived caches and results remain under their upstream corpus licenses
(CESNET, CIC-IDS-2017/2018, CIC-DDoS2019, CIC-IoT-2023, LITNET-2020); see each
dataset's terms.
