# Evaluation Datasets

Download pointers for the six public corpora used in the AntiDDoS Shield Layer-2
evaluation (paper §5.1, Table 6). **No dataset files are committed to this repository** —
they are large and redistribution-restricted. This directory holds only this README and a
`.gitkeep`; download the corpora from the official sources below into the matching
subfolders, then run the harness (`experiment/run_all.sh`).

Integrity: raw-input checksums are regenerated locally after download
(`experiment/make_sha_manifest.sh`) and are **not shipped**, since these corpora are third-party
downloads subject to occasional re-releases and cannot be third-party-verified from our copy (§7.3).
The committed result-artifact and feature-cache manifests are in `experiment/SHA256SUMS.{results,caches}`.

---

## Corpora used in the paper

| Corpus | Format (paper Table 6) | Role in §6 | Official source |
|---|---|---|---|
| CESNET-TimeSeries24 | Hourly per-IP flow aggregates (benign ISP telemetry) | False-positive headline + supplementary analysis (§6.4, §6.6) | [zenodo.org/records/13382427](https://zenodo.org/records/13382427) |
| LITNET-2020 | Real-world NetFlow v9 (Lithuanian academic network) | Carpet-bomb vs concentrated attacks; subnet-aggregation centerpiece (§6.2–§6.3) | [dataset.litnet.lt](https://dataset.litnet.lt) |
| CIC-IDS-2017 | Raw pcaps → per-(dst IP, 1 s) windows | Cross-day false-positive stress test (§6.4) | [unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) |
| CIC-IDS-2018 | Per-host pcaps | Slow-attack ensemble value (§6.5) | [unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html) |
| CIC-DDoS2019 | Raw pcaps, 5-tuple labels | Concentrated victim flood (§6.1) | [unb.ca/cic/datasets/ddos-2019.html](https://www.unb.ca/cic/datasets/ddos-2019.html) |
| CIC-IoT-2023 | Monothematic pcaps (13 volumetric families) | Subnet-aggregation centerpiece (§6.2–§6.3) | [unb.ca/cic/datasets/iotdataset-2023.html](https://www.unb.ca/cic/datasets/iotdataset-2023.html) |

---

> **Directory layout matters.** Each loader reads a *hardcoded* directory tree and
> filename pattern; if the data is not laid out exactly as shown below the raw pipeline
> will not find it. The **Expected layout** block for each corpus is the ground truth the
> loader/extractor source imposes, with the reading `file:line` cited. Paths are relative
> to the `datasets/` root. Unless noted otherwise the `datasets/` root is resolved as
> `$ANTIDDOS_BASE/datasets`, where `ANTIDDOS_BASE` defaults to the repository root
> (`experiment/config.py:98`); set that environment variable to relocate the whole tree.

## CESNET-TimeSeries24 (`datasets/cesnet/`)

- **Source:** https://zenodo.org/records/13382427 — **DOI:** 10.5281/zenodo.13382427
- **Reference:** Koumar et al., "CESNET-TimeSeries24: Time series dataset for network traffic anomaly detection and forecasting," *Scientific Data* 12:338, 2025, doi:10.1038/s41597-025-04603-x
- **Used as:** real benign backbone telemetry (174 IPs, hourly per-IP aggregates) for the false-positive headline; synthesized perturbations are sensitivity tests only.
- **Note:** the full per-IP series is ~38 GB; the `ip_addresses_sample.tar.gz` (163 MB) is a representative subset. Only the benign telemetry is required to reproduce the §6.4/§6.6 numbers.
- **Expected layout** (paths set in `experiment/config.py:103-104`; tar members read in `experiment/data_loader.py:25,104,166`):

  ```
  datasets/cesnet/
  ├── ip_addresses_sample.tar.gz   # per-IP aggregate archive; members matching  *agg_1_hour*.csv  are read
  └── times.tar.gz                 # timestamp-index archive; members matching  *1_hour*.csv  are read
  ```

  The two `.tar.gz` files are opened in place (`tarfile.open(..., 'r:gz')`) — do **not** unpack them. Override the base directory with `ANTIDDOS_BASE`.

## LITNET-2020 (`datasets/LITNET-2020/parts/`)

- **Source:** https://dataset.litnet.lt (freely downloadable)
- **Reference:** Damasevicius et al., "LITNET-2020: An Annotated Real-World Network Flow Dataset for Network Intrusion Detection," *Electronics* 9(5):800, 2020, doi:10.3390/electronics9050800
- **Used as:** NetFlow with labeled attack families (Smurf, HTTP flood, Code Red, Reaper, TCP SYN flood, …) — the carpet-bomb and protected-subnet-aggregation centerpiece. NetFlow lacks per-packet TCP-flag/TTL/fragment fields (10 of 40 candidate features active; §5.7).
- **Expected layout** (directory set in `experiment/run_litnet.py:40-42`; files globbed in `experiment/litnet_loader.py:121-125`):

  ```
  datasets/LITNET-2020/parts/
  ├── allFlows_part_00.csv
  ├── allFlows_part_01.csv
  └── ...                       # glob:  allFlows_part_*.csv  (sorted); a single  allFlows.csv  is used as fallback
  ```

  The 23 GB `allFlows.csv` export is pre-split into ~1.3 GB `allFlows_part_*.csv` chunks under `parts/`. Override this directory directly with the `LITNET_DIR` environment variable, or move the whole tree with `ANTIDDOS_BASE`.

## CIC-IDS-2017 (`datasets/CIC-IDS-2017/`)

- **Source:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Reference:** Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP 2018
- **Used as:** raw pcaps aggregated to per-(destination IP, 1 s) windows; cross-day (Monday benign baseline → Friday DDoS) generalization and the dominant false-positive case. Use the **pcaps**, not the CSVs for features (the CSV timestamps are unreliable; §5.1, §6.14) — the CSVs are read only for 5-tuple attack labels.
- **Expected layout** (paths set in `experiment/run_cicids2017_pcap.py:37-43`):

  ```
  datasets/CIC-IDS-2017/
  ├── PCAPs/
  │   ├── Monday-WorkingHours.pcap
  │   └── Friday-WorkingHours.pcap
  └── CSVs/TimestampedFlows/
      ├── Monday-WorkingHours.pcap_ISCX.csv
      └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  ```

  Filenames are matched exactly (not globbed). Override the base directory with `ANTIDDOS_BASE`.

## CIC-IDS-2018 (`datasets/CIC-IDS2018/pcap_dos/`)

- **Source:** https://www.unb.ca/cic/datasets/ids-2018.html (CSE-CIC-IDS2018; hosted on AWS S3)
- **Reference:** Sharafaldin et al., 2018 (as above)
- **Used as:** per-host pcaps; slow application-layer DoS (Thursday: GoldenEye + Slowloris) where the streaming ensemble leads offline batch detectors (§6.5).
- **Expected layout** (per-day pcaps globbed in `experiment/pcap_feature_extractor_cicids2018.py:323-324`):

  ```
  datasets/CIC-IDS2018/pcap_dos/
  ├── Wednesday-21-02-2018/     # per-host pcaps, glob:  cap*  and  UCAP*
  ├── Thursday-15-02-2018/      #   (each day directory holds the raw per-host captures)
  └── Friday-16-02-2018/
  ```

  Note the top-level directory is `CIC-IDS2018` (no second hyphen) and the pcaps live under `pcap_dos/`. Run the extractor `pcap_feature_extractor_cicids2018.py` with `<pcap_dir> <day_tag> <output_json>` positional args against the layout above. Override the base with `ANTIDDOS_BASE`.

## CIC-DDoS2019 (pcaps `datasets/pcap/03-11/` + labels `datasets/CICDDoS2019/03-11/`)

- **Source:** https://www.unb.ca/cic/datasets/ddos-2019.html
- **Reference:** Sharafaldin et al., "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy," IEEE ICCST 2019
- **Used as:** raw pcaps with 5-tuple labels; concentrated victim flood detected at 100% recall training-free (§6.1).
- **Expected layout** — the pcaps and the label CSVs live in **two separate top-level directories** (pcaps globbed in `experiment/pcap_feature_extractor.py:462`, CSVs mapped in `pcap_feature_extractor.py:30-37,339`):

  ```
  datasets/pcap/03-11/               # PCAP dir, glob:  SAT-03-11-2018_*   (extensionless split captures)
  ├── SAT-03-11-2018_0
  ├── SAT-03-11-2018_01
  └── ...
  datasets/CICDDoS2019/03-11/        # CSV label dir; these exact filenames are read
  ├── Syn.csv
  ├── UDP.csv
  ├── Portmap.csv
  ├── NetBIOS.csv
  ├── LDAP.csv
  ├── UDPLag.csv
  └── MSSQL.csv
  ```

  This split (pcaps under `datasets/pcap/`, labels under `datasets/CICDDoS2019/`) is what the extractor expects — a single combined `cicddos2019/` directory will **not** be found. `pcap_feature_extractor.py` also accepts `<pcap_dir> <csv_dir> <output_json>` positional args directly. Override the base with `ANTIDDOS_BASE`.

## CIC-IoT-2023 (`datasets/CIC_IOT_Dataset2023/PCAP/`)

- **Source:** https://www.unb.ca/cic/datasets/iotdataset-2023.html
- **Reference:** Neto et al., "CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment," *Sensors* 23(13):5941, 2023, doi:10.3390/s23135941
- **Used as:** monothematic pcaps for 13 volumetric attack families; per-IP and /24 protected-subnet aggregation (§6.2–§6.3). `heavy_hitter_count` and full CMS concentration features are not populated by the offline extractor (35 of 39 features active; §5.7).
- **Expected layout** (per-family pcaps globbed in `experiment/cicios2023_extractor.py:67`; each family's label is its directory name):

  ```
  datasets/CIC_IOT_Dataset2023/PCAP/
  ├── Benign_Final/                  # benign class; glob:  *.pcap
  ├── DDoS-ACK_Fragmentation/        # each family directory holds  *.pcap  captures
  ├── DDoS-HTTP_Flood/
  ├── DDoS-ICMP_Flood/
  ├── DDoS-ICMP_Fragmentation/
  ├── DDoS-PSHACK_Flood/
  ├── DDoS-RSTFINFlood/
  ├── DDoS-SlowLoris/
  ├── DDoS-SYN_Flood/
  ├── DDoS-SynonymousIP_Flood/
  ├── DDoS-TCP_Flood/
  ├── DDoS-UDP_Flood/
  ├── DDoS-UDP_Fragmentation/
  └── Mirai-udpplain/
  ```

  Note the top-level directory is `CIC_IOT_Dataset2023` (underscores) with a `PCAP/` subdirectory; the label of each family is its directory name. Run the single-family extractor `cicios2023_extractor.py` with `<pcap_dir> <label> <output_json>` positional args per family.

---

## Not part of the evaluation

Earlier drafts explored CTU-13, MAWILab, CAIDA, and threat-intelligence feeds; none are
part of the published six-corpus evaluation. CTU-13 was retracted (its bot-host pcaps are
structurally too small to warm the Tier-1 baseline); its legacy artifacts are retained
in the project's development history only, are not part of the release package, and are not
cited (§7.3).
