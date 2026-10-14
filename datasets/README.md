# Evaluation Datasets

Download pointers for the four public corpora used in the evaluation. **No dataset files are
committed to this repository** — they are large and redistribution-restricted. This directory
holds only this README; download the corpora from the official sources below.

The scripts that read the corpora are in `ComparisonResults/extraction/` (see its README). They
write per-day and per-IP caches into `ComparisonResults/cache/` and the derived per-window feature
tree into `datasets/extracted/`, which is not deposited either; the tree's per-file checksums are in
`ComparisonResults/extraction/tree_manifest/<corpus>/SHA256SUMS`, and each corpus directory there
has a README with that corpus's caveats. The deposited result records are verified by
`ComparisonResults/SHA256SUMS.results` (run `sha256sum -c ../SHA256SUMS.results` from inside
`ComparisonResults/results/`). Raw-input checksums for the corpora are not shipped.

---

## Corpora used in the evaluation

| Corpus | Format | Candidate scenarios in the derived tree | Official source |
|---|---|---|---|
| CIC-IDS-2017 | Raw pcaps → per-(destination IP, 1 s) windows; labels by 5-tuple join against CIC's labelled-flow CSVs | 7, on 2 victims | [unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) |
| CSE-CIC-IDS2018 | Per-host pcaps; labels from the published attack schedule | 8, on 2 victims | [unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html) |
| CIC-DDoS2019 | Raw pcaps of the 03-11 day; labels by 5-tuple join against the per-attack CSVs | 12, on the 2 labelled hosts | [unb.ca/cic/datasets/ddos-2019.html](https://www.unb.ca/cic/datasets/ddos-2019.html) |
| LITNET-2020 | NetFlow records with per-flow attack labels | 4, one per concentrated attack | [dataset.litnet.lt](https://dataset.litnet.lt) |

That is 31 candidates; 16 are admitted as usable scenarios
(`ComparisonResults/results/panel_inventory/PANEL.json`).

---

> **Directory layout matters.** Where a script reads a fixed path, the **Expected layout** block
> for that corpus shows it, with the reading `file:line` cited; where the path is a command-line
> argument, the block says so. Paths are relative to the `datasets/` root, resolved as
> `$ANTIDDOS_BASE/datasets`, where `ANTIDDOS_BASE` defaults to the repository root
> (`ComparisonResults/config.py:98`; the scripts in `ComparisonResults/extraction/` resolve it the
> same way). Set that environment variable to relocate the whole tree.

## CIC-IDS-2017 (`datasets/CIC-IDS-2017/`)

- **Source:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Reference:** Sharafaldin, Habibi Lashkari and Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP 2018, pp. 108–116, doi:10.5220/0006639801080116
- **Used as:** raw pcaps aggregated to per-(destination IP, 1 s) windows. The CSVs are read only for 5-tuple attack labels and for the role screening and audit of the benign pools: their timestamps have minute resolution, too coarse for 1-second windows (`run_cicids2017_pcap.py` docstring).
- **Expected layout** (paths set in `ComparisonResults/extraction/run_cicids2017_pcap.py:43-49`, `export_benign_pools.py:88-95` and `run_cicids2017_pool_audit.py:51-61`):

  ```
  datasets/CIC-IDS-2017/
  ├── PCAPs/
  │   ├── Monday-WorkingHours.pcap
  │   └── Friday-WorkingHours.pcap
  └── CSVs/
      ├── TimestampedFlows/
      │   ├── Monday-WorkingHours.pcap_ISCX.csv
      │   └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
      └── TrafficLabelling /          # trailing space is CIC's own; the eight weekly labelled-flow CSVs
          ├── Wednesday-workingHours.pcap_ISCX.csv
          ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
          ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
          ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
          └── ...
  ```

  Filenames are matched exactly (not globbed). The Wednesday slices also need the Wednesday capture,
  which no deposited script parses, and the deposited `run_cicids2017_pcap.py` labels Friday from the
  DDoS CSV alone; `ComparisonResults/extraction/tree_manifest/CIC-IDS-2017/README.md` describes
  both gaps.

## CSE-CIC-IDS2018 (per-day pcap directories, passed as an argument)

- **Source:** https://www.unb.ca/cic/datasets/ids-2018.html (hosted on AWS S3)
- **Reference:** Canadian Institute for Cybersecurity and Communications Security Establishment, "A Realistic Cyber Defense Dataset (CSE-CIC-IDS2018)," Registry of Open Data on AWS, https://registry.opendata.aws/cse-cic-ids2018/
- **Used as:** per-host pcaps of the four DoS/DDoS days. The released CSVs for Wednesday, Thursday and Friday lack the IP columns a 5-tuple join needs (Tuesday 20-02's retains them), so windows on all four days are labelled by the published attack schedule on the day's documented victim (`pcap_feature_extractor_cicids2018.py` docstring); Tuesday's `Dst IP` column serves to confirm that day's victim.
- **Expected layout:** no fixed path. Run
  `ComparisonResults/extraction/pcap_feature_extractor_cicids2018.py <pcap_dir> <day_tag> <output_json>`
  once per day, with `<day_tag>` one of `wed`, `thu`, `fri`; `<pcap_dir>` holds that day's per-host
  captures, matched by the globs `cap*` and `UCAP*` (`pcap_feature_extractor_cicids2018.py:329-330`).
  The deposited extractor has no Tuesday (20-02) entry; Tuesday's capture ships as a RAR5 archive,
  and `ComparisonResults/extraction/tree_manifest/CIC-IDS2018/README.md` describes how it was
  recovered.

## CIC-DDoS2019 (labels `datasets/CICDDoS2019/03-11/`; pcaps passed as an argument)

- **Source:** https://www.unb.ca/cic/datasets/ddos-2019.html
- **Reference:** Sharafaldin, Habibi Lashkari, Hakak and Ghorbani, "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy," ICCST 2019, doi:10.1109/CCST.2019.8888419
- **Used as:** raw pcaps of the 03-11 day with 5-tuple labels from the seven per-attack CSVs. One of the two labelled hosts is the attack source; its six slices are kept apart as a negative control.
- **Expected layout** — the label CSVs are read from a fixed path by `stamp_cicddos_roles.py:29` and `export_benign_pools.py:98`, and passed as `<csv_dir>` to `pcap_feature_extractor.py <pcap_dir> <csv_dir> <output_json>` (filenames at `pcap_feature_extractor.py:36-44`); the pcaps can live anywhere and are passed as `<pcap_dir>` (glob at `pcap_feature_extractor.py:464`):

  ```
  datasets/CICDDoS2019/03-11/        # CSV label dir; these exact filenames are read
  ├── Syn.csv
  ├── UDP.csv
  ├── Portmap.csv
  ├── NetBIOS.csv
  ├── LDAP.csv
  ├── UDPLag.csv
  └── MSSQL.csv
  <pcap_dir>/                        # glob:  SAT-03-11-2018_*   (extensionless split captures)
  ├── SAT-03-11-2018_0
  ├── SAT-03-11-2018_01
  └── ...
  ```

  The slices were split from a day cache carrying per-window attack types, which the deposited
  `pcap_feature_extractor.py` does not write;
  `ComparisonResults/extraction/tree_manifest/CICDDoS2019/README.md` describes the gap.

## LITNET-2020 (`datasets/LITNET-2020/`)

- **Source:** https://dataset.litnet.lt (freely downloadable)
- **Reference:** Damaševičius et al., "LITNET-2020: An Annotated Real-World Network Flow Dataset for Network Intrusion Detection," *Electronics* 9(5):800, 2020, doi:10.3390/electronics9050800
- **Used as:** NetFlow records with labelled attack families. The per-window caches carry 13 features; the TCP-flag features of the packet-capture corpora do not exist in a flow export. Four single-host scenarios, a role-screened benign pool, and `/24` and `/16` subnet records (`ComparisonResults/results/litnet_l1subnet_*_results.json`, produced from the truncated `parts/` export; see `ComparisonResults/README.md`).
- **Expected layout** (`ComparisonResults/extraction/rebuild_litnet_caches.py:45,54`; `export_benign_pools.py:102`):

  ```
  datasets/LITNET-2020/
  └── allFlows.csv      # the complete export, 26,943,158,910 bytes
  ```

  `rebuild_litnet_caches.py` warns if the file is not that size and refuses to run if
  `allFlows_part_*.csv` files sit in the same directory, because the loader would read those
  instead. The two subnet runners (`ComparisonResults/runners/run_litnet_l1subnet.py` and
  `ablate_no_unique_dst_runner.py`, lines 44-47) read `LITNET_DIR`, which defaults to
  `datasets/LITNET-2020/parts/`; the loader globs `allFlows_part_*.csv` there and falls back to an
  `allFlows.csv` in the same directory (`ComparisonResults/litnet_loader.py:356-360`). Set
  `LITNET_DIR=$ANTIDDOS_BASE/datasets/LITNET-2020` to read the complete file. A `parts/` split
  must be cut from the complete file: an earlier extraction was 11.5% short and lost two attack
  types entirely (`rebuild_litnet_caches.py` docstring). The scenario and pool exporters read the
  per-IP cache only from `ComparisonResults/cache/litnet_per_ip_cache.json`, which
  `rebuild_litnet_caches.py` writes; build it from the complete file. The deposit no longer
  tracks the symbolic links that stood under `ComparisonResults/cache/`; on the authors' machine
  they pointed at caches built from an incomplete export, with no `udp_f` windows, and the two
  subnet records were scored on those.

---

## Not part of the evaluation

CTU-13 was evaluated during development and retracted: its bot-host pcaps are too small to warm
the Tier-1 baseline. No deposited evaluation code or record (under `ComparisonResults/`) uses
it, and none uses MAWILab, CAIDA or threat-intelligence feeds.
