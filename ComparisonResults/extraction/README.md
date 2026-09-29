# extraction/ — the scripts that build the derived feature tree

The manuscript's runners read a derived per-window feature tree (`datasets/extracted/`, 88 files,
3.01 GB) that is **not** deposited. This directory carries the code that builds it from the
official corpus releases, the tree's own provenance files, and the per-file checksums a rebuild
must reproduce, so that a reader can regenerate the tree and verify it without the authors
shipping data.

## Provenance

Every script is a verbatim copy of the authors' development tree at commit `c8cc797`
(`PROVENANCE.tsv` gives each file's original path), with four mechanical changes made for the
deposit and nothing else:

1. a five-line preamble that puts `extraction/` and `ComparisonResults/` on `sys.path` and defines
   `_BASE` exactly as `config.BASE` does (`$ANTIDDOS_BASE`, else the directory above
   `ComparisonResults/`);
2. eleven developer-machine absolute paths replaced by `_BASE`-relative ones
   (`_os.path.join(_BASE, 'datasets', ...)`);
3. two helpers the scripts imported from modules the deposit does not carry in full
   (`within_split`, `load_perip`) moved verbatim into `tree_io.py`, and the three `import` lines
   that used them repointed;
4. `classify_scenarios.py` writes its canonical record to `config.RESULTS_DIR`
   (`ComparisonResults/results/scenario_classification.json`) instead of a `results/` directory
   beside the script, which the deposit layout does not have.

`tree_manifest/` holds, unchanged, the tree's `README.md`, `SCENARIO_INVENTORY.md`, the six
per-corpus `README.md`, the six `index.json` and the eleven `SHA256SUMS` (63 file checksums);
the only edit to them is that a developer machine's absolute path in one README is written
`/path/to/antiddos`.

## Inputs

Place the official releases under `$ANTIDDOS_BASE/datasets/` (or under `AntiDDOS_Shield/datasets/`
and leave `ANTIDDOS_BASE` unset):

| Corpus | Expected under `datasets/` | Consumed by |
|---|---|---|
| CIC-IDS-2017 | `CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap`, `Friday-WorkingHours.pcap`, `CIC-IDS-2017/CSVs/*.pcap_ISCX.csv` (CIC's corrected labelled-flow CSVs) | `run_cicids2017_pcap.py`, `export_benign_pools.py` |
| CSE-CIC-IDS2018 | per-day pcap directories (`UCAP172.31.69.25*.pcap` etc.), `CIC-IDS2018/CSV/` | `pcap_feature_extractor_cicids2018.py <pcap_dir> <wed|thu|fri> <out.json>` |
| CIC-DDoS2019 | `CICDDoS2019/03-11/` pcaps and the per-attack CSVs (`Syn.csv`, `UDP.csv`, `LDAP.csv`, `MSSQL.csv`, `NetBIOS.csv`, `UDPLag.csv`, `Portmap.csv`) | `pcap_feature_extractor.py <pcap_dir> <csv_dir> <out.json>`, `stamp_cicddos_roles.py` |
| CIC-IoT-2023 | `PCAP/<family>/*.pcap` and `PCAP/Benign_Final/*.pcap` | `cicios2023_extractor.py <pcap_dir> <label> <out.json>` |
| LITNET-2020 | `LITNET-2020/allFlows.csv` (the complete file; an 88.5 %-truncated export loses two attack types) | `rebuild_litnet_caches.py` |
| CESNET-TimeSeries24 | `cesnet/ip_addresses_sample.tar.gz`, `cesnet/times.tar.gz` (`config.TAR_PATH`, `config.TIMES_TAR`) | `export_cesnet_reference.py` (the tree's `benign_reference.json`); the CESNET runners in `runners/` read the export directly |

The extractors write per-day / per-family caches into `ComparisonResults/cache/`; the scenario
builders read those caches and write the tree.

## Recipe

In this order. `classify_scenarios.py --write` rewrites every payload to embed its verdict, so the
index and checksums are written **twice**: once before it (so it has an index to walk) and once
after it (so the checksums are of the final files).

```
# 1. caches from the raw captures (hours; dpkt reads the pcaps)
python3 run_cicids2017_pcap.py                                  # CIC-IDS-2017 Monday + Friday caches (the Monday cache is the cross-day training cache)
python3 pcap_feature_extractor_cicids2018.py <pcap_dir> <day> <cache.json>   # once per day
python3 pcap_feature_extractor.py <pcap_dir> <csv_dir> <cache.json>          # CIC-DDoS2019 03-11
python3 cicios2023_extractor.py <pcap_dir> <label> <cache.json>              # once per CIC-IoT family, and Benign_Final
python3 rebuild_litnet_caches.py                                # LITNET per-IP cache from allFlows.csv

# 2. scenarios
python3 split_by_attack_schedule.py all      # CIC-IDS-2017 + CSE-CIC-IDS2018 slices (180 s guard band; --guard)
python3 split_cicddos_by_type.py <typed_cache> 03-11
python3 stamp_cicddos_roles.py               # host roles measured from the 03-11 CSVs, stamped into the tree
python3 export_cicios2023_scenarios.py
python3 export_litnet_scenarios.py
python3 export_benign_pools.py               # benign_pools/ (the false-alarm denominator)   [--only CORPUS]

# 3. index, verdicts, checksums
python3 write_extracted_index.py datasets/extracted/<corpus>    # index.json            <- FIRST
python3 classify_scenarios.py datasets/extracted --write        # the four checks, verdict into each payload
python3 write_extracted_index.py datasets/extracted/<corpus>    # index.json + SHA256SUMS  <- LAST
python3 build_scenario_inventory.py                             # SCENARIO_INVENTORY.md
```

Verification of a rebuilt tree: `sha256sum -c SHA256SUMS` inside each corpus directory against the
copies in `tree_manifest/`; `python3 verify_extracted_tree.py datasets/extracted` (data against
itself) and `python3 verify_readme_claims.py --tree datasets/extracted` (prose against data).

## What was checked at deposit time

The raw corpora are not on the deposit machine, so steps 1–2 were not re-run. Against the tree the
manuscript was scored on, from this directory inside a copy of `ComparisonResults/`:

- all 20 modules compile and import;
- `build_scenario_inventory.py --out` reproduces `SCENARIO_INVENTORY.md` line for line (0 of 197
  lines differ);
- `write_extracted_index.py` on a copy of `LITNET-2020/` reproduces its `index.json` and
  `SHA256SUMS` exactly;
- `verify_extracted_tree.py`, `classify_scenarios.py` (without `--write`) and
  `verify_readme_claims.py` were run on the full tree; their logs are summarised in the commit
  message that added this directory.

## Which scripts back which statements of the article

- The guard-band leak measurement (Section 3.1): `split_by_attack_schedule.py` (`--guard`).
- The census statistics of Table 4 and the ledger inputs: `classify_scenarios.py`,
  `check_scenario_intensity.py`, `stamp_cicddos_roles.py`.
- The CIC-IDS-2017 benign-pool audit (Supplementary S16): `run_cicids2017_pool_audit.py`.
- The CIC-IoT-2023 session-matched control has no script here or elsewhere in the deposit; the
  article says so.
