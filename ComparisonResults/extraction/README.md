# extraction/ — the scripts that build the derived feature tree

The manuscript's runners read a derived per-window feature tree (`datasets/extracted/`: the four
corpus directories plus the tree's `README.md` and `SCENARIO_INVENTORY.md`, 65 files, 1.90 GB). The
tree is **not** deposited. This directory holds the code that builds it from the official corpus
releases, the tree's own provenance files and the per-file checksums of the authors' copy of the
tree, so that a reader can regenerate the tree and compare it without the authors shipping data.
Parts of the tree have no writer here; see
[What the chain cannot rebuild](#what-the-chain-cannot-rebuild).

The directory holds 17 scripts and one helper module (`tree_io.py`). `SHA256SUMS` lists the
checksum of every other file here, those under `tree_manifest/` included; run
`sha256sum -c SHA256SUMS` from this directory.

## Provenance

Every script except `tree_io.py` and `drop_duplicate_columns.py` was copied from the authors' development tree at commit `c8cc797`. `PROVENANCE.tsv`
gives each script's original path. Its `source_state` column records whether the copy came from
that commit (`HEAD`) or from the checkout's working tree (`working-tree`). `tree_io.py` has no row:
it was written for the deposit, and its docstring names the two files its helpers came from.

`drop_duplicate_columns.py` has no row either. It was not copied from `c8cc797`: it was written and
run once, on 2026-10-13, when this deposit was prepared, and the deposited copy differs from the one
that ran only in its paths, its docstring and a `main()` wrapper. It removed `burst_factor` and `unique_flows` from the per-window rows of
the 34 tree files that carried them (1,739,996 rows); in every such row they equalled
`packets_per_sec` and `flows_per_sec`, and no deposited record scored them. It rewrites a file only
if each new row equals the old row minus those two keys, then updates the stored hashes: the tree's
`SHA256SUMS` and `index.json`, their copies under `tree_manifest/`, and `payload_sha256` in
`results/admissibility_inputs.json`. The deposited extractor no longer writes the two columns, so on
the authors' tree or a rebuilt one the script rewrites nothing and leaves a header-only `hash_map.tsv` beside itself.

The copies received four mechanical changes:

1. a five-line preamble that puts `extraction/` and `ComparisonResults/` on `sys.path` and defines
   `_BASE` exactly as `config.BASE` does (`$ANTIDDOS_BASE`, else the directory above
   `ComparisonResults/`);
2. developer-machine absolute paths replaced by `_BASE`-relative ones of the form
   `_os.path.join(_BASE, 'datasets', ...)` (the current scripts contain ten joins of that form);
3. two helpers the scripts imported from modules the deposit does not carry in full
   (`within_split`, `load_perip`) moved verbatim into `tree_io.py`, with the scripts that use
   them importing them from there;
4. when run on the default tree, `classify_scenarios.py` writes its canonical record to
   `config.RESULTS_DIR` (`ComparisonResults/results/scenario_classification.json`) instead of a
   `results/` directory beside the script, which the deposit layout does not have. Given any other
   tree path, it writes `scenario_classification.json` into that tree. It writes this record with
   or without `--write`; the record is not among the deposited results.

Ten scripts were edited further after they were copied, so they no longer match their originals.
Besides docstrings and comments, the edits change:

- `pcap_feature_extractor.py`: its output columns. `feature_count` is now counted from the emitted
  rows instead of being written as a constant;
- `classify_scenarios.py`: it reads only the four corpus directories that `corpus_names.in_scope()`
  (in `ComparisonResults/`) accepts, stops with an error on a split mode other than `within` or
  `crossday`, and no longer writes a `role_unverified` field (see
  [What the chain cannot rebuild](#what-the-chain-cannot-rebuild));
- `build_scenario_inventory.py`: its corpus table and caveats. The LITNET-2020 `syn_flood` caveat
  now gives the complete export's census as figures typed into the script; no deposited record or
  script holds that census. The caveat's ratio and candidate counts are computed from the
  `index.json` files;
- `export_benign_pools.py` and `verify_readme_claims.py`: their lookup tables.

`check_scenario_intensity.py`, `export_litnet_scenarios.py`, `split_by_attack_schedule.py`,
`verify_extracted_tree.py` and `write_extracted_index.py` changed only in docstrings or comments.

`tree_manifest/` holds the four per-corpus `index.json` files and the eight `SHA256SUMS` files,
byte-identical to those in the authors' copy of the tree. It also holds the tree's `README.md` and
`SCENARIO_INVENTORY.md` and the four per-corpus `README.md` files, as revised for this deposit.
`build_scenario_inventory.py` writes the inventory; no
script writes the five `README.md` files. The `SHA256SUMS` files hold 47 checksums: 31 scenario
payloads, plus 16 benign-pool files (eight pools, each with its `.meta.json`).

## Inputs

Place the official releases under `$ANTIDDOS_BASE/datasets/`. You can also place them under
`datasets/` at the repository root and leave `ANTIDDOS_BASE` unset.

| Corpus | Expected under `datasets/` | Consumed by |
|---|---|---|
| CIC-IDS-2017 | `CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap` and `Friday-WorkingHours.pcap`; `CIC-IDS-2017/CSVs/TimestampedFlows/` (the Monday and Friday-afternoon `*.pcap_ISCX.csv`); `CIC-IDS-2017/CSVs/TrafficLabelling /` (the labelled-flow CSVs with IP columns; the trailing space is part of CIC's directory name) | `run_cicids2017_pcap.py` (pcaps, `TimestampedFlows/`); `export_benign_pools.py` and `run_cicids2017_pool_audit.py` (`TrafficLabelling /`) |
| CSE-CIC-IDS2018 | per-day directories of host captures (`UCAP*` and `cap*` files, e.g. `UCAP172.31.69.25-part1.pcap`), passed as `<pcap_dir>` | `pcap_feature_extractor_cicids2018.py <pcap_dir> <wed\|thu\|fri> <out.json>` |
| CIC-DDoS2019 | the `SAT-03-11-2018_*` pcaps, passed as `<pcap_dir>`; the per-attack CSVs in `CICDDoS2019/03-11/` (`Syn.csv`, `UDP.csv`, `LDAP.csv`, `MSSQL.csv`, `NetBIOS.csv`, `UDPLag.csv`, `Portmap.csv`) | `pcap_feature_extractor.py <pcap_dir> <csv_dir> <out.json>`, `stamp_cicddos_roles.py`, `export_benign_pools.py` |
| LITNET-2020 | `LITNET-2020/allFlows.csv` (the complete file; an export 11.5% short of it loses two attack types, `udp_f` and `smtp_b`) | `rebuild_litnet_caches.py`, `export_benign_pools.py` |

The extractors write their caches into `ComparisonResults/cache/`. The two that take an output
path must be given one there. The builders look for the CSE-CIC-IDS2018 caches as
`cicids2018_pcap_<day>.json` and for the CIC-DDoS2019 cache as `cicddos_03-11_typed.json`, but
`pcap_feature_extractor.py` does not write the `_attack_type` field the typed cache needs; see
[What the chain cannot rebuild](#what-the-chain-cannot-rebuild). The scenario builders read those
caches and write the tree.

## Recipe

Run the steps in this order from `ComparisonResults/extraction/`. Every builder writes into the
tree by default, which is `datasets/extracted/` under `$ANTIDDOS_BASE` or, if that is unset, under
the repository root. `<tree>` below stands for that directory.
`classify_scenarios.py --write` rewrites every payload to embed its verdict, so the index and
checksums are written **twice**: once before it (so it has an index to walk) and once after it
(so the checksums are of the final files).

```
# 1. caches from the raw captures (hours; dpkt reads the pcaps)
python3 run_cicids2017_pcap.py                                  # CIC-IDS-2017 Monday + Friday caches (the Monday cache is the cross-day training cache)
python3 pcap_feature_extractor_cicids2018.py <pcap_dir> <day> ../cache/cicids2018_pcap_<day>.json   # day = wed, thu, fri
python3 pcap_feature_extractor.py <pcap_dir> <csv_dir> <cache.json>          # CIC-DDoS2019 03-11 (output lacks _attack_type; see below)
python3 rebuild_litnet_caches.py                                # LITNET per-IP cache from allFlows.csv

# 2. scenarios
python3 split_by_attack_schedule.py all      # CIC-IDS-2017 + CSE-CIC-IDS2018 slices (180 s guard band; --guard)
python3 split_cicddos_by_type.py <typed_cache> 03-11   # needs the typed cache; see below
python3 stamp_cicddos_roles.py               # host roles measured from the 03-11 CSVs, stamped into the tree
python3 export_litnet_scenarios.py
python3 export_benign_pools.py               # benign_pools/ (the false-alarm denominator)   [--only CORPUS]

# 3. index, verdicts, checksums
python3 write_extracted_index.py <tree>/<corpus>    # index.json            <- FIRST
python3 classify_scenarios.py --write               # the four checks, verdict into each payload
python3 write_extracted_index.py <tree>/<corpus>    # index.json + SHA256SUMS  <- LAST
python3 build_scenario_inventory.py                 # SCENARIO_INVENTORY.md
```

`rebuild_litnet_caches.py` writes `ComparisonResults/cache/litnet_per_ip_cache.json`, which
`export_litnet_scenarios.py` and `export_benign_pools.py` read. Build it from the complete
LITNET-2020 export: the deposit no longer tracks the symbolic link that stood at that path, and on
the authors' machine that link pointed at a cache built from an incomplete export.

Verifying a rebuilt tree:

- run `sha256sum -c` inside `<tree>/<corpus>/` against `tree_manifest/<corpus>/SHA256SUMS` (the
  scenario checksums will not match; see
  [What the chain cannot rebuild](#what-the-chain-cannot-rebuild));
- run it again inside `<tree>/<corpus>/benign_pools/` against
  `tree_manifest/<corpus>/benign_pools/SHA256SUMS`. For the seven pools outside LITNET-2020,
  neither the payload nor the `.meta.json` checksum will match: their deposited metadata lacks
  fields that `export_benign_pools.py` always writes (`role_check_performed` in all seven; on
  CSE-CIC-IDS2018 and CIC-DDoS2019 also `role_check`, `n_hosts_excluded_as_attack_endpoint` and
  `hosts_excluded_as_attack_endpoint`), so compare their host and window counts instead;
- `python3 verify_extracted_tree.py` checks the data against itself;
- copy `tree_manifest/README.md` into `<tree>/` and each `tree_manifest/<corpus>/README.md` into
  `<tree>/<corpus>/`, because `verify_readme_claims.py` reads them there;
- `python3 verify_readme_claims.py` checks the prose against the data. It reads the record that
  `classify_scenarios.py` writes (item 4 under Provenance) and exits 1 if that record is missing,
  so run `classify_scenarios.py` first; `--write` is not needed.

## What the chain cannot rebuild

Four per-day caches that the scenario builders read, as the tree used them, have no writer in this
directory (each `index.json` entry names its cache in `derived_from`):

- `cicids2017_pcap_wednesday.json` is read by `split_by_attack_schedule.py` and
  `export_benign_pools.py`. `run_cicids2017_pcap.py` builds only the Monday and Friday caches.
- `cicids2017_pcap_friday.json` as used carries labels from three of CIC's Friday flow CSVs.
  `run_cicids2017_pcap.py` builds a Friday cache labelled from the afternoon DDoS CSV alone, which
  could not produce the 426 attack windows of `Fri-07-07_PortScan`.
- `cicids2018_pcap_tue.json` is read by `split_by_attack_schedule.py` for the two `Tue-20-02`
  slices. `pcap_feature_extractor_cicids2018.py` accepts only `wed`, `thu` and `fri`.
- `cicddos_03-11_typed.json` is read by `split_cicddos_by_type.py` and `export_benign_pools.py`.
  The splitter groups attack windows by a per-window `_attack_type` field, which
  `pcap_feature_extractor.py` does not write.

Even with that cache, `split_cicddos_by_type.py` writes slices only for the documented victim
`192.168.50.4`. No script here writes the six `attacker_side/` slices of `172.16.0.5`:
`stamp_cicddos_roles.py` only updates the slices that already exist.

As a result, these scripts alone cannot rebuild from the official releases:

- the five CIC-IDS-2017 `Wed-05-07` slices and the Wednesday benign pool;
- the two CIC-IDS-2017 `Fri-07-07` slices, as labelled;
- the two CSE-CIC-IDS2018 `Tue-20-02` slices;
- the twelve CIC-DDoS2019 slices and their pool.

That is 21 of the 31 scenario files, among them 10 of the 16 USABLE scenarios.

Nor can a rebuild reproduce the 31 scenario checksums. Every scenario payload in the authors' tree,
and every entry of the four `index.json` files in `tree_manifest/`, carries a `role_unverified`
field (false in all 31) that no script here writes. `classify_scenarios.py --write` and
`write_extracted_index.py` keep the field where it is present but never add it. With the field
stripped from the four LITNET-2020 payloads and their index, re-running those two steps leaves all
four payloads failing `sha256sum -c`. Compare a rebuilt scenario file with its `index.json` entry
(verdict, window counts, intensity statistics), not by checksum.

## What was checked

Steps 1–2 were not re-run for this deposit. The checks below ran against the four corpus
directories of the local feature tree, which all 47 `tree_manifest/` checksums verify. The scripts
ran from a copy of `ComparisonResults/` with `ANTIDDOS_BASE` unset, under Python 3.12 with numpy
2.4.2, scipy 1.17.0 and dpkt 1.9.8:

- all 18 modules compile and import (`tree_io.py` with `ComparisonResults/` on the path, which the
  other scripts' preamble provides);
- `verify_extracted_tree.py`: 31 scenario files and 16 pool files checked, 0 problems;
- `classify_scenarios.py` at its default alpha of 0.01, without `--write`, returns 31 verdicts,
  each identical to `results/admissibility_ledger.json`: USABLE 16, ATTACKER-SIDE 6,
  FLOOR-LIMITED 4, NOT-DDOS 2, NO-FPR 2, INSEPARABLE 1. `--alpha` may come before or after the
  tree path;
- `write_extracted_index.py` on a copy of `LITNET-2020/` rewrites the four payloads to the same
  bytes and reproduces its `index.json` and `SHA256SUMS` exactly;
- on copies of the other three corpus directories, `write_extracted_index.py` rewrites every payload
  to the same bytes and reproduces each `index.json` and `SHA256SUMS` exactly;
- `build_scenario_inventory.py --out` writes a 154-line inventory (16 usable of 31 scenarios, 5
  distinct victims), identical to `tree_manifest/SCENARIO_INVENTORY.md`;
- on a copy of the tree with the `tree_manifest/` READMEs copied in, `verify_readme_claims.py --tree`
  exits 0: the four corpus headers, the 11-row CSE-CIC-IDS2018 gap table and the tree README's 31
  scenarios and 16 usable all agree with the artifacts.

## Which scripts back which statements of the article

- The guard-band leak measurement (Section 3.1 and Appendix A.1): `split_by_attack_schedule.py`
  (`--guard`). For the CIC-IDS-2017 Wednesday and CSE-CIC-IDS2018 Tuesday captures it needs caches
  that no script here writes; it reports a missing cache as `ABSENT` and skips that day.
- The census statistics of Table 1 and the inputs of the per-candidate ledger (Table A2,
  Appendix C): `classify_scenarios.py`, `check_scenario_intensity.py`, `stamp_cicddos_roles.py`.
- The CIC-IDS-2017 benign-pool audit (Appendix B): `run_cicids2017_pool_audit.py`. The script
  drives `run_cicids2017_pcap.py` end to end, and its parity step reads
  `results/cicids2017_pcap_results.json`. Neither that file nor the record the audit writes
  (`results/cicids2017_pool_characterization.json`) is deposited.
