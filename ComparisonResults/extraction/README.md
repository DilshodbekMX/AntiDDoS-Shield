# extraction/: the scripts that build the derived feature tree

The manuscript's runners read a derived per-window feature tree (`datasets/extracted/`: the four
corpus directories plus the tree's `README.md` and `SCENARIO_INVENTORY.md`, 65 files, 2.06 GB). The
tree is **not** deposited. This directory holds the code that builds all of it from the official
corpus releases, the tree's own provenance files and the per-file checksums of the tree the authors
built with this code for this revision, so that a reader can regenerate the tree and compare it
without the authors shipping data. In this revision the extractors compute the two engine features
the earlier tree lacked, `burst_factor` and `unique_flows`, so packet-capture rows carry all 39
feature names the shipped engine scores and LITNET-2020 rows the 13 of them that the LITNET-2020
loader computes from the flow records (see [The 39-name tree](#the-39-name-tree)); on every other
column the tree equals the earlier one by value.

The directory holds 20 scripts and one helper module (`tree_io.py`). `SHA256SUMS` lists the
checksum of every other file here, those under `tree_manifest/` included; run
`sha256sum -c SHA256SUMS` from this directory.

## Provenance

Seventeen scripts were copied from the authors' development tree at commit `c8cc797`.
`PROVENANCE.tsv` has one row per module, and a last row for `../litnet_loader.py`, the harness
module that `rebuild_litnet_caches.py` calls, which came with the harness in the deposit's first
commit (`3f63dba`) and not from that copy. Its columns give the copy's original path; whether it came
from that commit (`HEAD`), from the checkout's working tree (`working-tree`), was written for the
deposit (`deposit`), or came with the harness (`harness`, that last row); the development commit
that last changed the original (`source_commit`); and what the deposit's revisions changed
(`changed_in_this_revision`; changes of the 39-name revision are marked as such).

Four modules were written for the deposit:

- `tree_io.py` holds two helpers (`within_split`, `load_perip`) moved verbatim from modules the
  deposit does not carry in full; its docstring names the two files they came from.
- `drop_duplicate_columns.py` was written and run once, on 2026-10-13, when the 37-name deposit
  was prepared. It removed `burst_factor` and `unique_flows` from the per-window rows of the 34
  tree files that carried them (1,739,996 rows); in every such row they equalled `packets_per_sec`
  and `flows_per_sec`, placeholder copies an older offline extractor wrote, and no deposited record
  scored them. It rewrites a file only if each new row equals the old row minus those two keys, then
  updates the stored hashes: the tree's `SHA256SUMS` and `index.json`, their copies under
  `tree_manifest/`, and `payload_sha256` in `results/admissibility_inputs.json`. For the 39-name
  revision it was made safe for a tree that carries the computed columns: it now rewrites a file only
  if both columns copy their twins in every row, and keeps any other file. The deposited copy
  therefore differs from the one that ran in its paths, its docstring, a `main()` wrapper and that
  copy test. On a tree built by the current extractors no file holds the copies, so it rewrites
  nothing and leaves a header-only `hash_map.tsv` beside itself; on the 39-name tree it kept all 39
  payloads.
- `stamp_cicddos_slice_metadata.py` writes the CIC-DDoS2019 payload keys that were first typed into
  the tree by hand (development commits `573e7e3`, `56d484a` and `a8ed451`): the four intensity
  keys, `floor_limited` and `usable_as_ddos_scenario` on all twelve slices, the floor-limit
  `unusable_reason` on the MSSQL and NetBIOS victim slices, and `role`, `ground_truth_source` and a
  provisional `unusable_reason` on the six `attacker_side/` slices. Later steps rewrite most of these
  values in place (`write_extracted_index.py`, `classify_scenarios.py --write`,
  `stamp_cicddos_roles.py`), as they did in the authors' tree.
- `write_admissibility_inputs.py`, added in the 39-name revision, writes
  `results/admissibility_inputs.json`, the input of
  `runners/run_admissibility_ledger.py`, from the four `index.json` files: one entry per candidate,
  each field copied from its index entry and `payload_sha256` from the entry's `sha256`. Before, that
  record had no writer and its hashes were edited by hand; run on the 37-name tree the writer
  reproduces the earlier file byte for byte. `--check FILE` compares instead of writing.

The copies received four mechanical changes:

1. a five-line preamble that puts `extraction/` and `ComparisonResults/` on `sys.path` and defines
   `_BASE` exactly as `config.BASE` does (`$ANTIDDOS_BASE`, else the directory above
   `ComparisonResults/`);
2. developer-machine absolute paths replaced by `_BASE`-relative ones of the form
   `_os.path.join(_BASE, 'datasets', ...)` (the copied scripts contain ten joins of that form);
   `reparse_friday_2017.py` instead loses a line that set `ANTIDDOS_BASE` to the authors' checkout;
3. two helpers the scripts imported from modules the deposit does not carry in full
   (`within_split`, `load_perip`) moved verbatim into `tree_io.py`, with the scripts that use
   them importing them from there;
4. when run on the default tree, `classify_scenarios.py` writes its canonical record to
   `config.RESULTS_DIR` (`ComparisonResults/results/scenario_classification.json`) instead of a
   `results/` directory beside the script, which the deposit layout does not have. Given any other
   tree path, it writes `scenario_classification.json` into that tree's root, which then holds 66
   files instead of the 65 counted above; delete the file before counting or sizing the tree. It
   writes this record with or without `--write`; the record is not among the deposited results. The
   recipe below runs it without a path.

Besides docstrings and comments, eleven copies differ further from their originals:

- `pcap_feature_extractor.py`: it computes `burst_factor` and `unique_flows` the engine's way
  (below) where the original wrote copies of `packets_per_sec` and `flows_per_sec` under those
  names, and it counts `feature_count` from the emitted rows instead of writing a constant;
- `pcap_feature_extractor_cicids2018.py`: the same counted `feature_count`, a usage message that
  names `tue`, and the per-window set of engine flow keys, capped at 50,000 like its other sets,
  that `unique_flows` counts (it inherits the counting from `pcap_feature_extractor.py`);
- `run_cicids2017_pcap.py`: a Wednesday entry and a `--day {monday,friday,wednesday}` option, with
  `main(argv)` behaving as before when another script calls it without arguments (both written for
  the deposit; see below);
- `reparse_friday_2017.py`: its body runs under a `__main__` guard, so importing it parses nothing;
- `split_cicddos_by_type.py`: an `--attacker-side` option and the `CSV_ATTACKERS` list (written for
  the deposit; see below);
- `classify_scenarios.py`: it reads only the four corpus directories that
  `corpus_names.in_scope()` (in `ComparisonResults/`) accepts, stops with an error on a split mode
  other than `within` or `crossday`, accepts `--alpha` before or after the tree path, and decides
  `role_unverified` from a list of corpus directories (below);
- `build_scenario_inventory.py`: its corpus table and caveats. The LITNET-2020 caveat gives the
  column counts (15 against the packet corpora's 40) and the complete export's `syn_flood` census as
  figures typed into the script; no deposited record or script holds that census. The caveat's
  ratio and candidate counts are computed from the `index.json` files;
- `verify_extracted_tree.py`: a `columns` check on every scenario and pool row of the four corpora:
  both new columns present, `burst_factor` a whole number from 0 to 3030, `unique_src_ips` ≤
  `unique_flows` ≤ `flows_per_sec`, and no file whose two columns copy their twins in every row;
- `export_litnet_scenarios.py`: when no benign window precedes the attack (`n_calib` is 0), the
  `fpr_note` it writes says so, where the original always said that the attack runs to the end of
  the capture;
- `export_benign_pools.py` and `verify_readme_claims.py`: their lookup tables.

`check_scenario_intensity.py`, `split_by_attack_schedule.py` and `write_extracted_index.py`
changed only in docstrings or comments. `litnet_loader.py`, which `rebuild_litnet_caches.py` calls,
lives in `ComparisonResults/` with the harness; for the 39-name revision its per-destination and
subnet builders gained the two columns (`PROVENANCE.tsv`, last row).

### What the 9d51bdc revision added

Before commit `9d51bdc` this directory could not write four of the per-day caches the tree is built
from, nor the six CIC-DDoS2019 attacker-side slices or one payload field. That revision, still on 37
feature names, ports the development code that wrote them and adds what never had a script:

| script | added | source |
|---|---|---|
| `run_cicids2017_pcap.py` | Friday labels from all three of CIC's Friday flow CSVs, not the afternoon DDoS CSV alone | development `experiments_copy/` copy at `fea05f5`; the earlier revision copied the `experiments/` one, which lacks this change |
| `run_cicids2017_pcap.py` | the Wednesday entry and the `--day` option, which parses one day into its cache and stops | new |
| `reparse_friday_2017.py` | the driver that re-parsed Friday with the three CSVs (`--day friday` runs the same parse) | `fea05f5` |
| `pcap_feature_extractor.py` | per-window attack types, `_attack_type` (the dominant label) and `_attack_types` (the distribution), which `split_cicddos_by_type.py` selects on | `9edaf03`, with the `0bef662` fix that the CSE-CIC-IDS2018 extractor depends on |
| `pcap_feature_extractor_cicids2018.py` | the `tue` day (Tuesday 20-02, victim `172.31.69.25`) | `0bef662` |
| `split_cicddos_by_type.py` | `--attacker-side`: the same slicing code run on the documented attack source `172.16.0.5`, written into `attacker_side/` | new; the development version at `2420cba` wrote these slices because it chose hosts by attack-window count, a rule `a8ed451` removed and this option does not restore |
| `stamp_cicddos_slice_metadata.py` | the hand-typed CIC-DDoS2019 keys (above) | new |
| `classify_scenarios.py` | the `role_unverified` field and the `ROLE-UNVERIFIED` verdict | `d2785b0`, with one change (below) |

The development classifier decided whether its inbound-flag direction heuristic can be trusted by
testing for one corpus name, a corpus outside the four here. The deposited classifier passes the
corpus directory to `analyse()` and tests it against `FLAG_HEURISTIC_INVALID`, a set that is empty
here, so `role_unverified` is false on all 31 scenarios, as it is in the authors' tree.

The Wednesday entry is not the authors' original writer. The cache the tree's Wednesday files were
first built from (2026-05-22) was written by a `parse_day` call that was never committed, with the
extractor as it stood before `dst_port_density` gained its factor of 1000; no copy of that code
survives. Run on the same capture and label file, the new entry reproduces that cache on every row
and key except two: `dst_port_density` equals 1000 times the old value, within one rounding step,
on all 502,770 rows (largest relative deviation 2.2e-16), and each row carries `_attack_type` (null)
and `_attack_types` (an empty mapping). The authors therefore regenerated the tree's six Wednesday
files with the chain; see
[The regenerated CIC-IDS-2017 Wednesday files](#the-regenerated-cic-ids-2017-wednesday-files).

`tree_manifest/` holds the four per-corpus `index.json` files and the eight `SHA256SUMS` files,
byte-identical to those of the 39-name tree the authors built with these scripts for this revision.
It also holds the tree's `README.md` and `SCENARIO_INVENTORY.md` and the four per-corpus `README.md`
files, as revised for this deposit. `build_scenario_inventory.py` writes the inventory; no script
writes the five `README.md` files. The `SHA256SUMS` files hold 47 checksums: 31 scenario payloads,
plus 16 benign-pool files (eight pools, each with its `.meta.json`).

## Inputs

Place the official releases under `$ANTIDDOS_BASE/datasets/`. You can also place them under
`datasets/` at the repository root and leave `ANTIDDOS_BASE` unset.

| Corpus | Expected under `datasets/` | Read by |
|---|---|---|
| CIC-IDS-2017 | `CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap`, `Wednesday-workingHours.pcap` and `Friday-WorkingHours.pcap`; `CIC-IDS-2017/CSVs/TimestampedFlows/Monday-WorkingHours.pcap_ISCX.csv` (CIC ships no `TimestampedFlows/`: copy the Monday CSV there from `TrafficLabelling /`, sha256 `96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820`, or pass `--csv`); `CIC-IDS-2017/CSVs/TrafficLabelling /` (the eight labelled-flow CSVs with IP columns; the trailing space is part of CIC's directory name) | `run_cicids2017_pcap.py` and `reparse_friday_2017.py` (the pcaps, the Monday CSV, and the Wednesday and three Friday CSVs under `TrafficLabelling /`); `export_benign_pools.py` (the same four `TrafficLabelling /` CSVs); `run_cicids2017_pool_audit.py` (all eight) |
| CSE-CIC-IDS2018 | per-day directories of host captures (`UCAP*` and `cap*` files, e.g. `UCAP172.31.69.25-part1.pcap`), passed as `<pcap_dir>`: the fully unpacked `pcap.zip` of Wednesday 21-02, Thursday 15-02 and Friday 16-02 (447, 450 and 444 captures; the extractor draws its 100 uninvolved hosts from those present with a fixed seed, so a partial unpack changes the cache and the pool), and for Tuesday 20-02 the `pcap/` directory unpacked from `pcap.rar` (below) | `pcap_feature_extractor_cicids2018.py <pcap_dir> <tue\|wed\|thu\|fri> <out.json>` |
| CIC-DDoS2019 | the `SAT-03-11-2018_*` pcaps, passed as `<pcap_dir>`; the per-attack CSVs in `CICDDoS2019/03-11/` (`Syn.csv`, `UDP.csv`, `LDAP.csv`, `MSSQL.csv`, `NetBIOS.csv`, `UDPLag.csv`, `Portmap.csv`) | `pcap_feature_extractor.py <pcap_dir> <csv_dir> <out.json>`, `stamp_cicddos_roles.py`, `export_benign_pools.py` |
| LITNET-2020 | `LITNET-2020/allFlows.csv` (the complete file, 26,943,158,910 bytes; an export 11.5% short of it loses two attack types, `udp_f` and `smtp_b`) | `rebuild_litnet_caches.py`, `export_benign_pools.py` |

**CSE-CIC-IDS2018 Tuesday ships as `pcap.rar` (RAR 5.0).** Every other day is a `pcap.zip`. Unpack it
with a RAR5 reader; `bsdtar` (libarchive) reads RAR5 and installs without root, as
`tree_manifest/CIC-IDS2018/README.md` shows. The authors' cache read two host captures, and those
two are all a rebuild needs:

```
bsdtar -xvf pcap.rar pcap/UCAP172.31.69.25 pcap/capEC2AMAZ-O4EL3NG-172.31.69.28   # 8.49 GB + 100 MB
```

Pass the resulting `pcap/` directory as `<pcap_dir>`. The CRC32 of both files on the authors' disk
equals the CRC that `pcap.rar` stores for them. The extractor keeps only windows whose destination
is the capture's own host, so the victim's rows, and with them both Tuesday slices, do not depend
on the other members; unpacking the whole archive (61.6 GB) adds uninvolved hosts to the cache.
There is no Tuesday benign pool.

The extractors write their caches into `ComparisonResults/cache/`. Those that take an output path
must be given one there; `reparse_friday_2017.py` always writes there (use
`run_cicids2017_pcap.py --day friday --out FILE` for another path). The scenario builders look for
`cicids2017_pcap_<day>.json`, `cicids2018_pcap_<day>.json`, `cicddos_03-11_typed.json` and
`litnet_per_ip_cache.json` there and write the tree.

Resources, as measured on the authors' machine for the 39-name rebuild: the CIC-DDoS2019 extraction
peaks at 17.4 GB (16.2 GiB) of memory and takes 14 to 16 minutes; the LITNET-2020 cache peaks at
16.5 GB (15.4 GiB; 8 minutes; 12.7 GB before the two columns were added); each CIC-IDS-2017 day takes
3 to 4 minutes (Friday just under 3) at up to 3.8 GB (3.5 GiB); the four CSE-CIC-IDS2018 days take 4
to 26 minutes each at under 1 GB (Wednesday, the longest, ran beside the LITNET-2020 cache build and
the three CIC-IDS-2017 extractions; it took 23 minutes in the earlier rebuild). Run the two large
extractions one after the other.
The scripts need Python 3.12 with dpkt, numpy and scipy (`ComparisonResults/requirements.txt`).

## Recipe

Run the steps in this order from `ComparisonResults/extraction/`. Every builder writes into the
tree by default, which is `datasets/extracted/` under `$ANTIDDOS_BASE` or, if that is unset, under
the repository root. `<tree>` below stands for that directory.
`classify_scenarios.py --write` rewrites every payload to embed its verdict, so the index and
checksums are written **twice**: once before it (so it has an index to walk) and once after it
(so the checksums are of the final files).

```
# 1. caches from the raw captures and flow files
python3 run_cicids2017_pcap.py --day monday       # CIC-IDS-2017 Monday (the cross-day training day; read here only for the Monday pool)
python3 run_cicids2017_pcap.py --day wednesday    # CIC-IDS-2017 Wednesday
python3 reparse_friday_2017.py                    # CIC-IDS-2017 Friday, labelled from its three CSVs
python3 pcap_feature_extractor_cicids2018.py <pcap_dir> <day> ../cache/cicids2018_pcap_<day>.json   # day = tue, wed, thu, fri
python3 pcap_feature_extractor.py <pcap_dir> <csv_dir> ../cache/cicddos_03-11_typed.json            # CIC-DDoS2019 03-11
python3 rebuild_litnet_caches.py                  # LITNET-2020 per-IP cache from allFlows.csv

# 2. scenarios and benign pools
python3 split_by_attack_schedule.py all           # CIC-IDS-2017 + CSE-CIC-IDS2018 slices (180 s guard band; --guard)
python3 split_cicddos_by_type.py cicddos_03-11_typed.json 03-11                   # the victim's six slices
python3 split_cicddos_by_type.py cicddos_03-11_typed.json 03-11 --attacker-side   # 172.16.0.5, into attacker_side/
python3 stamp_cicddos_slice_metadata.py           # the CIC-DDoS2019 keys first typed by hand
python3 stamp_cicddos_roles.py                    # host roles measured from the 03-11 CSVs
python3 export_litnet_scenarios.py
python3 export_benign_pools.py                    # benign_pools/ (the false-alarm denominator)   [--only CORPUS]

# 3. index, verdicts, checksums
python3 write_extracted_index.py <tree>/<corpus> ...   # index.json            <- FIRST
python3 classify_scenarios.py --write                  # the four checks, verdict into each payload
python3 write_extracted_index.py <tree>/<corpus> ...   # index.json + SHA256SUMS  <- LAST
python3 build_scenario_inventory.py                    # SCENARIO_INVENTORY.md

# 4. the admissibility ledger's input record, from the index files
python3 write_admissibility_inputs.py                  # ../results/admissibility_inputs.json
```

`write_extracted_index.py` takes one or more corpus directories; pass all four. Both
`split_cicddos_by_type.py` runs find the typed cache in `ComparisonResults/cache/` by its file name.
`rebuild_litnet_caches.py` must run on the complete LITNET-2020 export: the deposit no longer tracks
the symbolic link that stood at its output path, and on the authors' machine that link pointed at a
cache built from an incomplete export.

## Comparing a rebuilt tree

`tree_manifest/` lists the checksums of the tree that one run of this recipe wrote from the raw
releases for this revision. Every file of that tree was written by these scripts, so a rebuild from
the same releases should match it byte for byte: running steps 2 and 3 again on that run's caches,
into an empty tree, reproduced all 65 files byte for byte. The whole recipe was not run a second
time from the raw releases. To compare:

- run `sha256sum -c` inside `<tree>/<corpus>/` against `tree_manifest/<corpus>/SHA256SUMS`, and
  again inside `<tree>/<corpus>/benign_pools/` against `tree_manifest/<corpus>/benign_pools/SHA256SUMS`;
  all 47 lines pass on the tree they list;
- if a line fails, compare the file by value: each scenario file with its `index.json` entry and
  with the listed payload, on every `index.json` field except `bytes` and `sha256`, every metadata
  key, the same hosts with the same number of rows each, and row *i* equal to row *i* on every key;
  each pool by its host set and order, its per-host window counts and the `n_windows`,
  `n_hosts_kept`, `n_hosts_truncated` and excluded-host fields of its `.meta.json`. The deposit ships
  no script for this comparison;
- `python3 verify_extracted_tree.py` checks the data against itself, the two new columns included;
- copy `tree_manifest/README.md` into `<tree>/` and each `tree_manifest/<corpus>/README.md` into
  `<tree>/<corpus>/`, because `verify_readme_claims.py` reads them there;
- `python3 verify_readme_claims.py` checks the prose against the data. It reads the record that
  `classify_scenarios.py` writes (item 4 under Provenance) and exits 1 if that record is missing,
  so run `classify_scenarios.py` first; `--write` is not needed. For a tree passed as `--tree DIR`
  it reads the record from `DIR`, so run `classify_scenarios.py DIR`, which writes it there (item 4;
  remove it again before counting the tree's files);
- `python3 build_scenario_inventory.py --out FILE` should give a file identical to
  `tree_manifest/SCENARIO_INVENTORY.md`.

The 37-name tree of commit `895e581`, the authors' earlier copy, was partly written by hand, and a
rebuild matched only 9 of its 47 checksums. Against it the 39-name tree differs, besides the two new
columns, in the three ways that rebuild did, none of which touches a value:

1. *metadata key order*: in the authors' files it records the order in which several writers,
   some of them run by hand, first added each key, and no single run of the chain repeats it;
2. *per-window keys the authors' older files lack*: the current extractors write `_attack_type`
   and `_attack_types` into every cache row, so the CSE-CIC-IDS2018 Wed/Thu/Fri slices carry
   `_attack_types` (an empty mapping), the CIC-IDS-2017 Monday pool and the three CSE-CIC-IDS2018
   pools carry both keys, and in the 2018 slices `_attack_type` sits at a different position in each
   row;
3. *pool metadata*: the authors' Monday and Friday CIC-IDS-2017 pool metadata carry an older
   wording of `role_check` and lack `role_check_performed`, and the three CSE-CIC-IDS2018 pools
   and the CIC-DDoS2019 pool lack `role_check`, `role_check_performed`,
   `n_hosts_excluded_as_attack_endpoint` and `hosts_excluded_as_attack_endpoint`, all of which
   `export_benign_pools.py` writes.

Cache checksums are no test: cache metadata records the absolute input paths and, for the
CSE-CIC-IDS2018 and CIC-DDoS2019 caches, the run time. The LITNET-2020 cache records neither, and
before this revision a rebuilt one was byte-identical to the authors'; the 39-name cache also
carries the two new columns.

## The 39-name tree

`recompute/PREREGISTRATION_39_FEATURES.md` asks for every feature name the shipped engine scores
(`l2_feature_names`, `project/layer2/baselines.c`, 39 names). The packet-capture extractors of the
37-name revision wrote 37 of them and the LITNET-2020 loader 11; an older packet-capture extractor
had written the other two, `burst_factor` and `unique_flows`, as copies of `packets_per_sec` and
`flows_per_sec`, which `drop_duplicate_columns.py` removed. For this revision the extractors
compute both the engine's way, as the pre-registration defines them and `tree_manifest/README.md`
describes:

- `pcap_feature_extractor.py` (the shared window aggregator, used for CIC-DDoS2019, by
  `run_cicids2017_pcap.py` and `reparse_friday_2017.py`, and inherited by
  `pcap_feature_extractor_cicids2018.py`): `unique_flows` counts the window's distinct (source
  address, protocol) pairs, which with the destination fixed are the engine's flow keys {lower
  address, higher address, protocol}; `burst_factor` runs the engine's EWMA
  (`project/layer1/telemetry/burst_ewma.h`) per destination over the cache in time order, stepping
  every second without a window with x = 0. Packet-capture rows now carry 40 columns, the 39 engine
  names in the engine's order and `dir_ratio`, and the CSE-CIC-IDS2018 and CIC-DDoS2019 caches
  record `feature_count` 40;
- `ComparisonResults/litnet_loader.py`, the per-destination builder `rebuild_litnet_caches.py` uses:
  the same two columns from the NetFlow records starting in the window (`packets_per_sec` counts
  both directions), after `ttl_mean`, so LITNET-2020 rows carry 15 columns. Its subnet builder,
  which only the two LITNET-2020 subnet runners read, gained them too (`PROVENANCE.tsv`);
- `verify_extracted_tree.py` checks both columns on every row of the four corpora, and
  `build_scenario_inventory.py` and `drop_duplicate_columns.py` were adjusted (Provenance above).

The whole recipe was then run from the official releases on the authors' machine, which the runs
only read, under Python 3.12.15 with numpy 2.4.2, scipy 1.17.0 and dpkt 1.9.8 and one BLAS thread;
all 21 modules here compile and import. Every cache has the window count the earlier rebuild had
(CIC-IDS-2017 Monday 545,470, Wednesday 502,770 and Friday 442,606; CSE-CIC-IDS2018 Tuesday 19,824,
Wednesday 1,329,269, Thursday 1,037,772 and Friday 1,172,125; CIC-DDoS2019 93,238; LITNET-2020
3,848,562 on 19,015 hosts). The resulting tree:

- holds the same 65 files as the 37-name tree (31 scenario payloads, eight pools and their
  `.meta.json`, four `index.json`, eight `SHA256SUMS`, `SCENARIO_INVENTORY.md` and the five README
  files) in 2,056,369,268 bytes, against 1,912,630,664 (both counted with the README files of commit
  `895e581`; 2,056,372,694 with this revision's README files copied in); `tree_manifest/README.md`
  gives the sizes by corpus;
- equals the 37-name tree by value on every column that tree carried: all 39 payloads have the same
  hosts in the same order and the same windows, and all 2,165,971 rows are equal on every earlier
  key, in value and JSON type. `burst_factor` and `unique_flows` are on every row; the other
  differences are the three listed above, with `bytes` and `sha256`;
- passes the new checks: in every row `burst_factor` is a whole number from 0 to 3030 (largest
  3029) and `unique_src_ips` ≤ `unique_flows` ≤ `flows_per_sec`. The authors checked both columns
  outside the deposit against separate implementations: `burst_factor` recomputed from the per-day
  caches matches all 2,165,971 tree rows and all 8,991,636 cache rows, and `unique_flows` matches a
  separate re-parse of all eight capture days and of the complete LITNET-2020 export (39,603,674
  records). The 50,000 cap of the CSE-CIC-IDS2018 extractor's sets never binds (its largest
  `unique_flows` is 64), so every value is an exact count;
- gives the same admissibility results: `classify_scenarios.py` (with `--write`, and read-only)
  returns the census USABLE 16, ATTACKER-SIDE 6, FLOOR-LIMITED 4, NOT-DDOS 2, NO-FPR 2,
  INSEPARABLE 1, and on all 31 candidates the same `verdict`, `best_feature`, `best_auc`,
  `best_dr_at_5pct_fpr`, `n_calib`, `n_test_benign`, `p_floor`, `fpr_measurable` and
  `flag_profile_suggests_source` as `results/admissibility_ledger.json`. Neither new column beats a
  scenario's best feature; on CSE-CIC-IDS2018 `Wed-21-02_DDoS-LOIC-UDP` and LITNET-2020 `smurf`
  `unique_flows` ties it exactly (detection 100%, AUC 1.0), and the classifier keeps the earlier
  column. LITNET-2020 `http_flood` stays INSEPARABLE: `unique_flows` is constant there, and
  `burst_factor` detects 5.3% at AUC 0.594, against the best feature's 8.3% at 0.570;
- passes `verify_extracted_tree.py` (31 scenario files and 16 pool files, 0 problems),
  `verify_readme_claims.py` (0 problems) and `build_scenario_inventory.py --out` (identical to
  `tree_manifest/SCENARIO_INVENTORY.md`); `drop_duplicate_columns.py` keeps all 39 payloads and
  changes nothing; `write_extracted_index.py`, run again on a copy, leaves every file identical.

`unique_flows` is close to `unique_src_ips`, as the pre-registration expected: the two are equal on
99.7% of CIC-IDS-2017 rows, 99.9% of CSE-CIC-IDS2018 rows, 93.2% of CIC-DDoS2019 rows and 98.3% of
LITNET-2020 rows, and on every row of the CIC-DDoS2019 benign pool and of LITNET-2020 `http_flood`.
`ComparisonResults/README.md` ("Records after the 39-name re-run") describes the records re-run on
this tree.

## The regenerated CIC-IDS-2017 Wednesday files

Until the revision before this one (commit `9d51bdc`), the tree's five `Wed-05-07` slices and
`benign_pool_wednesday.json` stored `dst_port_density` without its factor of 1000
(`unique_dst_ports / packets_per_sec`, maximum 1.0), because the cache they came from predates that
factor; every other packet-capture file carries it. For that revision the authors rebuilt the
Wednesday cache with `run_cicids2017_pcap.py --day wednesday` and the six Wednesday files from it
with steps 2 and 3. No other value in them changed: window counts, labels, every other column, the
verdicts, the intensity statistics and the scenario inventory are as before, and in
`tree_manifest/CIC-IDS-2017/index.json` only the `bytes` and `sha256` values of the five Wednesday
entries changed (key order changed too, inside those entries and in the files' metadata and rows).
The slices' rows then also carried `_attack_types` (an empty mapping), the pool's rows
`_attack_type` (null) and `_attack_types`, and the pool metadata the current `role_check` wording
and `role_check_performed`. The rebuilt Wednesday cache was extracted from the raw capture three
times with identical rows, and two separate runs of steps 2 and 3 on it, one into an empty tree and
one into a copy of the authors' tree, wrote the six files byte for byte as `tree_manifest/` listed
them at that commit.

The whole `regenerate.sh` set, with `sixth_victim.sh` and `heldout_threeway40.sh`, was then run
again on the regenerated tree. Three records changed in value and were replaced
(`results/c_engine_ours.json`, `results/split_control_threeway40_matrix.json` and
`recompute/results/split_control_threeway40_sixvictim_matrix.json`); the other records these
scripts write were unchanged apart from unseeded LODA cells and stored run times, and were kept.
`ComparisonResults/README.md` (section "Records after the Wednesday regeneration") gives the
changed values and says what was re-measured for the four records with Wednesday rows that these
scripts do not rewrite. All of those records were scored on 37 names and were replaced again by
the 39-name re-run.

## What a rebuild does not reproduce

- **Checksums of the caches**, which record input paths and, for two corpora, run times (see
  [Comparing a rebuilt tree](#comparing-a-rebuilt-tree)).
- **The original Wednesday writer**, which does not survive (see
  [What the 9d51bdc revision added](#what-the-9d51bdc-revision-added)). A rebuild reproduces the
  regenerated Wednesday files, not the files the authors' tree held before that regeneration.
- **The hand-done steps themselves.** `stamp_cicddos_slice_metadata.py` and
  `split_cicddos_by_type.py --attacker-side` write the same values the authors typed or moved by
  hand, but not the original edits or the key order they left. The first `unusable_reason` typed
  into the six attacker-side slices quoted a count from a truncated read of `Syn.csv`; it is not
  reproduced, and in the authors' tree as in a rebuild `stamp_cicddos_roles.py` replaces it with the
  counts it measures over all seven 03-11 CSVs.
- **One metadata value of five caches.** In the four rebuilt CSE-CIC-IDS2018 day caches (Tuesday,
  Wednesday, Thursday and Friday) and the rebuilt CIC-DDoS2019 typed cache, `feature_count` is 40,
  against 39 in the caches the authors' 37-name tree was built from: the development extractors
  wrote a constant, and the deposited ones count the feature columns they write (38 before this
  revision). The tree does not carry this field.
- **A full-day CSE-CIC-IDS2018 Tuesday cache.** The authors' cache holds the victim and one other
  host (see [Inputs](#inputs)).

## What was checked for the 37-name revision

Every step of the recipe was run for that revision from the official releases on the authors'
machine, which the runs only read, with the scripts in this directory as they stood then (one
comment in `run_cicids2017_pcap.py` was reworded afterwards; no code changed), under Python 3.12.15
with numpy 2.4.2, scipy 1.17.0 and dpkt 1.9.8 and one BLAS thread. All 20 modules of the time
compiled and imported.

Each rebuilt cache was compared row by row with the cache the authors' tree was built from, with
`burst_factor` and `unique_flows` removed from the authors' rows:

| cache | built by | windows | result |
|---|---|---:|---|
| `cicids2017_pcap_monday.json` | `run_cicids2017_pcap.py --day monday` | 545,470 | equal; rebuilt rows add `_attack_type` and `_attack_types` |
| `cicids2017_pcap_wednesday.json` | `run_cicids2017_pcap.py --day wednesday` | 502,770 | equal on 9,012 hosts and 4,298 attack windows, except `dst_port_density`, equal to 1000 times the old value within one rounding step on every row (largest relative deviation 2.2e-16); rebuilt rows add the two keys |
| `cicids2017_pcap_friday.json` | `reparse_friday_2017.py` | 442,606 | equal on 8,327 hosts and 3,748 attack windows; byte-identical once the two removed columns are deleted from the authors' file |
| `cicids2018_pcap_tue.json` | `pcap_feature_extractor_cicids2018.py ... tue` | 19,824 | equal on both hosts and 4,684 attack windows; `feature_count` 38 against 39 |
| `cicids2018_pcap_{wed,thu,fri}.json` | `pcap_feature_extractor_cicids2018.py ... wed\|thu\|fri` | 1,329,269 / 1,037,772 / 1,172,125 | equal on 101 hosts each; rebuilt rows add the two keys; `feature_count` 38 against 39 |
| `cicddos_03-11_typed.json` | `pcap_feature_extractor.py` | 93,238 | equal on 1,286 hosts, including `_attack_type` and `_attack_types`; `feature_count` 38 against 39 |
| `litnet_per_ip_cache.json` | `rebuild_litnet_caches.py` | | byte-identical |

The tree was then built from these caches with steps 2 and 3 and compared with the authors' tree as
described above:

- all 31 `index.json` entries are equal on every field except `bytes` and `sha256`, and all 31
  payloads on every metadata key and every row. Against the tree as it stood before that revision,
  the only difference was `dst_port_density` in the six Wednesday files, which led to their
  regeneration;
- all eight pools have the same hosts in the same order, the same per-host window counts, the same
  `n_windows` and truncation counts, the same exclusion counts where the authors' metadata records
  them, and equal rows;
- `classify_scenarios.py` returns 31 verdicts equal to `results/admissibility_ledger.json` on the
  verdict and on `best_feature`, `best_auc`, `best_dr_at_5pct_fpr`, `n_calib`, `n_test_benign`,
  `p_floor`, `fpr_measurable` and `flag_profile_suggests_source`: USABLE 16, ATTACKER-SIDE 6,
  FLOOR-LIMITED 4, NOT-DDOS 2, NO-FPR 2, INSEPARABLE 1. `role_unverified` is false on all 31;
- `verify_extracted_tree.py` checks 31 scenario files and 16 pool files and reports 0 problems, and
  `verify_readme_claims.py` reports 0 problems;
- `build_scenario_inventory.py --out` writes a 154-line inventory (16 usable of 31 scenarios, 5
  distinct victims), identical to `tree_manifest/SCENARIO_INVENTORY.md`;
- on the CIC-DDoS2019 typed cache the authors used, both `split_cicddos_by_type.py` runs reproduce,
  byte for byte, the twelve slices the development splitter wrote at `2420cba`.

## Which scripts back which statements of the article

- The guard-band leak measurement (Section 3.1 and Appendix A.1): `split_by_attack_schedule.py`
  (`--guard`), on the caches that step 1 writes.
- The census statistics of Table 1 and the inputs of the per-candidate ledger (Table A2,
  Appendix C): `classify_scenarios.py`, `check_scenario_intensity.py`, `stamp_cicddos_roles.py`.
- The CIC-IDS-2017 benign-pool audit (Appendix B): `run_cicids2017_pool_audit.py`. The script
  drives `run_cicids2017_pcap.py` end to end, and its parity step reads
  `results/cicids2017_pcap_results.json`. Neither that file nor the record the audit writes
  (`results/cicids2017_pool_characterization.json`) is deposited.
