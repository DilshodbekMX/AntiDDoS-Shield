# Per-attack scenario caches

Single-attack evaluation scenarios derived from four public corpora, one
directory per corpus, one file per attack. Each file is self-contained: the
victim's benign windows plus that attack's windows, one row per destination
host per second, in the schema the Layer-2 harness consumes. Rows from the
three packet-derived corpora carry 38 feature columns; LITNET-2020 rows, built
from flow records, carry 13.

This is the README of the derived tree `datasets/extracted/`, which is not
deposited. The deposit carries this file, `SCENARIO_INVENTORY.md`, and each
corpus's `README.md`, `index.json` and `SHA256SUMS` files under
`ComparisonResults/extraction/tree_manifest/`. The scripts that build it from
the official corpus releases are in `ComparisonResults/extraction/` (see below).

```
extracted/
  CIC-IDS-2017/    7 scenarios    39.4 MB    3 benign pools    681.3 MB
  CIC-IDS2018/     8 scenarios    29.2 MB    3 benign pools    860.5 MB
  CICDDoS2019/    12 scenarios    84.0 MB    1 benign pool      40.4 MB
  LITNET-2020/     4 scenarios     4.8 MB    1 benign pool     172.8 MB
                  31 scenarios   157.4 MB    8 benign pools  1,755.1 MB
```

Each corpus directory holds `SHA256SUMS`, an `index.json` with per-scenario
provenance and measurements, a `README.md` covering that corpus's specific
caveats, and a `benign_pools/` subdirectory with its own `SHA256SUMS`.
CIC-DDoS2019 keeps its six attacker-side scenarios in `attacker_side/`.

## benign_pools/: the false-alarm denominator

Scenario files carry the **victim's own** benign windows, which is what the
causal split calibrates on. That is not a false-alarm measurement. A detector's
operational cost is what it does to hosts that are never attacked, and those
hosts appear in no scenario file.

`benign_pools/` holds them: every destination with **zero** attack-labelled
windows and at least 100 windows, each truncated to its first 3,000
chronologically, minus any host the role check below excludes.

**This is not the population behind the manuscript's 71.8% pooled fixed-θ
false-alarm rate on CIC-IDS-2017**, and an earlier revision of this file said
it was. That figure comes from `run_cicids2017_pool_audit.py`, which drives
`run_cicids2017_pcap.py`; the record the audit writes is not deposited. Its
530-host pool is gated differently: at least 60 windows on both Monday and
Friday, then zero attack-labelled windows and at least 30 benign windows in the
Friday test slice. The Friday pool here is 602 hosts / 184,443 whole-day
windows, so the two host sets necessarily differ. Use these pools for what
they are, an attack-free denominator for new measurements, not as a
reconstruction of a published number.

| corpus | pool | hosts | windows | role check |
|---|---|---:|---:|---|
| CIC-IDS-2017 | monday | 800 | 268,173 | benign-only capture day; nothing to exclude |
| CIC-IDS-2017 | wednesday | 660 | 227,274 | label CSVs; 1 host excluded (`172.16.0.1`) |
| CIC-IDS-2017 | friday | 602 | 184,443 | label CSVs; 2 hosts excluded |
| CIC-IDS-2018 | wed / thu / fri | 100 each | 292,852 / 291,232 / 288,798 | not possible from the labels; address-range check |
| CIC-DDoS2019 | 03-11 | 88 | 39,687 | attacker and victim absent; no role-check field in `.meta.json` |
| LITNET-2020 | per_ip | 956 | 414,702 | corpus ground truth; 9 hosts excluded |
| **total** | | **3,406** | **2,007,161** | |

**A pool is not attack-free just because no window carries `_is_attack`.** In
CIC-IDS-2017 that flag comes from a direction-sensitive join, so an attacker
whose victim's replies never match the CSV accumulates zero attack windows and
qualifies. `172.16.0.1`, the source of every non-BENIGN Wednesday flow, was
the **loudest of 661** hosts in `benign_pool_wednesday` on exactly that basis.
Membership is now decided on **role**: any host appearing as either endpoint of
a non-BENIGN flow is excluded. Each corpus carries its ground truth somewhere
different:

- **CIC-IDS-2017**: the per-day labelled-flow CSVs. Wednesday excludes
  `172.16.0.1`; Friday excludes `192.168.10.12` and `192.168.10.17`.
- **CSE-CIC-IDS2018**: its CSVs carry no IP columns, so no label-derived role
  check is possible. Checked by address instead: all 300 pool hosts are
  internal `172.31.*`, and none lies in CIC's documented external attacker
  range (`18.*` / `13.*`).
- **CIC-DDoS2019**: the 03-11 per-attack CSVs. The attacker `172.16.0.5` and the
  victim `192.168.50.4` are both absent from the 88-host pool.
- **LITNET-2020**: the corpus's flow labels. 965 hosts qualify on labels; the
  role check removes 9 that source attack flows, among them `193.219.86.241`,
  the source of all 747 `smtp_b` flows.

Every eligible host is kept; each is truncated to its first 3,000 windows
chronologically. That ordering is deliberate: a false-positive rate is an
average over **hosts**, so diversity is preserved and depth is traded away. An
earlier version capped total windows per pool instead, which kept 137 of 800
hosts on CIC-IDS-2017 Monday.

**LITNET-2020**'s pool is built from the per-IP cache of the complete
`allFlows.csv` (26,943,158,910 bytes). It is not the corpus's full uninvolved
population: that cache keeps only destinations in `193.219.*` and `83.171.*`
plus the external victim `23.32.104.60`, so these are attack-free hosts of the
protected network, not every uninvolved host in the capture.

`usable_for: false-positive rate only`: there are no attacks in these files.
**Read the corpus README before using its files**: the protocols differ in
ways that matter.

Rebuild with the scripts in `ComparisonResults/extraction/`; its `README.md`
gives the recipe, including the per-day caches these steps read and how they
are built from the raw captures and flow files. A rebuilt tree equals this one
by value; only 9 of the 47 files listed in the `SHA256SUMS` files also match
byte for byte, so compare the others with their `index.json` entries (that
README says how). The six CIC-IDS-2017 Wednesday files were regenerated with
these scripts for this revision. The order matters:
`classify_scenarios.py --write` rewrites the payloads, so the index and
checksums must be written **after** it, never only before:

```
split_by_attack_schedule.py all                  # CIC-IDS-2017 + CSE-CIC-IDS2018 slices
split_cicddos_by_type.py <typed_cache> 03-11     # CIC-DDoS2019 victim slices
split_cicddos_by_type.py <typed_cache> 03-11 --attacker-side   # the six attacker_side/ slices
stamp_cicddos_slice_metadata.py                  # CIC-DDoS2019 keys first typed by hand
stamp_cicddos_roles.py                           # CIC-DDoS2019 host roles, measured from the 03-11 CSVs
export_litnet_scenarios.py                       # LITNET-2020  (rebuild_litnet_caches.py first)
export_benign_pools.py                           # benign_pools/   [--only CORPUS]
write_extracted_index.py <dir>                   # index.json      <- FIRST, see below
classify_scenarios.py --write                    # verdicts into each payload
write_extracted_index.py <dir>                   # index.json + SHA256SUMS, again, LAST
build_scenario_inventory.py                      # SCENARIO_INVENTORY.md
```

`write_extracted_index.py` runs **twice**, and both runs matter.
`classify_scenarios.py` skips any corpus directory that has no `index.json`, so
on a fresh tree the single-pass order prints `USABLE: 0 of 0` and writes no
verdict; an earlier revision of this file documented exactly that order. And
because `classify --write` rewrites each payload to embed its verdict, the
hashes must be taken *after* it, or `sha256sum -c` fails on every file. So:
index first to give classify something to walk, index again at the end to
record what the files finally are.

`split_by_attack_schedule.py` writes to `datasets/extracted/<corpus>/` by
default, like the other builders.

## 31 scenarios exist; 16 are usable

| corpus | usable | total | excluded |
|---|---:|---:|---|
| CIC-IDS-2017 | 5 | 7 | 2 not denial-of-service (PortScan, Heartbleed) |
| CIC-IDS-2018 | 6 | 8 | 1 floor-limited, 1 no measurable FPR |
| CIC-DDoS2019 | 4 | 12 | 6 attacker-side (measured), 2 floor-limited |
| LITNET-2020 | 1 | 4 | 1 no FPR, 1 floor-limited, 1 inseparable |
| **total** | **16** | **31** | |

By verdict: USABLE 16, ATTACKER-SIDE 6, FLOOR-LIMITED 4, NOT-DDOS 2, NO-FPR 2,
INSEPARABLE 1. The 16 usable scenarios sit on 5 distinct victims.
`ComparisonResults/results/admissibility_ledger.json` records the same verdict
for each of the 31.

Only **one** scenario carries the separability verdict, LITNET `http_flood`:
on every feature the screen measures, its attack windows are statistically
the same traffic as the host's own benign windows (best rank-AUC 0.5701,
packet rate 1.1× its benign p95). The verdict is the screen's, not a proof
that the attack cannot be detected. The earlier full-tree sweep
(`results/full_tree_all_scenarios_metrics.json`) scores the ensemble on it at
0.0% detection, AUC 0.40; under the engine's rule set and a 60/20/20
per-host benign split, the rescued record
`ComparisonResults/results/rescued/litnet_results_COMPLETE_EXPORT.json`, which
the deposit does not regenerate, detects 359 of its 360 attack windows at
11.9% false alarms. The two runs are not like for like; see the LITNET-2020
README. The screen also fails CIC-DDoS2019 `cicddos_03-11_172-16-0-5_LDAP`
(17.1% detection at a 5%-FPR threshold), whose recorded verdict is
ATTACKER-SIDE because the direction check comes first. Every other exclusion
is structural: the labelled host is the attack source, the calibration set is
too small for the nominal alpha, no benign traffic follows the attack, or the
attack is not a denial-of-service.

Verdicts come from `ComparisonResults/extraction/classify_scenarios.py`, which
applies four independent checks and records all of them per file:

| check | disqualifies when |
|---|---|
| **direction** | the host's inbound flag mix matches an attack *source*. Documented roles override it: CIC-DDoS2019's `172.16.0.5` is a measured attacker (20,299,481 flows out against 8,079 back across all seven 03-11 CSVs), so those six verdicts rest on ground truth, not on the heuristic |
| **separability** | no feature reaches rank-AUC 0.75 and 20% detection at a 5%-FPR threshold. Rank-AUC over *all* features, not a percentile ratio on packet rate: Slowloris is invisible in packet rate by design |
| **conformal floor** | `1/(n_calib+1) > alpha`, so no detector can fire and every method reads 0.0% by arithmetic |
| **FPR measurable** | `n_test_benign < 5`: the false-positive rate is undefined, not zero |

Verify the whole tree with
`ComparisonResults/extraction/verify_extracted_tree.py`, which recomputes the
numbers it checks from the files rather than reading the index back; an index
that agrees with itself proves nothing. It covers the scenario files (hashes,
index coverage, schema, window counts, intensity class, cross-slice
calibration purity) **and the benign pools** (hashes against their own
`SHA256SUMS`, host and window counts against each `.meta.json`, and a check
that no pool contains an attack-labelled window). It does **not** re-derive
`n_calib`, `p_floor`, `verdict`, `best_auc` or the `inbound_*_share` values,
which come from `classify_scenarios.py`, and it does not compare the index's
`bytes` field with the file size.

The pools were once pruned out of its walk and checked nowhere while the
script printed "0 problems". That is the gap the attacker-in-the-pool finding
came through.

That gap is the point of this directory. Every scenario carries
`usable_as_ddos_scenario` in its `index.json`, and the reasons are measured,
not asserted.

## The three ways a scenario fails

**Indistinguishable traffic.** On some scenarios the labelled host's
attack-window packet rate is under 2× its *own* benign p95, sometimes below
it: CIC-IDS-2017 Slowloris at 0.83×, CIC-DDoS2019's `172.16.0.5` at 1.0–1.33×
across its six scenarios, LITNET `http_flood` at 1.1×. The three cases end
differently. Slowloris is slow by design and separates on another feature
(`src_port_entropy`, 99.9% detection at a 5%-FPR threshold), so it is usable;
`172.16.0.5` is the attack source, so it is attacker-side; `http_flood`
separates on no feature and is the one inseparable scenario. A packet-rate
ratio alone would have condemned Slowloris, which is why separability is
judged by rank-AUC over every feature.

Two numbers are needed, not one. An absolute rate floor alone is wrong:
CIC-IDS-2018 SlowHTTPTest sits at a p95 of 40 pkt/s, far under any flood
threshold, but that is 5.7× its host's benign p95 of 7, and it is a real
attack. Conversely a host can pass an absolute threshold on a single burst
while sitting at background rate throughout. `check_scenario_intensity.py`
reports both, and `write_extracted_index.py` records the resulting intensity
class (VOLUMETRIC, LOW-RATE, INDISTINCT) in each `index.json`. The verdicts
come from `classify_scenarios.py`, which replaced the intensity check as the
gate.

**No measurable FPR.** The attack runs to the end of the capture, so no benign
traffic follows its onset and `n_test_benign = 0`. The detection rate is valid;
the false-positive rate is **undefined, not zero**. Affects CIC-IDS-2018
Tue LOIC-UDP and LITNET `smurf`. LITNET `udp_f` also records
`n_test_benign = 0`, for the opposite reason: its attack opens the record, so
no benign window precedes it and the causal split is undefined; its verdict
records the conformal floor first.

**A contaminated calibration set.** Not a verdict the classifier assigns, since
it is invisible to every check that looks at counts, but it is the defect that
has cost the most here, twice. Split-conformal p-values are order statistics,
so the detection threshold is the **top** of the calibration distribution.
Attack traffic that reaches calibration is therefore fatal in proportion to how
loud it is, not how prevalent: CIC-IDS-2017 DDoS-LOIT's calibration was 10.2%
port scan (165 of 1,617) and read 13.6% DR instead of 99.6%; CIC-IDS-2018
HOIC's was 2.1% (8 of 380) and read 0.0% instead of 98.2%. Neither was close to
a majority, and in both the contaminating windows owned the top of the
distribution. `verify_extracted_tree.py` now enforces the machine-checkable
half of this: no slice's fit or calibration set may contain a window that a
sibling slice of the same victim-day labels attack. It runs over all **26**
multi-slice scenarios, `attacker_side/` included. Those six are the sharpest
case the invariant has, six overlapping attacks on one host-day where
`_attack_type` records only the dominant label per window, and they are what
the attacker-side exclusion is argued *from*.

**Conformal floor.** Split-conformal p-values cannot go below `1/(n_calib+1)`.
Where that exceeds α no detector can fire and every method reads exactly 0.0%
by arithmetic. At α=0.01 this affects four scenarios: CIC-IDS-2018 Thu
GoldenEye (n_calib=89), CIC-DDoS2019 MSSQL (81) and NetBIOS (94), and LITNET
`udp_f`, whose attack occupies the opening minutes of the record so nothing
precedes it and n_calib is **0**. The closest survivor is CIC-IDS-2018
Tue LOIC-HTTP (n_calib=106, floor 0.0093). `admissibility_ledger.json` records
how the usable count moves with α: 15 at 0.0075, 19 at 0.0125.

## Protocols differ by corpus

| corpus | how labels were assigned | benign source |
|---|---|---|
| CIC-IDS-2017 | **per-flow 5-tuple join** to CIC's labelled-flow CSVs; schedule used only to separate one attack from another, **UTC−3** | same capture, pre-attack |
| CIC-IDS-2018 | published schedule, **UTC−4** | same capture, pre-attack |
| CIC-DDoS2019 | per-flow CSV labels, no schedule | same capture, fully-benign windows |
| LITNET-2020 | corpus flow labels | same capture |

**CIC-IDS-2017's labels do not come from its schedule**, and an earlier
revision of this table said they did. `_is_attack` there comes from a join on
`(src_ip, sport, dst_ip, dport, proto)`, with no timestamp, where an attack
label beats BENIGN; the schedule only separates one attack from another
afterwards. Two consequences follow from the key: it is **time-blind**, so a
5-tuple reused later in the day inherits the earlier attack label (this is
where the 212 attack-labelled windows outside every scheduled span come from:
134 on Wednesday `.50`, 44 on `.51`, 34 on Friday `.50`), and it is
**direction-sensitive**, so victim→attacker packets never match. See the
CIC-IDS-2017 README. CIC-IDS-2018's labels really are schedule-derived.

The two timezone offsets were **derived**, not assumed, each by matching the
corpus's own existing labels against its published schedule. They differ by an
hour, as Atlantic daylight time (July 2017) and Atlantic standard time
(February 2018) do. Assuming one offset for both would have shifted every
CIC-IDS-2017 attack by an hour.

## Shared benign pools

Where several scenarios come from one day and one victim, they draw on the same
benign windows: the four CIC-IDS-2017 Wednesday slices on `192.168.10.50`
share one 3,067-window pool, and each CIC-IDS-2018 day's two slices share that
day's benign (1,273 / 1,469 / 567 / 2,291 for Thu / Fri / Tue / Wed). The causal
split partitions them differently so FPR rows are not identical, but it is the
same traffic. **A mean over such scenarios counts that benign sample more than
once.** Aggregate per victim, or deduplicate.

## Temporal holes

Removing the other attacks from a day leaves a gap the recursive detectors
(CUSUM, AnEWMA, MCP-TS, PEWMA, Moving CV) cannot see: they consume rows in
order and treat instants far apart as adjacent. CIC-IDS-2017 Wednesday is the
extreme case: each slice has three other attacks cut out of it.

**Separate the causes before attributing anything to the split.** The largest
gap in most slices is *not* the split's doing. It is the **protocol splice**,
the slice's own attack span sitting between the last calibration window and the
first post-attack benign window. That gap exists identically in the unsplit day
cache; it is a property of the causal split, not of this directory. Only the
**other** attack's removal is split-induced, and on CIC-IDS-2018 just four
slices have one.

**Measured, both are small.** Over the 60 benign windows following each gap:
split-induced holes (n=4) reach at most **1.36× (CUSUM) / 1.67× (AnEWMA)**;
protocol splices (n=7) at most 1.36× / 1.74×. The two biggest gaps of all,
229.83 minutes, produce responses *below* baseline. Per-slice table in the
CIC-IDS-2018 README.

An earlier revision reported a 41.5-minute hole inflating scores 3.65–3.77× and
placed it "inside its calibration region". None of that reproduces: the gap
Slowloris's own span leaves between its calibration and test windows is 47.18
minutes, and its calibration set's largest internal gap is 2.60 minutes.

Attribution was re-checked rather than carried forward. CIC-IDS-2018 Thursday's
and Tuesday's source caches have no gap over 5 minutes (3.33 and 3.30), so every
large hole in those four slices is an artifact of the split; Friday's source has
one natural 9.20-minute gap. **The 208.43-minute gap belongs to CIC-IDS-2018
Wednesday**, where it is a natural capture break already present in the
source. An earlier revision credited it to CIC-DDoS2019, whose 03-11 capture is
a single Saturday with a largest gap of 14 minutes and no Wednesday at all.

## What is not here

- **LITNET `syn_flood`**, the corpus's largest attack family. It is
  distributed: in the per-IP cache built from the complete `allFlows.csv` it
  spreads 701,483 attack windows over 17,174 destination hosts, 15,873 of them
  past the 30-window gate (median 42, mean 42.7, maximum 175 windows per host).
  No deposited record holds this census. `export_litnet_scenarios.py` builds
  one scenario per concentrated attack family from a hand-written victim list;
  this family is dispersed, so it ships no scenario and, because the exclusion
  happens before the four checks run, carries no verdict. See the LITNET-2020
  README.
- **LITNET `udp_f`**: recovered. It was absent while the per-IP cache came from
  an `allFlows.csv` extracted 11.5% short; the tree was rebuilt from the
  complete file and now carries it. It is still not usable: the attack
  occupies the opening minutes of the record, so no benign traffic precedes it,
  `n_calib` is 0 and the conformal floor is 1. `smurf` is the mirror image: the
  attack runs to the end, so `n_test_benign` is 0 and no FPR exists.
- **CIC-DDoS2019 `Portmap`**: absent from both 03-11 hosts by design. It is the
  first attack of the day and starts at capture open, leaving 1 and 11 benign
  windows before it, below the gate of 30.
- **CIC-DDoS2019 01-12**: twelve further attacks in four unextracted zips.
