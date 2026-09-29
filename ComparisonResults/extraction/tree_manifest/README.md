# Per-attack scenario caches

Single-attack evaluation scenarios derived from five public corpora, one
directory per corpus, one file per attack. Each file is self-contained: the
victim's benign windows plus that attack's windows, in the 39-feature per-window
schema the Layer-2 harness consumes.

```
extracted/
  CIC-IDS-2017/           7 scenarios      39M
  CIC-IDS2018/            8 scenarios      30M
  CICDDoS2019/           12 scenarios      84M
  CIC_IOT_Dataset2023/   13 scenarios     229M
  LITNET-2020/            4 scenarios     4.6M
  CESNET-TimeSeries24/    benign reference 291M
                         44 scenarios     678M
```

**CESNET-TimeSeries24 is not a scenario set.** It has no attacks and no label
column — 174 hosts, 970,277 hourly windows, zero attack windows. It is the
false-alarm anchor: real ISP backbone traffic with no synthetic generator, which
is what rules out "the false-alarm floor is a testbed artifact". Its numbers are
not comparable to the pcap corpora (hourly windows, 11 features against 39). See
its own README.

Each corpus directory holds `SHA256SUMS`, an `index.json` with per-scenario
provenance and measurements, a `README.md` covering that corpus's specific
caveats, and a `benign_pools/` subdirectory.

## benign_pools/ — the false-alarm denominator

Scenario files carry the **victim's own** benign windows, which is what the
causal split calibrates on. That is not a false-alarm measurement. A detector's
operational cost is what it does to hosts that are never attacked, and those
hosts appear in no scenario file.

`benign_pools/` holds them: every destination with **zero** attack-labelled
windows and at least 100 windows, each truncated to its first 3,000
chronologically.

**This is not the population the manuscript's 71.8% per-window floor is measured
on**, and an earlier revision of this file said it was. That figure comes from
`run_cicids2017_pool_audit.py`, whose pool is **530 IPs / 145,030 benign *test*
windows** under a different gate — zero attack-labelled windows *in the
cross-day test slice* and at least 30 benign test windows there. The Friday pool
here is 610 hosts / 208,254 whole-day windows. The two overlap on 387 hosts;
143 of the manuscript's are absent here and 223 of these are extra. Use these
pools for what they are — an attack-free denominator for new measurements — not
as a reconstruction of a published number.

| corpus | pool | hosts | windows |
|---|---|---:|---:|
| CIC-IDS-2017 | monday | 800 | 268,173 |
| CIC-IDS-2017 | wednesday | 660 | 227,274 |
| CIC-IDS-2017 | friday | 602 | 184,443 |
| CIC-IDS-2018 | wed / thu / fri | 100 each | 292,852 / 291,232 / 288,798 |
| CIC-DDoS2019 | 03-11 | 88 | 39,687 |
| CIC-IoT-2023 | benign_capture | 479 | 470,789 |
| LITNET-2020 | per_ip | 965 | 419,913 |
| **total** | | **3,894** | **2,583,161** |

**A pool is not attack-free just because no window carries `_is_attack`.** In
CIC-IDS-2017 that flag comes from a direction-sensitive join, so an attacker
whose victim's replies never match the CSV accumulates zero attack windows and
qualifies. `172.16.0.1` — the source of every non-BENIGN Wednesday flow — was
the **loudest of 661** hosts in `benign_pool_wednesday` on exactly that basis.
Membership is now decided on **role**: any host appearing as either endpoint of
a non-BENIGN flow is excluded. The other corpora were checked before scoping
this to 2017.

Every eligible host is kept; each is truncated to its first 3,000 windows
chronologically. That ordering is deliberate — a false-positive rate is an
average over **hosts**, so diversity is preserved and depth is traded away. An
earlier version capped total windows per pool and kept 5 of 479 CIC-IoT hosts.

Two corpus-specific points:

**CIC-IoT-2023** uninvolved hosts cannot be recovered from its attack captures
at all: the corpus labels every window of a family capture as attack regardless
of host, so an untouched device still reads as attacked. Its pool comes from the
dedicated benign capture.

**LITNET-2020**'s pool is built from an `allFlows.csv` that was extracted 11.5%
short, with two attack types entirely absent. Some hosts counted attack-free
there may not be. Rebuild from the now-complete file before trusting it.

`usable_for: false-positive rate only` — there are no attacks in these files. **Read the corpus README before using its files** — the protocols
differ in ways that matter.

Regenerate with the scripts in `AntiDDOS_Shield/experiments_copy/`, in this
order — `classify_scenarios.py --write` mutates the payloads, so the index and
checksums must be written **after** it, never before:

```
split_by_attack_schedule.py      # CIC-IDS-2017 + CIC-IDS-2018 slices
split_cicddos_by_type.py         # CIC-DDoS2019
export_cicios2023_scenarios.py   # CIC-IoT-2023
export_litnet_scenarios.py       # LITNET-2020  (rebuild_litnet_caches.py first)
export_benign_pools.py           # benign_pools/   [--only CORPUS]
write_extracted_index.py <dir>   # index.json      <- FIRST, see below
classify_scenarios.py --write    # verdicts into each payload
write_extracted_index.py <dir>   # index.json + SHA256SUMS, again, LAST
```

`write_extracted_index.py` runs **twice**, and both times are load-bearing.
`classify_scenarios.py` skips any corpus directory that has no `index.json` and
exits 0, so on a fresh tree the single-pass order prints `USABLE: 0 of 0` and
writes nothing — an earlier revision of this file documented exactly that order.
And because `classify --write` rewrites each payload to embed its verdict, the
hashes must be taken *after* it, or `sha256sum -c` fails on every file. So:
index first to give classify something to walk, index again at the end to record
what the files finally are.

`split_by_attack_schedule.py` writes to `datasets/extracted/<corpus>/` by
default. It used to default to `experiments_copy/cache/`, so following this
recipe put 15 slices there under filenames identical to the tree's — a stale
pre-guard shadow set that any load-by-basename would have picked up. Those
copies have been removed.

## 44 scenarios exist; 22 are usable

| corpus | usable | total | excluded |
|---|---:|---:|---|
| CIC-IDS-2017 | 5 | 7 | 2 not denial-of-service (PortScan, Heartbleed) |
| CIC-IDS-2018 | 6 | 8 | 1 floor-limited, 1 no measurable FPR |
| CIC-DDoS2019 | 4 | 12 | 6 attacker-side (measured), 2 floor-limited |
| CIC-IoT-2023 | 6 | 13 | 7 role-unverified |
| LITNET-2020 | 1 | 4 | 1 no FPR, 1 floor-limited, 1 inseparable |
| **total** | **22** | **44** | |

Only **one** scenario in the whole tree is excluded for being genuinely
undetectable (LITNET `http_flood`). Every other exclusion is structural: the
labelled host is the attack source, the calibration set is too small for the
nominal alpha, no benign traffic follows the attack, or the attack is not a
denial-of-service.

Verdicts come from `AntiDDOS_Shield/experiments_copy/classify_scenarios.py`,
which applies four independent checks and records all of them per file:

| check | disqualifies when |
|---|---|
| **direction** | the host's inbound flag mix matches an attack *source*. Documented roles override it — CIC-DDoS2019's `172.16.0.5` is a measured attacker (20,299,481 flows out against 8,079 back across all seven CSVs), so those six verdicts rest on ground truth, not on the heuristic. **On CIC-IoT-2023 the heuristic is disabled**: pcap ground truth shows it flags 15 of 16 confirmed RSTFIN flood *targets* and 0 of 10 confirmed sources — inverted — so those seven are `ROLE-UNVERIFIED` rather than attacker-side. Still excluded, for a reason that is true |
| **separability** | no feature reaches rank-AUC 0.75 and 20% detection at a 5%-FPR threshold. Rank-AUC over *all* features, not a percentile ratio on packet rate — Slowloris is invisible in packet rate by design |
| **conformal floor** | `1/(n_calib+1) > alpha`, so no detector can fire and every method reads 0.0% by arithmetic |
| **FPR measurable** | `n_test_benign < 5` — the false-positive rate is undefined, not zero |

Verify the whole tree with
`AntiDDOS_Shield/experiments_copy/verify_extracted_tree.py`, which recomputes
the numbers it checks from the files rather than reading the index back — an
index that agrees with itself proves nothing. It covers the scenario files
(hashes, index coverage, schema, window counts, intensity class) **and the
benign pools** (hashes against their own SHA256SUMS, host and window counts
against each `.meta.json`, and a check that no pool contains an attack-labelled
window). It does **not** re-derive `n_calib`, `p_floor`, `verdict`, `best_auc`
or the `inbound_*_share` values — those come from `classify_scenarios.py`.

Until recently the pools were pruned out of its walk and checked nowhere, which
left 76.6% of the tree by bytes and all 3,894 pool hosts unverified while the
script printed "0 problems". That is the gap the attacker-in-the-pool finding
came through.

That gap is the point of this directory. Every scenario carries
`usable_as_ddos_scenario` in its `index.json`, and the reasons are measured, not
asserted.

## The three ways a scenario fails

**Indistinguishable traffic.** The labelled host's attack traffic is under 2× its
*own* benign p95 — sometimes below it. CIC-IDS-2017 Slowloris runs at 0.8×,
CIC-DDoS2019's `172.16.0.5` at 1.0–1.3× across all seven of its attacks. These
are not mislabelled: the host is a NAT, gateway or bystander the corpus marks
attack-involved without it receiving the attack. A detection rate needs
something to detect, and these still report high numbers — CIC-IoT
ACK_Fragmentation reports 69.8% DR at 0.54× its own benign p95, i.e. on traffic
quieter than its own baseline.

Two numbers are needed, not one. An absolute rate floor alone is wrong:
CIC-IoT ICMP_Flood sits at 44 pkt/s but its host's benign p95 is 1.0, so that is
a real 44× attack a flood threshold would discard. Conversely a host can pass an
absolute threshold on a single burst while sitting at background rate
throughout. Check with `check_scenario_intensity.py`, which reports both.

**No measurable FPR.** The attack runs to the end of the capture, so no benign
traffic follows its onset and `n_test_benign = 0`. The detection rate is valid;
the false-positive rate is **undefined, not zero**. Affects CIC-IDS-2018
Tue LOIC-UDP and LITNET smurf.

**A contaminated calibration set.** Not a verdict the classifier assigns — it
is invisible to every check that looks at counts — but it is the defect that has
cost the most here, twice. Split-conformal p-values are order statistics, so the
detection threshold is the **top** of the calibration distribution. Attack
traffic that reaches calibration is therefore fatal in proportion to how loud it
is, not how prevalent: CIC-IDS-2017 DDoS-LOIT's calibration was 10.2% port scan
(165 of 1,617) and read 13.6% DR instead of 99.6%; CIC-IDS-2018 HOIC's was 2.1%
(8 of 380) and read 0.0% instead of 98.2%. Neither was close to a majority, and
in both the contaminating windows owned the top of the distribution.
`verify_extracted_tree.py` now enforces the machine-checkable half of this: no
slice's fit or calibration set may contain a window that a sibling slice of the
same victim-day labels attack. It runs over all **26** multi-slice scenarios,
`attacker_side/` included — those six are the sharpest case the invariant has,
six overlapping attacks on one host-day where `_attack_type` records only the
dominant label per window, and they are what the attacker-side exclusion is
argued *from*.

**Conformal floor.** Split-conformal p-values cannot go below `1/(n_calib+1)`.
Where that exceeds α no detector can fire and every method reads exactly 0.0% by
arithmetic. At α=0.01 this affects four scenarios: CIC-IDS-2018 Thu GoldenEye
(n_calib=89), CIC-DDoS2019 MSSQL (81) and NetBIOS (94), and LITNET `udp_f`,
whose attack occupies the opening minutes of the record so nothing precedes it
and n_calib is **0**.

## Protocols differ by corpus

| corpus | how labels were assigned | benign source |
|---|---|---|
| CIC-IDS-2017 | **per-flow 5-tuple join** to CIC's labelled-flow CSVs; schedule used only to separate one attack from another, **UTC−3** | same capture, pre-attack |
| CIC-IDS-2018 | published schedule, **UTC−4** | same capture, pre-attack |
| CIC-DDoS2019 | per-flow CSV labels, no schedule | same capture, fully-benign windows |
| CIC-IoT-2023 | directory-derived (whole capture) | **separate benign capture** |
| LITNET-2020 | corpus flow labels | same capture |

**CIC-IDS-2017's labels do not come from its schedule**, and an earlier revision
of this table said they did. `_is_attack` there comes from a join on
`(src_ip, sport, dst_ip, dport, proto)` — no timestamp — where an attack label
beats BENIGN; the schedule only separates one attack from another afterwards.
Two consequences follow from the key: it is **time-blind**, so a 5-tuple reused
later in the day inherits the earlier attack label (this is where the 212
attack-labelled windows outside every scheduled span come from), and it is
**direction-sensitive**, so victim→attacker packets never match. See the
CIC-IDS-2017 README. CIC-IDS-2018's labels really are schedule-derived.

The two timezone offsets were **derived**, not assumed — each by matching the
corpus's own existing labels against its published schedule. They differ, and
neither matches the calendar for its date. Assuming one offset for both would
have shifted every CIC-IDS-2017 attack by an hour.

CIC-IoT's benign comes from a *different capture session*, so its FPR is
measured inside the benign capture rather than adjacent to the attack. Its
numbers are not directly comparable to the within-capture splits.

## Shared benign pools

Where several scenarios come from one day and one victim, they draw on the same
benign windows: the four CIC-IDS-2017 Wednesday slices share one 3,067-window
pool, and each CIC-IDS-2018 day's two slices share that day's benign (1,273 /
1,469 / 567 / 2,291 for Thu / Fri / Tue / Wed). The causal
split partitions them differently so FPR rows are not identical, but it is the
same traffic. **A mean over such scenarios counts that benign sample more than
once.** Aggregate per victim, or deduplicate.

## Temporal holes

Removing the other attacks from a day leaves a gap the recursive detectors
(CUSUM, AnEWMA, MCP-TS, PEWMA, Moving CV) cannot see — they consume rows in
order and treat instants far apart as adjacent. CIC-IDS-2017 Wednesday is the
extreme case: each slice has three other attacks cut out of it.

**Separate the causes before attributing anything to the split.** The largest
gap in most slices is *not* the split's doing — it is the **protocol splice**,
the slice's own attack span sitting between the last calibration window and the
first post-attack benign window. That gap exists identically in the unsplit day
cache; it is a property of the causal split, not of this directory. Only the
**other** attack's removal is split-induced, and on CIC-IDS-2018 just four
slices have one.

**Measured, both are small.** Over the 60 benign windows following each gap:
split-induced holes (n=4) reach at most **1.36× (CUSUM) / 1.67× (AnEWMA)**;
protocol splices (n=7) at most 1.36× / 1.74×. The two biggest gaps of all —
229.83 minutes — produce responses *below* baseline. Per-slice table in the
CIC-IDS-2018 README.

An earlier revision reported a 41.5-minute hole inflating scores 3.65–3.77× and
placed it "inside its calibration region". None of that reproduces: Slowloris's
own span is 47.18 minutes and its calibration set's largest internal gap is 2.60
minutes.

Attribution was re-checked rather than carried forward. CIC-IDS-2018 Thursday's
and Tuesday's source caches have no gap over 5 minutes (3.33 and 3.30), so every
large hole in those four slices is an artifact of the split; Friday's source has
one natural 9.20-minute gap. **The 208.43-minute gap belongs to CIC-IDS-2018
Wednesday**, where it is a natural capture break already present in the source —
an earlier revision credited it to CIC-DDoS2019, whose capture is a single
Saturday with a largest gap of 14 minutes and no Wednesday at all.

## What is not here

- **CESNET-TimeSeries24** — no label column at all. It is unlabelled benign ISP
  telemetry, usable as a false-alarm anchor and nothing else. No per-attack
  split is possible because there are no attacks.
- **LITNET `udp_f`** — recovered. It was absent from every cache because
  `allFlows.csv` had been extracted 11.5% short; the caches were rebuilt from
  the complete file and it is now present. It is still not usable: the attack
  occupies the opening minutes of the record, so no benign traffic precedes it,
  `n_calib` is 0 and the conformal floor is 1. `smurf` is the mirror image —
  the attack runs to the end, so `n_test_benign` is 0 and no FPR exists.
- **CIC-IoT** DoS-\*, Recon-\*, MITM, DNS_Spoofing and the web attacks — CSV
  only locally, and those CSVs ship without IPs or timestamps so no join to
  packets is possible. Downloadable via `download_pcap.sh` with valid cookies.
- **CIC-DDoS2019 01-12** — twelve further attacks in four unextracted zips.
