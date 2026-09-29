# CIC-IDS-2017 — per-attack-type feature caches

Seven single-attack slices of CIC-IDS-2017, one file per attack. Derived from
the committed per-day caches — **no pcap was re-parsed**; the day caches already
carry per-window unix timestamps.

Produced by `AntiDDOS_Shield/experiments_copy/split_by_attack_schedule.py 2017`.
`index.json` and `SHA256SUMS` are written by `write_extracted_index.py`, which
derives every field from the files on disk. Verify with `sha256sum -c
SHA256SUMS` run **from this directory**.
Schedule source: https://www.unb.ca/cic/datasets/ids-2017.html

## How `_is_attack` is actually assigned — not by the schedule

CIC-IDS-2017 does **not** label from the published schedule. `_is_attack` comes
from `load_2017_flow_labels()`, a join on the 5-tuple `(src_ip, sport, dst_ip,
dport, proto)` against CIC's own labelled-flow CSVs, where an attack label
always beats BENIGN. The schedule is consulted **only** to separate one attack
from another once a window is already labelled. Earlier revisions of this file
and of the tree README said the schedule assigns the label; it does not, and the
difference matters in two directions:

* **The join is time-blind.** No timestamp is in the key, so a 5-tuple reused
  later in the day inherits the earlier use's attack label. That is where the
  attack-labelled windows outside every scheduled span come from (134 on
  Wednesday .50, 44 on .51, 34 on Friday .50); they are reported and excluded,
  never absorbed.
* **The join is direction-sensitive.** The CSVs list flows attacker→victim, so
  packets travelling victim→attacker never match and are labelled benign. This
  is why the *attacker* accumulates zero attack windows — see the benign-pool
  note below.

CIC ships each day's labels under `CSVs/TrafficLabelling ` (the trailing space
is CIC's own), 85 columns with `Timestamp` at column 7. There is also a
79-column ML-CVE copy under `CSVs/` with no `Timestamp` at all; an earlier
revision of this file cited that copy as evidence that 2017 has no timestamped
labels, which is false and was used to justify not cross-checking the schedule
against the CSVs here. It can be cross-checked, and doing so is what found the
defect below.

## Friday's labels live in THREE files, and only one was being read

`run_cicids2017_pcap.py` named the DDoS CSV as Friday's sole label source. Two
whole attacks were therefore never labelled:

| unlabelled attack | flows | span | consequence |
|---|---:|---|---|
| **PortScan** | 158,930 | 13:05–15:23, all `172.16.0.1 → 192.168.10.50` | stayed in the benign pool and landed in DDoS-LOIT's calibration set |
| **Bot** | 1,966 | 09:34–12:59, C2 `205.174.165.73` | all 8 involved hosts shipped in `benign_pools/benign_pool_friday.json` as "attack-free" |

The PortScan consequence is the serious one. `within_split` calibrates on benign
*preceding the first attack window*; with the scan unlabelled, the scan **is**
benign, so it entered the calibration set of the DDoS attack that runs later the
same afternoon.

**It did not need to be most of that set — it needed to be the top of it.**
165 of the 1,617 calibration windows were scan: **10.2%**, and 0% of `fit`. But
all ten of the calibration set's highest `packets_per_sec` windows were scan,
from 1,090 down to 1,007, against a scan-free maximum of 156. Split-conformal
p-values are order statistics — `p = (1 + #{calib >= s}) / (n + 1)` — so the
threshold is set by the extreme tail of the calibration distribution and
contamination is fatal in proportion to how LOUD it is, not how prevalent.
CIC-IDS-2018's HOIC is the same shape at 8 windows in 380, **2.1%**.

Earlier revisions of this file said 85%, and the audit that found the defect
said 77.2%. Both counted calibration windows falling inside the scan's *time
envelope* — but the scan ran in 27 discrete minutes spread across 2 h 18 m, so
1,202 of those 1,366 windows are genuinely benign traffic between bursts. The
arithmetic that settles it is this fix's own: PortScan gained 426 − 261 = 165
attack windows, and exactly those 165 left the calibration set.

| DDoS-LOIT calibration | before | after |
|---|---:|---:|
| max `packets_per_sec` | 1,090 | **156** |
| max `syn_per_sec` | 1,001 | **8** |
| max `unique_dst_ports` | 1,026 | **32** |

| DDoS-LOIT DR @ α=0.01 | before | after |
|---|---:|---:|
| ours_ensemble | 13.6% | **99.6%** |
| ours_z | 0.0% | 88.7% |
| anewma | 0.0% | 99.6% |
| mcpts | 3.3% | 99.0% |
| spot | 23.3% | 97.7% |

It is not a sample-size effect. Holding `n_calib` fixed at 251, five random
subsamples of the contaminated set give 13.6–26.8% while the scan-free subset
gives 99.6%. Structurally this is CIC-IDS-2018's Wednesday defect with a
different cause — there a schedule boundary, here an unopened file — and the
guard band cannot reach either, because the guard quarantines span edges and
this is span interior.

Fixed by loading all three CSVs (`FRIDAY_CSVS`) and re-parsing the day. Attack
windows went 1,434 → 3,748 across the capture; packets, windows and host count
are unchanged, so only labels moved.

## Timezone is UTC−3, and it is NOT the same as CIC-IDS-2018

Derived, not assumed. Matching the **existing** `_is_attack` labels against the
published schedule:

```
Heartbleed labelled   18:12:15–18:31:59 UTC
schedule (local)          15:12–15:32          =>  UTC-3
```

At UTC−4 — the EDT the July calendar implies, and the offset that is correct
for CIC-IDS-2018 — every 2017 attack lands exactly one hour early. Assuming one
offset for both corpora would have mislabelled every window in this directory.

## Files

| file | attack | victim | schedule | n_attack | n_calib | DoS/DDoS? |
|---|---|---|---|---:|---:|---|
| `Wed-05-07_DoS-Slowloris.json` | DoS Slowloris | 192.168.10.50 | 09:47–10:10 | 1267 | 171 | yes |
| `Wed-05-07_DoS-Slowhttptest.json` | DoS Slowhttptest | 192.168.10.50 | 10:14–10:35 | 788 | 179 | yes |
| `Wed-05-07_DoS-Hulk.json` | DoS Hulk | 192.168.10.50 | 10:43–11:00 | 463 | 212 | yes |
| `Wed-05-07_DoS-GoldenEye.json` | DoS GoldenEye | 192.168.10.50 | 11:10–11:23 | 422 | 255 | yes |
| `Wed-05-07_Heartbleed.json` | Heartbleed (port 444) | 192.168.10.51 | 15:12–15:32 | 1180 | 3741 | **no — exploit** |
| `Fri-07-07_PortScan.json` | Port Scan | 192.168.10.50 | 13:55–15:27 | 426 | 1030 | **no — recon** |
| `Fri-07-07_DDoS-LOIT.json` | DDoS LOIT | 192.168.10.50 | 15:56–16:16 | 1136 | 1550 | yes |

Heartbleed and PortScan are included for completeness but are **not**
denial-of-service attacks. Do not put them in a DDoS panel without saying so.

Botnet ARES (Friday 10:02–11:02) is absent by design: it targets
192.168.10.5/.8/.9/.14/.15, never .50, so the cached Friday victim carries zero
botnet windows — confirmed empirically.

## Why this matters: the Friday scenario is mis-scoped in the panel

The manuscript's headline cross-day scenario tests victim 192.168.10.50 on
Friday with 1,427 attack windows. Those windows are **not all DDoS**:

```
PortScan    13:55–15:27     261 windows   (18%)  <- recon, not DDoS
DDoS-LOIT   15:56–16:16    1136 windows   (80%)
unaccounted                  30 windows
```

Scoring them separately under the same cross-day protocol (calibrate on Monday
benign, n_fit=3140, n_calib=786):

| test set | n_attack | Ours (Ensemble) | Ours (no AnEWMA) | SPOT |
|---|---:|---|---|---|
| **DDoS-LOIT only** | 1136 | **99.2% / 1.7%** | 87.8% / 2.5% | 97.7% / 2.6% |
| PortScan only | 426 | see note | | |
| blended | 1562 | see note | | |

**Correctly scoped to the actual DDoS, the cross-day result is 99.2% DR at
1.7% FPR.** The manuscript's headline blends 1,427 Friday windows of which the
scan is recon, not denial of service. Now that the scan is properly labelled the
blend is 1,562 windows (1,136 LOIT + 426 PortScan), and the PortScan and blended
rows are left un-quoted here rather than restated from the pre-fix run — they
were measured against a contaminated calibration set and have not been re-run.
The DDoS-LOIT row is the one that matters and is current.

## A "protocol effect" that was actually the unlabelled scan

An earlier revision of this file reported that DDoS-LOIT scores **13.6% DR**
within-day against **99.2% cross-day**, and explained the gap as a property of
the protocol — "cross-day calibration on Monday fits Friday poorly, so every
score inflates". **That explanation was wrong.** Monday's calibration contains
no port scan, while Friday's within-day calibration held the scan's loudest
165 windows. The gap was the contamination above, not the protocol.

Corrected, both protocols agree and the cross-day false-alarm rate collapses,
because the scan was inflating the test-benign side too:

| DDoS-LOIT | before | after |
|---|---|---|
| within-day (`n_calib` 1617 → 1550) | 13.6% / 0.0% | **99.6% / 3.3%** |
| cross-day Mon→Fri (`n_calib` 786) | 99.2% / 12.1% | **99.2% / 1.7%** |

There is still a real protocol difference — cross-day calibration is the harder
test and should be quoted with its number — but it is worth ~0 pp of DR here,
not 86.

## The label-boundary guard

`_is_attack` comes only from the published schedule minute, and attacks do not
start and stop on a documented minute. Traffic outside the boundary is carried
as *benign* into the conformal calibration set, where one contaminated window
can set a threshold no later attack can cross. On CIC-IDS-2018 this silenced
three whole scenarios; see that corpus's README for the measurements.

The same correction is applied here: benign windows within **180 s** of a
labelled attack span are quarantined — dropped, counted as neither attack nor
benign. Labels are never rewritten, and only the *edges* are guarded, never the
span interior, so a benign-labelled window during an attack stays in the pool
and a detector firing on it still counts as a false positive.

| victim | benign before | quarantined | max pps removed | max pps kept |
|---|---:|---:|---:|---:|
| Wed .50 | 3227 | 160 (5.0%) | 124 | 234 |
| Wed .51 | 11130 | 134 (1.2%) | 2,700 | 3,390 |
| Fri .50 | 4221 | 135 (3.2%) | 108 | 1,090 |

**No leak was found in this corpus** — on all three victims the guard removes
windows *quieter* than ones it keeps, which is what a magnitude-blind rule looks
like when there is nothing to catch. It is applied anyway, because the rule has
to be the same for both corpora to mean anything.

Unlike CIC-IDS-2018, no CSV cross-check was possible: CIC-IDS-2017 ships the
ML-CVE flow files, which have 79 columns beginning at `Destination Port` and
**no `Timestamp` column at all**. A CSV-union refinement was available for 2018
and not here, which is precisely why the shipped correction is the guard band
alone rather than a per-corpus mixture of the two.

## Caveats — the same ones as the 2018 set

**1. Same-day slices share a benign pool.** The four Wednesday DoS slices all
draw on the same 3,067 benign windows of victim .50; the two Friday slices share
4,086. The causal split partitions them differently, so FPR rows are not
identical, but it is the same traffic. **A mean over the four Wednesday slices
counts that benign sample four times.** Aggregate per day or deduplicate by
victim.

**2. Removing the other attacks leaves temporal holes — but measurably small
ones.** Recursive detectors (CUSUM, AnEWMA, MCP-TS, PEWMA, Moving CV) consume
rows in order and carry state; they cannot see a hole. Wednesday is the extreme
case here — each slice has three other attacks cut out of it. An earlier
revision of this file imported a figure from the 2018 set, "a 41-minute hole
inflated post-gap benign scores 3.65×–3.77×", and told you to expect the same.
**That figure does not reproduce.** Re-measured on the 2018 set with each gap
attributed to its cause, split-induced holes reach at most 1.36× (CUSUM) and
1.67× (AnEWMA) and protocol splices at most 1.36× / 1.74×; the two largest gaps
give responses *below* baseline. Note also that most of what looks like a "hole"
is the **protocol splice** — the slice's own attack span, which the causal split
straddles and which is present in the unsplit day cache too. Check a Wednesday
slice's FPR if you like, but do not expect a hole artifact to explain it.

**3. Windows outside every scheduled window are excluded, not absorbed.**
Wednesday .50: 134 of 3,074 (09:01:00–14:25:01). Wednesday .51: 44 of 1,224.
Friday .50: 34 of 1,596. Labels are never rewritten — only `_attack_type` is
added. These are the time-blind join's residue (see the provenance section):
some are genuine attack drain past a scheduled end, some are 5-tuple reuse. The
splitter prints the count on every run.

**4. The attacker used to ship inside the benign pool.** `172.16.0.1` is the
source of every non-BENIGN Wednesday flow, yet it carried zero attack windows —
the join is direction-sensitive, and Wednesday's CSV has no role-reversed rows
to catch it. It qualified as "attack-free" and was the **loudest of 661** hosts
in `benign_pool_wednesday`, 1st on both max (6,243 pps) and p99 (5,981) against
a pool median-of-medians of 2.0. Friday escaped only by accident: its DDoS CSV
happens to carry 3 role-reversed rows. Pool membership is now decided on
**role** — any host appearing as either endpoint of a non-BENIGN flow in the
label CSVs is excluded — which is a property of the corpus, not of the join's
direction. Wednesday 661 → 660 hosts; Friday 610 → 602 (6 now attack-labelled
by the re-parse, 2 more by the role check). Checked on the other corpora before
scoping this to 2017: CIC-DDoS2019 already excludes its attacker, and none of
the 15 documented CSE-CIC-IDS2018 attacker IPs appears in any 2018 pool.
