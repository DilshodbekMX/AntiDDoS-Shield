# CIC-IDS-2018 — per-attack-type feature caches

**Eight** single-attack slices of the CSE-CIC-IDS2018 DoS/DDoS days, one file per
attack, named by attack. Derived from the committed per-day caches — the day
caches already carry per-window unix timestamps — except Tuesday, whose pcap had
to be recovered and re-parsed (see below).

Produced by `AntiDDOS_Shield/experiments_copy/split_by_attack_schedule.py`.
`index.json` and `SHA256SUMS` are written by `write_extracted_index.py`, which
derives every field from the files on disk. Verify with `sha256sum -c SHA256SUMS`
run **from this directory**.

## Why these exist

The day-level caches blend two distinct attacks into one scenario, and the blend
describes neither. Thursday is the clearest case: the blended day inherits
GoldenEye's small calibration set, so it reads 0.0% at α=0.01 and a 99.8% attack
disappears inside it.

| Thursday 15-02 | n_attack | n_calib | DR @ α=0.01 |
|---|---:|---:|---:|
| day-level blend | 3309 | 89 | **0.0%** |
| `DoS-GoldenEye` | 917 | 89 | 0.0% *(floor-limited)* |
| `DoS-Slowloris` | 2392 | 149 | **99.8%** |

## Files

| file | attack | victim | schedule (local) | n_attack | n_benign | n_calib | DR @ α=0.01 |
|---|---|---|---|---:|---:|---:|---:|
| `Thu-15-02_DoS-GoldenEye.json` | DoS-GoldenEye | 172.31.69.25 | Thu 15-02 09:26–10:09 | 917 | 1273 | 89 | 0.0% § |
| `Thu-15-02_DoS-Slowloris.json` | DoS-Slowloris | 172.31.69.25 | Thu 15-02 10:59–11:40 | 2392 | 1273 | 149 | 99.8% |
| `Fri-16-02_DoS-SlowHTTPTest.json` | DoS-SlowHTTPTest | 172.31.69.25 | Fri 16-02 10:12–11:08 | 3189 | 1469 | 158 | 100.0% |
| `Fri-16-02_DoS-Hulk.json` | DoS-Hulk | 172.31.69.25 | Fri 16-02 13:45–14:19 | 844 | 1469 | 348 | 99.8% |
| `Tue-20-02_DDoS-LOIC-HTTP.json` | DDoS-LOIC-HTTP | 172.31.69.25 | Tue 20-02 10:12–11:17 | 3779 | 567 | 106 | 99.9% |
| `Tue-20-02_DDoS-LOIC-UDP.json` | DDoS-LOIC-UDP | 172.31.69.25 | Tue 20-02 13:13–13:32 | 905 | 567 | 227 | 99.4% ‡ |
| `Wed-21-02_DDoS-LOIC-UDP.json` | DDoS-LOIC-UDP | 172.31.69.28 | Wed 21-02 10:09–10:43 | 1101 | 2291 | 327 | 100.0% |
| `Wed-21-02_DDoS-HOIC.json` | DDoS-HOIC | 172.31.69.28 | Wed 21-02 14:05–15:05 | 3298 | 2291 | 356 | 98.2% |

§ floor-limited, see note 3. ‡ `n_test_benign = 0`, so no FPR is measurable —
the attack occupies the tail of the capture. DR is the `ours_ensemble` arm.

Schema: `{metadata, per_ip_windows: {victim: [window, ...]}}`. Each window keeps
the source 39-feature row plus `_dt`, `_id_time`, `_is_attack`, `_n_flows`, and
an added `_attack_type`.

## The label-boundary guard — read this first

**`_is_attack` in the source day caches comes only from CIC's published Table-2
schedule minute, and real floods do not respect a documented minute.** Traffic
that starts before or drains after a scheduled boundary is carried as *benign*,
and under the causal split it lands in the split-conformal **calibration set**,
where a single flood window sets a threshold no later attack can cross.

Three leaks were measured, each from an independent source:

| leak | evidence | size |
|---|---|---|
| Wed LOIC-UDP start | CIC's own CSV labels the flood from **10:08:51**; the schedule says 10:09 | 8 windows, 39,274–100,441 pps, `udp_ratio` 1.000 |
| Wed HOIC drain | runs unbroken across 15:05 at ~1,100 pps, decaying to 103 pps at 15:05:53 before a 100× cliff to 1 pps. The Wednesday CSV is 12-hour and stops at 14:33, so this is provable only from the packets | 54 windows |
| Thu Slowloris end | CIC's CSV runs to **11:42:01** against a schedule ending 11:40 | 121 s — the largest |

Those 8 Wednesday windows were the calibration **maximum for both Wednesday
slices**, 48× HOIC's own attack maximum. Effect at α=0.01:

| scenario | calibration max | DR |
|---|---|---|
| `Wed-21-02_DDoS-HOIC` | 100,441 → 15 pps | **0.0% → 98.2%** |
| `Wed-21-02_DDoS-LOIC-UDP` | 100,441 → 15 pps | 89.6% → **100.0%** |
| `Thu-15-02_DoS-Slowloris` | 1,035 → 13 pps | **0.1% → 99.8%** |

**The correction is a guard band, not a relabelling.** Benign windows within
**180 s** of a labelled attack span are *quarantined* — dropped from the slice,
counted as neither attack nor benign. Labels are never rewritten. Three
properties, all load-bearing:

1. **Magnitude-blind.** The rule is temporal proximity to a labelled attack. It
   contains no packets-per-second test, so it cannot be selecting away the
   benign windows that happen to be inconvenient. Where there is no leak it
   removes *low*-rate windows and keeps higher ones — Friday drops a maximum of
   10 pps while keeping a genuine 916 pps benign burst at 08:56, 76 minutes
   before any attack.
2. **Never invents a positive.** DR denominators are unchanged. Every change
   comes from a cleaner calibration set, not a larger attack set.
3. **Edge bands only, never the span interior.** A benign-labelled window
   *during* an attack stays in the pool: if the detector fires on it, that is a
   false positive and has to be counted. Guarding the interior would have
   deleted precisely the windows the detector is most likely to alarm on.

180 s is sized from the largest measured leak (121 s) plus margin. Cost per day:

| day | benign before | quarantined | max pps removed | max pps kept |
|---|---:|---:|---:|---:|
| Thu 15-02 | 1436 | 163 (11.4%) | 1,344 | 13 |
| Fri 16-02 | 1508 | 39 (2.6%) | 10 | 916 |
| Tue 20-02 | 597 | 30 (5.0%) | 8 | 66 |
| Wed 21-02 | 2430 | 139 (5.7%) | **100,441** | **18** |

`--guard N` re-runs the split at another half-width. `metadata` records
`guard_seconds`, `n_benign_before_guard` and `n_benign_quarantined` per file.

**CIC-IDS-2017 gets the same rule and no CSV refinement**: it ships only the
ML-CVE flow files, which have no `Timestamp` column at all, so a CSV-union rule
would have corrected the two corpora under different definitions.

## Timezone — derived, not assumed

The published schedule is local time; cache timestamps are unix epoch. The
offset was fixed by matching the **existing** `_is_attack` labels against the
schedule, which pins it at **UTC−4**:

```
Thursday labelled blocks   UTC 13:26:44–14:08:56   and   14:59:05–15:39:59
schedule (local)               09:26–10:09         and       10:59–11:40
```

Both match to the second; Friday and Wednesday confirm it independently. Note
that UTC−4 in February is **AST, not EDT** — earlier revisions of this file
named it EDT, which is a season that did not exist on these capture dates.

## Read these before using the files

**1. Same-day slices share a benign pool.** Both slices from a day draw on that
day's benign windows. The causal split partitions them differently (Thursday:
GoldenEye `n_calib`=89, Slowloris `n_calib`=149), so FPR rows are not identical
— but it is the same underlying traffic. **A mean over all eight double-counts
four benign samples.** Aggregate per day, or deduplicate by victim.

**2. Two different discontinuities exist, and only one of them is caused by
this split.** Recursive detectors (CUSUM, AnEWMA, MCP-TS, PEWMA, Moving CV)
consume rows in order and carry state; they cannot see a gap. But before
attributing anything to the per-attack split, the gaps have to be separated by
cause, because the largest gap in most slices is **not** the split's doing:

* **Protocol splice — the slice's own attack span.** The causal split
  calibrates on benign *preceding* the first attack and tests on what follows,
  so the last calibration window and the first post-attack benign window are
  separated by the whole attack. This gap exists identically in the unsplit day
  cache. It is a property of the evaluation protocol, not of this directory.
* **Split-induced hole — the other attack's span, removed.** This is the one
  the per-attack split actually creates, and only four slices have one.

Measured on the 60 benign windows following each gap, against that detector's
mean over all its benign eval windows:

| slice | gap | interval (local) | cause | CUSUM | AnEWMA |
|---|---:|---|---|---:|---:|
| `Wed-21-02_DDoS-LOIC-UDP` | 66.03 min | 14:01:59–15:08:01 | **split-induced** (HOIC removed) | 1.36× | 1.67× |
| `Fri-16-02_DoS-SlowHTTPTest` | 40.92 min | 13:41:36–14:22:31 | **split-induced** (Hulk removed) | 1.10× | 1.39× |
| `Thu-15-02_DoS-GoldenEye` | 47.18 min | 10:55:54–11:43:05 | **split-induced** (Slowloris removed) | 1.09× | 1.28× |
| `Wed-21-02_DDoS-HOIC` | 229.83 min | 10:05:56–13:55:46 | **split-induced** (LOIC-UDP removed, spanning the natural capture break) | 0.96× | 0.77× |
| `Wed-21-02_DDoS-HOIC` | 66.03 min | 14:01:59–15:08:01 | protocol splice | 1.36× | 1.62× |
| `Tue-20-02_DDoS-LOIC-HTTP` | 72.03 min | 10:08:25–11:20:27 | protocol splice | 1.24× | 1.74× |
| `Fri-16-02_DoS-SlowHTTPTest` | 62.37 min | 10:08:51–11:11:13 | protocol splice | 0.93× | 0.80× |
| `Thu-15-02_DoS-GoldenEye` | 49.93 min | 09:22:04–10:12:00 | protocol splice | 0.99× | 1.11× |
| `Thu-15-02_DoS-Slowloris` | 47.18 min | 10:55:54–11:43:05 | protocol splice | 1.06× | 1.32× |
| `Fri-16-02_DoS-Hulk` | 40.92 min | 13:41:36–14:22:31 | protocol splice | 1.10× | 1.32× |
| `Wed-21-02_DDoS-LOIC-UDP` | 229.83 min | 10:05:56–13:55:46 | protocol splice | 0.91× | 0.78× |

**Split-induced holes: 4, largest response 1.36× (CUSUM) and 1.67× (AnEWMA).
Protocol splices: 7, largest 1.36× and 1.74×.** Neither is large, and the two
*biggest* gaps of all — the 229.83-minute pair — produce responses *below*
baseline. `Tue-20-02_DDoS-LOIC-UDP` has no gap over 10 minutes at all.

Note that the same wall-clock interval appears twice with different causes: the
Thursday 10:55–11:43 gap is Slowloris's own span in the Slowloris slice and
Slowloris's *removal* in the GoldenEye slice. Same seconds, opposite
attribution — which is exactly why the causes have to be separated rather than
tabulated as one "hole" column.

Two earlier revisions of this file got this wrong in different ways. The first
reported a 41.5-minute Slowloris hole inflating scores 3.65×–3.77×, put Hulk at
34.9 minutes, and said Slowloris's hole "sits inside its calibration region" —
none of which reproduces (Slowloris's calibration set's largest internal gap is
2.60 minutes). The second corrected the numbers but listed one gap per slice
under a heading about removing the other attack, when for five of seven slices
the gap it listed was the protocol splice.

Where the gaps come from: Thursday's and Tuesday's source caches have **no** gap
over 5 minutes (3.33 and 3.30), and Friday's has one natural 9.20-minute gap, so
in those days every large gap is either a protocol splice or split-induced.
**Wednesday's 208.43-minute gap is natural** — a capture break already present
in the source day cache, which is why the Wednesday rows are so much larger than
any attack span.

**3. Exactly one slice is floor-limited at α=0.01.** Split-conformal p-values
cannot go below `1/(n_calib+1)`. `Thu-15-02_DoS-GoldenEye` (`n_calib`=89, floor
**0.0111**) cannot fire at α=0.01 at all — every detector reads exactly 0.0%
there by arithmetic, not by failing. Evaluate it at α≥0.05, where it is 99.5%,
or not at all. Every other slice has a floor between 0.0028 and 0.0093 and is
evaluable at α=0.01. An earlier revision said two slices were floor-limited;
that was true only of the pre-guard calibration sets.

**4. DDoS-HOIC does *not* separate the path families.** An earlier revision
reported that nine of ten arms score exactly 0.0% at α=0.01 while Adaptive
Entropy scores 98.0%, and concluded that HOIC "shifts distributional features
enough for an entropy path while staying outside the volume paths' operating
point". **That is refuted.** It was the poisoned calibration set: the LOIC-UDP
lead-in seven hours earlier set a 100,441 pps volume threshold, silencing every
rate-driven path, while entropy features are not rate-driven and survived.

| DDoS-HOIC, α=0.01 | arms detecting | range |
|---|---:|---|
| before the guard (`n_calib`=380) | **1 of 11** | entropy 98.0%; nine arms exactly 0.0% |
| after the guard (`n_calib`=356) | **10 of 11** | 88.6% – 98.2%; only Moving CV fails |

Moving CV is a degenerate comparator panel-wide (mean AUC 0.496), so its failure
here says nothing about HOIC.

## Tuesday: why it was missing, and how it was recovered

Tuesday was absent because its pcaps had never been extractable. Every other day
ships from the AWS bucket as `pcap.zip`; **Tuesday alone ships as `pcap.rar`
(RAR 5.0)** — 41.3 GiB. No rar reader was installed (`unrar`, `unar`, `7z`,
`bsdtar` and Python `rarfile` all absent), so the download script fell through
its rar branch and wrote a partial extraction: 253 members, subnets
172.31.64–67 only, missing 68.x and 69.x and therefore both victims.

**Those members are almost entirely unusable, not merely incomplete.** Of the
253 written, **252 are zero-prefixed** (magic `00000000`) and only one is a
readable capture. `parse_pcap_for_one_host`'s bare `except Exception: return 0,0`
makes a corrupt capture indistinguishable from a silent host, which is why the
partial extraction produced no error.

No root was needed to fix it. `bsdtar` reads RAR5 via libarchive, and a `.deb`
unpacks without privileges:

```bash
apt-get download libarchive-tools
dpkg -x libarchive-tools_*.deb /tmp/local
export PATH=/tmp/local/usr/bin:$PATH
bsdtar -xvf pcap.rar pcap/UCAP172.31.69.25      # 8.49 GB, victim only
```

That recovery wrote `pcap/UCAP172.31.69.25` (8.49 GB) and
`pcap/capEC2AMAZ-O4EL3NG-172.31.69.28` (100 MB), and **the two Tuesday slices
are built from the former** — not from the 253 partial members. Only the
victim's own capture was extracted, not all 41.3 GiB: the extractor keeps only
windows where `dst_ip` equals the file's own host, so the other members are
irrelevant to this victim. The victim is confirmed by the same size-dominance
rule the extractor documents for the other days — 8.49 GB against a 100 MB
runner-up — and independently by the Tuesday CSV, whose `Dst IP` column (the
only 2018 CSV that retains it) carries `172.31.69.25` on every
`DDoS attacks-LOIC-HTTP` flow.

## Coverage

All four DoS/DDoS capture days of CSE-CIC-IDS2018 are extracted; eight attacks in
total, and `pcap_dos/` holds no fifth day. Six further capture days ship CSVs in
`datasets/CIC-IDS2018/CSV/` — 14-02, 22-02, 23-02, 28-02, 01-03 and 02-03 — but
they carry brute-force, web-attack, infiltration and botnet traffic, not
DoS/DDoS, and no pcaps for them are present. An earlier revision said "nothing
further remains in this corpus", which overstates it: nothing further remains
*that is a denial-of-service day*.
