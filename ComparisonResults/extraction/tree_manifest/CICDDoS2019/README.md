# CIC-DDoS2019 — per-attack-type feature caches (day 03-11)

Twelve single-attack slices from the 3 November 2018 capture, six attacks on
each of two labelled hosts. Produced by re-extracting the pcaps with per-window
attack-type recording, then splitting on the dataset's own CSV labels.

**Only one of the two hosts is a victim.** `172.16.0.5` is the attack *source*,
confirmed against the corpus CSVs; its six slices live in `attacker_side/` and
are excluded from every usable count, leaving **four** usable scenarios on
`192.168.50.4`. See "`172.16.0.5` is the ATTACKER" below — the tables in the
next two sections still list all twelve, because the exclusion is a conclusion
drawn from them, not an assumption made before them.

Pipeline, in this order — `write_extracted_index.py` runs **twice** and both
times matter:

```
pcap_feature_extractor.py        # CHANGE 180, per-window attack-type recording
split_cicddos_by_type.py         # victim slices (--out defaults to this tree)
stamp_cicddos_roles.py           # measures host roles from the CSVs, stamps them
write_extracted_index.py <dir>   # index.json  <- FIRST
classify_scenarios.py --write    # verdicts into each payload
write_extracted_index.py <dir>   # index.json + SHA256SUMS, again, LAST
```

`classify_scenarios.py` skips any corpus directory with no `index.json` and
exits 0, so the single-pass order prints `USABLE: 0 of 0` and writes nothing —
an earlier revision of this file documented exactly that order, and the tree
README was corrected for it while this one was not. And because
`classify --write` rewrites each payload to embed its verdict, hashes must be
taken after it. `write_extracted_index.py` keeps the quarantined
`attacker_side/` slices in the index rather than erasing the finding.

Verify with `sha256sum -c SHA256SUMS` run **from this directory**.

## Why this corpus contributed nothing before

CIC-DDoS2019 yielded **zero** usable scenarios. Its causal split found
`n_pre_benign = 1`, because the day-level labels run wall-to-wall — victim
192.168.50.4 showed one continuous attack block covering 09:18:30–17:36:40, the
entire capture.

The cause is in the extractor: a window is labelled attack if **any** flow in it
is one. These floods produce enormous flow counts, so nearly every second at the
victim contains at least one attack flow and the whole day reads as attack.
There *is* a benign prologue in the capture; there was none in the label.

Splitting by attack type recovers it. Each attack begins at a different time, so
the fully-benign windows preceding a given attack become its calibration set:

| | scenarios |
|---|---|
| day-level (as in the panel) | 0 |
| per-attack-type | 12 produced |
| …that clear the split gates | 10 |
| **…that are actually DDoS floods** | **3** |

**Read the intensity section below before using any of these.** Twelve slices
exist; only three are usable DDoS scenarios.

## No schedule and no timezone were used

Unlike the CIC-IDS-2017 and -2018 splits, this one needs neither. Attack type
comes from the dataset's per-flow CSV labels, carried through the extractor's
existing 5-tuple join. That matters: the other two corpora required *different*
offsets (2018 UTC−4, 2017 UTC−3, neither matching the calendar), and this one
would have needed a third derivation to get right.

For reference only, the capture date is **3 November 2018** — the naming is
DD-MM, so `SAT-03-11-2018` is a Saturday (3 Nov 2018 was; 11 Mar was not),
confirmed by the CSVs' own `2018-11-03` timestamps. Note the UNB page's day
labels are swapped relative to the file naming: its "First Day (Training)"
table lists the seven attacks belonging to this 03-11 day.

## Files

| victim | attack | n_attack | n_calib | floor | evaluable at α=0.01 |
|---|---|---:|---:|---:|---|
| 192.168.50.4 | LDAP | 593 | 144 | 0.0069 | yes |
| 192.168.50.4 | **MSSQL** | 1861 | 81 | 0.0122 | **no — floor-limited** |
| 192.168.50.4 | **NetBIOS** | 560 | 94 | 0.0105 | **no — floor-limited** |
| 192.168.50.4 | Syn | 6272 | 236 | 0.0042 | yes |
| 192.168.50.4 | UDP | 831 | 197 | 0.0051 | yes |
| 192.168.50.4 | UDPLag | 472 | 214 | 0.0047 | yes |
| 172.16.0.5 | LDAP | 146 | 478 | 0.0021 | yes |
| 172.16.0.5 | MSSQL | 410 | 674 | 0.0015 | yes |
| 172.16.0.5 | NetBIOS | 91 | 166 | 0.0060 | yes |
| 172.16.0.5 | Syn | 5744 | 1413 | 0.0007 | yes |
| 172.16.0.5 | UDP | 112 | 905 | 0.0011 | yes |
| 172.16.0.5 | UDPLag | 224 | 1268 | 0.0008 | yes |

**Portmap is absent from both victims by design.** It is the first attack of the
day and starts at capture open (08:18:30 / 08:19:24), leaving `n_pre_benign` of
1 and 11 — below the gate of 30. That is the original whole-corpus failure, now
isolated to a single attack instead of condemning all seven.

## What a slice actually is — read before using

**Attack time SPANS interleave, but individual windows are clean.** An earlier
version of this file claimed windows mix attacks heavily. They do not, and the
measurement says so: the dominant type holds a median of **100%** of a window's
attack packets (p05 = 0.945), only 15.8% of windows on 192.168.50.4 contain
more than one type at all, and on 172.16.0.5 just **2 windows** do.

What interleaves is the *dominant-label spans* — 18 of 21 span-pairs on
192.168.50.4 overlap, with MSSQL-dominant windows running 08:44–11:38 across
NetBIOS, LDAP and UDP. **That is an artifact of how the labels are merged, not a
property of the capture.** The corpus's own labels are strictly sequential by
flow start time, with zero overlap among all 21 pairs and gaps as small as 59
microseconds:

```
Portmap  09:18:19 -> 10:01:48      UDP      10:52:00 -> 11:12:58
NetBIOS  10:01:48 -> 10:18:39      UDPLag   11:13:03 -> 11:27:53
LDAP     10:19:10 -> 10:31:59      Syn      11:28:00 -> 17:36:41
MSSQL    10:32:02 -> 10:51:59
```

The seven CSVs are merged into one 5-tuple dictionary with unconditional
last-write-wins, so a 5-tuple appearing in several files resolves to whichever
file was loaded last rather than to whichever record matches the packet in time.
MSSQL.csv loads last, which is why MSSQL-dominant windows appear hours from any
MSSQL flow record. Treat a slice's span as "windows this label won", not as
"when this attack ran" — the second reading is what the sequential table above
gives.

So a slice means: *windows where this attack dominates, plus every fully-benign
window; windows dominated by a different attack are excluded.* It is **not** a
claim that the attack ran continuously across that span. Each window carries
`_attack_types`, the full `{label: packet_count}` distribution.

**Verified clean:** across all 12 slices there is zero leakage — no attack
window in any fit or calibration set, no attack-flagged window in any benign
test set, and no wrong-attack window in any test set. The benign windows are
real traffic, not idle seconds: 0% sit below 1 pkt/s.

**Same-victim slices share a benign pool** (192.168.50.4: 3,183 fully-benign
windows across six slices; 172.16.0.5: 7,730). A mean over all six counts that
benign sample six times. Aggregate per victim or deduplicate.

## MOST OF THESE SLICES ARE NOT FLOODS

Only five of the twelve carry attack traffic at flood intensity. Applying the
same p95 packet-rate test that exposed a non-victim in CIC-IoT-2023 (where a
claimed +72.9 pp win became +2.1 pp on the correct host):

| victim | attack | p95 pkt/s | flood? |
|---|---|---:|---|
| 192.168.50.4 | UDP | 37,204 | yes |
| 192.168.50.4 | Syn | 27,314 | yes |
| 192.168.50.4 | MSSQL | 25,630 | yes, but floor-limited |
| 192.168.50.4 | LDAP | 18,570 | yes |
| 192.168.50.4 | NetBIOS | 16,359 | yes, but floor-limited |
| 192.168.50.4 | UDPLag | 16 | **no** |
| 172.16.0.5 | *all seven* | 12–16 | **no** |

**`172.16.0.5` is the ATTACKER.** Not "almost certainly" — confirmed against
the corpus's own CSVs, unanimously across all seven 03-11 files:

Measured over **all seven** 03-11 CSVs, 20,364,525 data rows, by
`stamp_cicddos_roles.py` — which also writes this into `index.json` and every
`attacker_side/` payload, so the number cannot drift from its source again:

| direction | flows |
|---|---:|
| `172.16.0.5` → `192.168.50.4` | **20,299,481** |
| `192.168.50.4` → `172.16.0.5` | 8,079 |
| ratio | **2,513 : 1** |

Per file: LDAP 2,107,494 / 616 · MSSQL 5,772,083 / 909 · NetBIOS 3,454,063 / 515
· Portmap 186,511 / 449 · Syn 4,281,316 / 3,435 · UDP 3,777,978 / 1,094 ·
UDPLag 720,036 / 1,061. All seven agree.

Those 8,079 inbound flows are SYN-ACK and RST-ACK replies from the victim —
backscatter. Its attack-labelled windows are that backscatter plus its own
outbound attack traffic, so no detection claim can rest on them.

**An earlier revision of this file printed "2,966,708 and 2,232" here.** Those
are Syn.csv alone, and only its first 3,000,000 of 4,320,541 rows — both numbers
reproduce simultaneously at exactly that row, so it was a truncated read rather
than a different counting rule. No variant reproduces the pair. The same figure
had been copied into `index.json`, into all six `attacker_side/` payloads and
into the splitter source: one short read stamped in sixteen places. The verdict
was right, which is precisely why it survived review — a 1,329:1 ratio on a
truncated slice instead of 2,513:1 on the corpus.

Those six files are moved to `attacker_side/` and excluded from every count.
They are kept rather than deleted because they are a useful negative control:
a detector that alarms on them is alarming on the attack *source*, which is a
different and much easier problem than protecting the target.

**How this was missed, and how it was caught.** The original victim rule picked
hosts by attack-window count. The cache is keyed by destination, but a host also
accumulates attack-labelled windows from backscatter it *receives* — so the
attacker ranked second by count with 7,025 windows. The intensity gate flagged
all six independently at 1.0–1.3× their own benign traffic before the CSV was
consulted, which is a useful validation of that gate: it reached the right
answer with no ground truth available. The splitter now selects victims from
the CSV Destination IP field.

So: **4 usable scenarios** — 192.168.50.4 on LDAP, Syn, UDP and UDPLag.
`is_flood` and `usable_as_ddos_scenario` are recorded per entry in `index.json`.
An earlier revision said three here while saying four at the top of the file;
every machine record says four (`index.json`, `scenario_classification.json`
and `PANEL.json` agree), and the tree's "22 usable" total is built on four.
UDPLag is the one that was being dropped: it is LOW-RATE rather than a flood —
`is_flood` is false — but low-rate is not unusable, and it clears every gate.

## Measured results (α=0.01, causal split)

**The `all 12 slices` FPR column is dominated by the victim's backscatter and
should not be read as a false-alarm rate.** 343 windows of RST+ACK traffic
flowing `192.168.50.4 → 172.16.0.5` (14:29:16–14:37:16 UTC, median 10,912 pkt/s,
`rst/s = ack/s = 10,958`, `syn/s = 0`) sit in the *benign test set* of all six
`attacker_side/` slices, against a remaining-benign maximum of 20 pkt/s. They
are the victim answering the SYN flood; the label lookup keys on the packet's
own direction and the CSVs list only attacker→victim flows, so they read as
benign. Alarming on them is not a false alarm.

Removing them leaves every DR identical and collapses the column:

| model | FPR as shipped | FPR without backscatter |
|---|---:|---:|
| Ours (Ensemble) | 11.2 | **2.1** |
| Ours (no AnEWMA path) | 5.0 | 2.0 |
| AnEWMA | 9.7 | 0.3 |
| Adaptive Entropy | 3.5 | 0.3 |
| SPOT / EVT | 3.6 | 0.5 |

No ranking inverts, and the **5 floods** column — the one the headline rests on
— is unaffected, because the victim slices carry no backscatter (max benign 258
pkt/s). This is the same direction-blindness that put the attacker into
CIC-IDS-2017's benign pool: one mechanism, two corpora, two different symptoms.

| model | all 12 slices | **5 floods** | 7 non-floods |
|---|---|---|---|
| Ours (Ensemble) | 38.7 / 11.2 | 43.0 / 0.6 | 35.6 / 18.8 |
| Ours (no AnEWMA path) | 34.6 / 5.0 | **35.9 / 0.6** | 33.7 / 8.2 |
| **AnEWMA** | 23.8 / 9.7 | **42.7 / 0.3** | 10.3 / 16.5 |
| Adaptive Entropy | 21.6 / 3.5 | 39.0 / 0.5 | 9.2 / 5.6 |
| SPOT / EVT | 29.8 / 3.6 | 34.6 / 0.2 | 26.4 / 6.0 |
| MCP-TS | 18.5 / 4.1 | 28.2 / 0.3 | 11.5 / 6.8 |
| PEWMA | 12.7 / 3.4 | 21.6 / 0.3 | 6.4 / 5.6 |

**On the genuine floods our method loses.** AnEWMA reaches 42.7% DR at 0.3% FPR
against our 35.9% at 0.6% — **−6.8 pp at double the false-alarm rate**. The
all-12 column, which appears to show us ahead of SPOT (34.6 vs 29.8), is an
average dominated by seven scenarios that contain no flood.

Per-scenario on the five floods:

| attack | n | ours (ablated) | SPOT |
|---|---:|---|---|
| Syn | 6272 | 9.6 / 1.3 | 7.8 / 0.2 |
| MSSQL | 1861 | 0.0 / 0.0 | 0.0 / 0.0 (floor-limited) |
| UDP | 831 | 88.7 / 1.0 | 78.1 / 0.6 |
| LDAP | 593 | 81.1 / 0.6 | 87.0 / 0.3 |
| NetBIOS | 560 | 0.0 / 0.0 | 0.0 / 0.0 (floor-limited) |

Syn at 9.6% is the striking case: 6,272 attack windows at p95 27,314 pkt/s, and
almost nothing detected at α=0.01.

## Not included

The **01-12 day** (1 December 2018) holds twelve further attacks — NTP, DNS,
LDAP, MSSQL, NetBIOS, SNMP, SSDP, UDP, UDP-Lag, WebDDoS, SYN, TFTP — in four
unextracted zips (22 GB) under `../`. Its CSVs use a `DrDoS_` prefix and its
victim is 192.168.50.1, so slices from it must be day-qualified: several attack
names recur across both days with different victims and times.
