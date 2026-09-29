# CIC-IoT-2023 — per-family scenario caches

Thirteen self-contained scenarios, one per attack family, each holding a single
victim's benign and attack windows. Produced by
`AntiDDOS_Shield/experiments_copy/export_cicios2023_scenarios.py`.

Verify with `sha256sum -c SHA256SUMS`. Provenance and every measurement below
are in `index.json`, per scenario.

## How this differs from the other corpora

The CIC-IDS-2017/2018 and CIC-DDoS2019 sets required *splitting*: one cache held
several attacks. CIC-IoT is the reverse — each family already has its own
capture and cache, but a cache holds every destination in the testbed, and a
scenario is one victim. So the work here is selection and materialisation.

Benign comes from a **separate benign capture**, not from before the attack in
the same capture. The train/calibration set is therefore not temporally adjacent
to the attack, and FPR is measured inside the benign capture. That is a
different protocol from the within-day splits used elsewhere and the numbers are
not directly comparable to them.

## Victim selection — and why the obvious rule is wrong

`cicios2023_extractor.py:107-112` applies a **directory-derived** label: every
window of a family capture is marked attack, regardless of which host it belongs
to. `_is_attack` here means *"captured during this attack"*, not *"this window
contains attack traffic"*.

Ranking candidates by attack-window count therefore selects whichever host
merely appears most often — `8.8.8.8` shows up as an "attack victim" in all 13
families with up to 25,692 windows, as do AWS and GCP addresses.

The rule used instead: the testbed device in `192.168.137.0/24`, excluding the
gateway `.1`, with the most attack windows, clearing the split gates and a
max-rate floor. It reproduces all five of the manuscript's hand-picked victims
exactly, and matches the gate implemented independently at
`run_crosscorpus_auc.py:315`.

## Intensity — read this before using any file

The victim rule is necessary but **not sufficient**. Three families select a
host whose attack traffic never rises above its own normal traffic. Classified
by attack p95 packets/s against the *same host's* benign p95:

| family | victim | atk p95 | ben p95 | ratio | class | DR / FPR |
|---|---|---:|---:|---:|---|---|
| DDoS-TCP_Flood | .99 | 20,200 | 3 | 6733× | volumetric | 50.4 / 1.1 |
| DDoS-UDP_Flood | .99 | 19,910 | 3 | 6638× | volumetric | 45.4 / 1.1 |
| DDoS-SynonymousIP_Flood | .90 | 23,989 | 4 | 5997× | volumetric | 100.0 / 2.7 |
| DDoS-SYN_Flood | .99 | 14,277 | 3 | 4761× | volumetric | 45.7 / 1.1 |
| Mirai-udpplain | .209 | 2,032 | 1 | 2035× | volumetric | 73.6 / 0.6 |
| DDoS-HTTP_Flood | .82 | 216 | 4 | 54× | volumetric | 93.9 / 0.5 |
| DDoS-ICMP_Flood | .139 | 44 | 1 | 44× | **low-rate, real** | 76.0 / 0.3 |
| DDoS-PSHACK_Flood | .186 | 450 | 15 | 30× | volumetric | 97.6 / 1.7 |
| DDoS-SlowLoris | .82 | 102 | 4 | 26× | volumetric | 48.7 / 0.5 |
| DDoS-UDP_Fragmentation | .187 | 24 | 10 | 2.4× | **low-rate, real** | 25.4 / 19.9 |
| DDoS-ICMP_Fragmentation | .41 | 14 | 13 | **1.1×** | **INDISTINCT** | 0.9 / 3.6 |
| DDoS-RSTFINFlood | .51 | 28 | 28 | **1.0×** | **INDISTINCT** | 62.8 / 2.2 |
| DDoS-ACK_Fragmentation | .51 | 15 | 28 | **0.5×** | **INDISTINCT** | 69.8 / 2.2 |

**8 volumetric, 2 low-rate, 3 indistinct.**

Two numbers are needed, not one. An absolute rate floor alone is wrong:
**DDoS-ICMP_Flood** sits at just 44 pkt/s but its host's benign p95 is 1.0, so
that is a genuine 44× elevation and a real attack. A flat threshold would have
discarded it. Conversely **DDoS-ACK_Fragmentation** carries 12,507 attack
windows yet its attack traffic is *quieter* than the same host's benign traffic
(0.5×).

## The separate-capture confound applies to the WHOLE corpus

An earlier revision of this file scoped the following concession to three
scenarios. **It applies to all thirteen**, and the reason is measurable rather
than a matter of caution.

Benign comes from one capture session, attacks from others. If the separation
the detector finds were the attack, it would track packet rate. It does not:

| scenario | victim | ttl benign | ttl attack | pps benign p95 | pps attack p95 |
|---|---|---:|---:|---:|---:|
| DDoS-RSTFINFlood | .51 | 112.0 | **140.8** | 28.0 | **28.0** |
| DDoS-ACK_Fragmentation | .51 | 112.0 | **200.1** | 28.0 | **15.0** |
| DDoS-ICMP_Fragmentation | .41 | 57.7 | 62.9 | 13.0 | 14.0 |
| DDoS-SYN_Flood | .99 | 43.0 | 122.0 | 3.0 | 14,277 |
| DDoS-TCP_Flood | .99 | 43.0 | 107.2 | 3.0 | 20,200 |
| DDoS-UDP_Flood | .99 | 43.0 | 94.5 | 3.0 | 19,910 |

The first two rows decide it. On RSTFINFlood the attack's packet rate is
**identical** to benign; on ACK_Fragmentation it is **lower** — yet `ttl_mean`
moves 29 and 88 units. There is no volumetric signal to detect and a large
separation exists anyway, so that separation is the recording. Note also that
the same host and the same benign capture yield three different attack TTLs
(.99: 122.0 / 107.2 / 94.5): TTL is a property of each session's peer set, and
it is production feature 38, inside the shipped detector's path.

**Treat `best_dr_at_5pct_fpr` here as a separability gate, not as evidence of
attack detection.** Where the rate signal is present — SYN 14,277, TCP 20,200,
UDP 19,910, SynonymousIP 23,989 pkt/s against a benign p95 of 3–4 — there is a
real attack underneath, and the confound sits on top of it. Where the rate
signal is absent, the confound is all there is.

**Calibration also postdates the attack in four of the six usable scenarios.**
The benign session starts 2022-10-07; attacks run 2022-08-16 to 2023-01-19. For
DDoS-TCP_Flood the benign capture is 52.0 days *after* the attack, SYN 42.0,
UDP 37.1, ICMP_Flood 31.1. An earlier revision said only "not temporally
adjacent" and gave neither magnitude nor sign.

The three indistinct scenarios still report high detection rates — 69.8% and
57.2%. Those measure discrimination between two capture sessions, not detection
of an attack, and must not be averaged into any DDoS mean.

**Seven of the thirteen are excluded on ROLE — but not as "attacker-side".**
An earlier revision reported those seven as confirmed attack sources on the
strength of an inbound-flag heuristic. **Checked against ground truth read from
the raw pcaps, that heuristic is inverted on this corpus**, and the scenarios
are now marked `ROLE-UNVERIFIED`: still excluded, because a role we cannot
establish cannot anchor a detection claim, but excluded for a reason the
evidence supports rather than one it contradicts.

Each family floods a different target per pcap file, so roles are unambiguous:

| family | confirmed TARGETS flagged | confirmed SOURCES flagged |
|---|---|---|
| RSTFINFlood | **15 of 16** | **0 of 10** — inverted |
| PSHACK_Flood | 15 of 16 | 7 of 7 — no discriminative power |
| ACK_Fragmentation | 5 of 13 flagged, 8 kept, split at the 4th decimal | |

`192.168.137.168` — 99.7% of the first 120k packets of `DDoS-RSTFINFlood10.pcap`
are RST+FIN destined **to** it — is condemned by the rule. RST+FIN provokes no
reply, so the actual sources never accumulate enough inbound windows to be
scored at all. On PSHACK, `.233` (ack 0.9992, 23,337 pkt/s) and `.120` (0.9998,
24,539 pkt/s) are *receiving* the flood and draw the same verdict this file once
reserved for "`.186`, the attacker's own console".

ACK_Fragmentation is the sharpest case: of 193,953 packets to target `.33` in
`DDoS-ACK_Fragmentation8.pcap`, 49.98% are first fragments carrying the TCP ACK
header and 50.01% are continuation fragments with none. The ack share is pinned
at 0.4999 ± 0.0005 **by IP fragmentation itself**, and the rule's `RESP_BAR` of
0.50 bisects that constant — the closest condemned/kept pair differs by 6.2e-5.

The rule works where a flood provokes a reply the victim sends back, which is
the SYN-flood case it was built for. It cannot work where the flood provokes
nothing. The original table follows, as the evidence the verdicts *were* drawn
from:

| scenario | host | inbound SYN share | DR @5% FPR | why excluded |
|---|---|---:|---:|---|
| DDoS-PSHACK_Flood | .186 | **0.0000** | 100.0 | attacker-side |
| DDoS-HTTP_Flood | .82 | **0.0000** | 93.3 | attacker-side |
| DDoS-SlowLoris | .82 | **0.0000** | 56.8 | attacker-side |
| DDoS-ACK_Fragmentation | .51 | **0.0000** | 69.8 | attacker-side + indistinct |
| DDoS-RSTFINFlood | .51 | **0.0000** | 57.2 | attacker-side + indistinct |
| DDoS-ICMP_Fragmentation | .41 | **0.0000** | 7.9 | attacker-side + indistinct |
| DDoS-UDP_Fragmentation | .187 | 0.0215 | 46.2 | attacker-side |

PSHACK on `.186` is the sharpest case: 100.0% DR against an inbound RST share of
1.0000. That is a detector scoring the attacker's own console. Compare the six
hosts that survive — `.99` reads an inbound SYN share of 0.9817 on SYN_Flood and
`.90` reads 0.9987 on SynonymousIP_Flood, which is what a flood target looks
like.

**Six of thirteen are usable**: ICMP_Flood (.139), SYN_Flood, TCP_Flood and
UDP_Flood (.99), SynonymousIP_Flood (.90) and Mirai-udpplain (.209).
`usable_as_ddos_scenario` in `index.json` reflects the combined verdict, and
`classify_scenarios.py` records the direction measurements per file.

Re-check any new slices with
`AntiDDOS_Shield/experiments_copy/check_scenario_intensity.py`.

## What is not here

The dataset documents **33 attacks in 7 categories**; only 14 have pcaps
locally, because `download_ddos.sh` fetched the DDoS subset. The rest —
DoS-\* (4), Recon-\* (4), Mirai-greeth/greip, MITM-ArpSpoofing, DNS_Spoofing,
web attacks, brute force — exist locally as **CSV only**, and the CSVs cannot be
used: they ship without IPs or timestamps, so no 5-tuple join to packets is
possible (`cicios2023_extractor.py` docstring).

They are downloadable. `download_pcap.sh` is a recursive fetcher over the
server's whole `PCAP/` tree and needs valid cookies
(`cicresearch.ca_cookies.txt` dates from June and is likely expired).

Of the missing families the four **DoS-\*** are the ones worth having: single-
source DoS against distributed DDoS is an axis this evaluation lacks entirely.
Recon, MITM and Spoofing are not denial-of-service and would only serve as
non-DDoS false-positive tests.
