# Scenario inventory — what is evaluable, and why the rest is not

**Generated** by `ComparisonResults/extraction/build_scenario_inventory.py` from each
corpus's `index.json`. Do not hand-edit — re-run it after any regeneration or
re-classification. The tables are read from the tree at generation time; the caveat
figures are fixed in the script, apart from the `syn_flood` ratio and candidate counts.

**16 usable of 31 scenarios**, across 5 distinct victims.

Verdicts come from `classify_scenarios.py`, which applies four independent checks and records
all of them per file: traffic **direction**, **separability**, the **conformal floor**, and
whether an FPR is **measurable** at all.


---

## The evaluable set

| corpus | scenario | victim | n_attack | n_benign | n_calib | n_test_benign | split |
|---|---|---|---:|---:|---:|---:|---|
| CIC-IDS-2017 | `Fri-07-07_DDoS-LOIT` | `192.168.10.50` | 1136 | 4086 | 1550 | 212 | within |
| CIC-IDS-2017 | `Wed-05-07_DoS-GoldenEye` | `192.168.10.50` | 422 | 3067 | 255 | 2430 | within |
| CIC-IDS-2017 | `Wed-05-07_DoS-Hulk` | `192.168.10.50` | 463 | 3067 | 212 | 2539 | within |
| CIC-IDS-2017 | `Wed-05-07_DoS-Slowhttptest` | `192.168.10.50` | 788 | 3067 | 179 | 2620 | within |
| CIC-IDS-2017 | `Wed-05-07_DoS-Slowloris` | `192.168.10.50` | 1267 | 3067 | 171 | 2640 | within |
| CSE-CIC-IDS2018 | `Fri-16-02_DoS-Hulk` | `172.31.69.25` | 844 | 1469 | 348 | 599 | within |
| CSE-CIC-IDS2018 | `Fri-16-02_DoS-SlowHTTPTest` | `172.31.69.25` | 3189 | 1469 | 158 | 1075 | within |
| CSE-CIC-IDS2018 | `Thu-15-02_DoS-Slowloris` | `172.31.69.25` | 2392 | 1273 | 149 | 902 | within |
| CSE-CIC-IDS2018 | `Tue-20-02_DDoS-LOIC-HTTP` | `172.31.69.25` | 3779 | 567 | 106 | 304 | within |
| CSE-CIC-IDS2018 | `Wed-21-02_DDoS-HOIC` | `172.31.69.28` | 3298 | 2291 | 356 | 1401 | within |
| CSE-CIC-IDS2018 | `Wed-21-02_DDoS-LOIC-UDP` | `172.31.69.28` | 1101 | 2291 | 327 | 1475 | within |
| CIC-DDoS2019 | `cicddos_03-11_192-168-50-4_LDAP` | `192.168.50.4` | 593 | 3183 | 144 | 2825 | within |
| CIC-DDoS2019 | `cicddos_03-11_192-168-50-4_Syn` | `192.168.50.4` | 6272 | 3183 | 236 | 2594 | within |
| CIC-DDoS2019 | `cicddos_03-11_192-168-50-4_UDP` | `192.168.50.4` | 831 | 3183 | 197 | 2692 | within |
| CIC-DDoS2019 | `cicddos_03-11_192-168-50-4_UDPLag` | `192.168.50.4` | 472 | 3183 | 214 | 2649 | within |
| LITNET-2020 | `code_red_worm` | `193.219.81.138` | 345 | 3055 | 1097 | 313 | within |

### Not independent — shared victims and benign pools

Scenarios sharing a victim draw on the same benign windows. The causal split partitions
them differently, so their FPR rows are not identical, but it is the same traffic.
**A mean over them counts that benign sample more than once.** Aggregate per victim, or
deduplicate — and note that at the deduplicated n the minimum attainable Wilcoxon p may
sit above a Bonferroni-corrected alpha, which is a power floor, not evidence of absence.

- **CIC-IDS-2017** `192.168.10.50` carries 5: `Fri-07-07_DDoS-LOIT`, `Wed-05-07_DoS-GoldenEye`, `Wed-05-07_DoS-Hulk`, `Wed-05-07_DoS-Slowhttptest`, `Wed-05-07_DoS-Slowloris`
- **CSE-CIC-IDS2018** `172.31.69.25` carries 4: `Fri-16-02_DoS-Hulk`, `Fri-16-02_DoS-SlowHTTPTest`, `Thu-15-02_DoS-Slowloris`, `Tue-20-02_DDoS-LOIC-HTTP`
- **CIC-DDoS2019** `192.168.50.4` carries 4: `cicddos_03-11_192-168-50-4_LDAP`, `cicddos_03-11_192-168-50-4_Syn`, `cicddos_03-11_192-168-50-4_UDP`, `cicddos_03-11_192-168-50-4_UDPLag`
- **CSE-CIC-IDS2018** `172.31.69.28` carries 2: `Wed-21-02_DDoS-HOIC`, `Wed-21-02_DDoS-LOIC-UDP`

So the 16 scenarios represent **5 distinct victims**.

---

## Why the rest is not evaluable

Grouped by corpus so each block can be lifted into that corpus's dataset section.


### CIC-IDS-2017 — 2 excluded

**NOT-DDOS** (2) — not a denial-of-service attack, so out of scope for a DDoS panel.

- `Fri-07-07_PortScan` — victim `192.168.10.50`, 426 attack windows (n_calib=1030, p_floor=0.00097, n_test_benign=1512, atk/ben p95=12.21x, AUC=0.9518)
- `Wed-05-07_Heartbleed` — victim `192.168.10.51`, 1180 attack windows (n_calib=3741, p_floor=0.000267, n_test_benign=1644, atk/ben p95=0.7x, AUC=0.9718)


### CSE-CIC-IDS2018 — 2 excluded

**FLOOR-LIMITED** (1) — split-conformal p-values cannot go below `1/(n_calib+1)`; where that exceeds alpha no detector can fire and every method reads 0.0% by arithmetic.

- `Thu-15-02_DoS-GoldenEye` — victim `172.31.69.25`, 917 attack windows (n_calib=89, p_floor=0.011111, n_test_benign=1052, atk/ben p95=242.7x, AUC=0.9395)

**NO-FPR** (1) — the attack runs to the end of the capture, so no benign traffic follows its onset; `n_test_benign = 0` and the false-positive rate is **undefined, not zero**.

- `Tue-20-02_DDoS-LOIC-UDP` — victim `172.31.69.25`, 905 attack windows (n_calib=227, p_floor=0.004386, n_test_benign=0, atk/ben p95=16686.67x, AUC=0.9974)


### CIC-DDoS2019 — 8 excluded

**ATTACKER-SIDE** (6) — the labelled host is the attack **source**, established from the corpus CSVs' own direction counts, not from a heuristic.

- `cicddos_03-11_172-16-0-5_LDAP` — victim `172.16.0.5`, 146 attack windows (n_calib=478, p_floor=0.002088, n_test_benign=6535, atk/ben p95=1.0x, AUC=0.8959)
- `cicddos_03-11_172-16-0-5_MSSQL` — victim `172.16.0.5`, 410 attack windows (n_calib=674, p_floor=0.001481, n_test_benign=6045, atk/ben p95=1.17x, AUC=0.9203)
- `cicddos_03-11_172-16-0-5_NetBIOS` — victim `172.16.0.5`, 91 attack windows (n_calib=166, p_floor=0.005988, n_test_benign=7315, atk/ben p95=1.17x, AUC=0.923)
- `cicddos_03-11_172-16-0-5_Syn` — victim `172.16.0.5`, 5744 attack windows (n_calib=1413, p_floor=0.000707, n_test_benign=4199, atk/ben p95=1.33x, AUC=0.9217)
- `cicddos_03-11_172-16-0-5_UDP` — victim `172.16.0.5`, 112 attack windows (n_calib=905, p_floor=0.001104, n_test_benign=5469, atk/ben p95=1.0x, AUC=0.9144)
- `cicddos_03-11_172-16-0-5_UDPLag` — victim `172.16.0.5`, 224 attack windows (n_calib=1268, p_floor=0.000788, n_test_benign=4562, atk/ben p95=1.17x, AUC=0.9229)

**FLOOR-LIMITED** (2) — split-conformal p-values cannot go below `1/(n_calib+1)`; where that exceeds alpha no detector can fire and every method reads 0.0% by arithmetic.

- `cicddos_03-11_192-168-50-4_MSSQL` — victim `192.168.50.4`, 1861 attack windows (n_calib=81, p_floor=0.012195, n_test_benign=2981, atk/ben p95=6407.5x, AUC=0.9859)
- `cicddos_03-11_192-168-50-4_NetBIOS` — victim `192.168.50.4`, 560 attack windows (n_calib=94, p_floor=0.010526, n_test_benign=2948, atk/ben p95=4089.82x, AUC=0.9587)


### LITNET-2020 — 3 excluded

**FLOOR-LIMITED** (1) — split-conformal p-values cannot go below `1/(n_calib+1)`; where that exceeds alpha no detector can fire and every method reads 0.0% by arithmetic.

- `udp_f` — victim `193.219.81.137`, 301 attack windows (n_calib=0, p_floor=1.0, n_test_benign=0, atk/ben p95=3.29x, AUC=0.9974)

**INSEPARABLE** (1) — on every feature the screen measures, the attack traffic is statistically indistinguishable from the same host's own benign traffic: no feature reaches rank-AUC 0.75 with 20% detection at a 5%-FPR threshold.

- `http_flood` — victim `23.32.104.60`, 360 attack windows (n_calib=462, p_floor=0.00216, n_test_benign=526, atk/ben p95=1.1x, AUC=0.5701)

**NO-FPR** (1) — the attack runs to the end of the capture, so no benign traffic follows its onset; `n_test_benign = 0` and the false-positive rate is **undefined, not zero**.

- `smurf` — victim `193.219.88.36`, 299 attack windows (n_calib=1131, p_floor=0.000883, n_test_benign=0, atk/ben p95=117.25x, AUC=1.0)


---

## Caveats that must travel with the numbers

From the extraction audit. These are not optional context: each
changes how a figure from that corpus should be read.


### CIC-IDS-2017

- Labels are a per-flow **5-tuple CSV join**, not a schedule; the published schedule is used only to separate one attack from another within a day.
- A 180 s **guard band** quarantines benign windows adjacent to any labelled attack span (edge bands only, never the span interior). `n_benign_quarantined` is recorded per scenario.
- All five usable scenarios share victim `192.168.10.50`; its four Wednesday slices share one benign pool. **A mean over them counts that benign sample more than once.**

### CSE-CIC-IDS2018

- The CSVs are IP-sanitized, so `_is_attack` comes from the published attack **schedule**, not from a per-flow join. This is the weakest labelling of the three CIC corpora.
- A 180 s **guard band** is applied for the same reason as CIC-IDS-2017: the schedule minute is not the attack edge, and traffic outside it was reaching the calibration set.
- Same-day slices share that day's benign pool; each day's two scenarios are not independent.
- Positives are **diluted**: the schedule labels every window inside a documented span, including windows whose traffic looks like background; 258 of 917 GoldenEye and 69 of 844 Hulk attack windows sit at or below the slice's highest benign packet rate. This bias is CONSERVATIVE — it understates DR.

### CIC-DDoS2019

- Labels are the dataset's own per-flow CSV labels. **No schedule and no timezone derivation** are used anywhere in this corpus.
- `_attack_type` is the **dominant** label in a window. Read a slice's span as "windows this label won", not as "when this attack ran".
- All six victim scenarios share one 3,183-window benign pool.
- `Portmap` is absent by design: it starts at capture open, leaving `n_pre_benign` of 1 on the victim and 11 on `172.16.0.5`, below the gate of 30. Only the 03-11 day is extracted; 01-12 ships CSVs but no scenarios.

### LITNET-2020

- The only corpus built from **flow records rather than packets**. Rows carry **15 feature columns against the packet corpora's 40**: 26 of those 40 are structurally absent, among them all 13 TCP-flag-derived features and both entropy features, and one column, `unique_dst_ips`, exists only here.
- Built from the complete 26.9 GB `allFlows.csv`. A truncated export of that file, which loses `udp_f` entirely, was once the pipeline default; any number computed from it is suspect. Both deposited subnet records, `litnet_l1subnet_16_results.json` and `litnet_l1subnet_24_results.json` in `ComparisonResults/results/`, were scored on it and were not re-run.
- `syn_flood` is the corpus's largest attack — **701,483 attack windows over 17,174 destination hosts**, 15,873 of them above the 30-window gate at **mean 42.7 / median 42 windows each (maximum 175)**, counted on the complete-export per-IP cache; no deposited record holds this census — and it ships no scenario: it is distributed, and `export_litnet_scenarios.py` builds one scenario per concentrated attack family from a hand-written victim list. The exclusion happens at that step, *before* the four admissibility checks, so it carries **no verdict** and appears in no census row, despite being 17.2x the 40,728 attack windows of the entire 31-scenario candidate set. (An earlier revision printed "~175 windows each"; 175 is the maximum of the per-host distribution, not its typical value.) Its behaviour under subnet aggregation is described in the LITNET-2020 README, from caches and records built on the truncated export.
- The four scenarios have four different victims, so unlike the other corpora they do not share a benign pool with each other.

---

## Verifying this file

```bash
python3 ComparisonResults/extraction/build_scenario_inventory.py   # regenerate
python3 ComparisonResults/extraction/verify_extracted_tree.py      # data vs itself
python3 ComparisonResults/extraction/verify_readme_claims.py       # prose vs data
```
