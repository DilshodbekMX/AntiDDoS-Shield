# LITNET-2020 — per-attack scenario caches

**Four** scenarios, one per concentrated attack. Produced by
`ComparisonResults/extraction/export_litnet_scenarios.py` from the per-IP cache
that `rebuild_litnet_caches.py` builds from the complete `allFlows.csv` — an
earlier extraction was 11.5% short and lost two attack types entirely.
No schedule was needed: `litnet_loader.py` already records `_attack_type` per
window from the corpus's own flow labels, so this is selection only.

The export scripts (`export_litnet_scenarios.py` for the scenarios,
`export_benign_pools.py` for the pool) read that cache from
`ComparisonResults/cache/litnet_per_ip_cache.json`, a path neither lets you
change. A LITNET rebuild therefore needs the complete per-host cache from
`ComparisonResults/extraction/rebuild_litnet_caches.py`, which writes that path
by default (`--out` moves the rebuild's output, but the export scripts still
read the fixed path). The deposit no longer tracks the symbolic link that stood
there; on the authors' machine it pointed at a cache built from an incomplete
export, one with no `udp_f` windows.

`index.json` and `SHA256SUMS` are written by `write_extracted_index.py`. To
verify a rebuilt tree, run `sha256sum -c` against this directory's `SHA256SUMS`
(four entries, one per scenario) from inside `datasets/extracted/LITNET-2020/`,
and against `benign_pools/SHA256SUMS` (the per-IP pool and its `.meta.json`, two
entries) from inside its `benign_pools/`.

## Only one is usable

| attack | victim | n_attack | ratio to own benign p95 | n_calib | n_test_benign | verdict |
|---|---|---:|---:|---:|---:|---|
| `code_red_worm.json` | 193.219.81.138 | 345 | **779.14×** | 1097 | 313 | **usable** |
| `smurf.json` | 193.219.88.36 | 299 | 117.25× | 1131 | **0** | volumetric, **FPR undefined** |
| `udp_f.json` | 193.219.81.137 | 301 | 3.29× | **0** | 0 | volumetric, **floor-limited** |
| `http_flood.json` | 23.32.104.60 | 360 | **1.10×** | 462 | 526 | **indistinguishable** |

**smurf** has `n_test_benign = 0` — the attack runs to the end of the capture, so
no benign traffic follows its onset. Its detection rate is valid; its
false-positive rate is **undefined, not zero**. Same failure mode as
CIC-IDS-2018 Tuesday LOIC-UDP.

**udp_f** is the mirror image, and it is the corpus's fourth-largest attack
(93,583 flows). It was absent from every cache until the rebuild; recovering it
did not make it usable. The attack occupies the *opening* minutes of this host's
record, so nothing benign precedes it (all 2,406 of its benign windows follow
it): `n_calib = 0`, the conformal floor is 1, and no detector can fire at any α.
Both boundary failures are properties of where the capture happens to start and
stop, not of the attacks themselves. The `udp_f` entry's `fpr_note` in
`index.json` was corrected by hand to say this. The payload's own
`metadata.fpr_note` still reads "attack runs to capture end", the text
`export_litnet_scenarios.py` writes for every scenario without test-benign
windows, and `write_extracted_index.py` copies the payload's note back into the
index on a rebuild.

**http_flood** carries 360 attack windows whose packet rate is 1.10× the same
host's benign p95. On the screen's per-feature tests it is statistically the
same traffic as the host's benign windows: its best feature, `packets_per_sec`,
detects 8.3% at 5% false alarms with AUC 0.5701 (`best_feature`,
`best_dr_at_5pct_fpr`, `best_auc`), and `index.json` gives it the verdict
`INSEPARABLE`. The earlier full-tree sweep,
`ComparisonResults/results/full_tree_all_scenarios_metrics.json` (an undeposited
harness, run on an earlier version of this tree), scores the ensemble on this
file at 0.0% DR and 8.8% FPR, AUC 0.40. The verdict is a property of this
screen: under the engine's rule set, with a 60/20/20 per-host benign split
(`metadata.methodology`),
`ComparisonResults/results/rescued/litnet_results_COMPLETE_EXPORT.json` detects
359 of its 360 attack windows (`per_attack_type.http_flood`), 99.7% at a
calibrated θ of 7.5 against 11.9% false alarms on 336 benign windows
(`top_victims`). That record has no deposited writer, and the two runs are not
like for like, so the screen's verdict may still be right for its own scorer.

## syn_flood is absent, and that is the interesting part

Five attack types have any host with ≥ 30 attack windows:

```
http_flood         1 host     360 windows
code_red_worm      1 host     345
udp_f              2 hosts    301 (193.219.81.137), 64 (193.219.81.138)
smurf              1 host     299
syn_flood     15,873 hosts    ~43 each (median 42, max 175)
```

(An earlier revision of this block listed four and omitted `udp_f`, contradicting
the scenario table above, which records it at 301 windows on 193.219.81.137. Four
families materialize a scenario; `syn_flood` is the fifth family clearing the gate
and the only one that materializes none. Anything downstream saying LITNET has
"three other families" inherited the short list.)

**Read that last row carefully.** `syn_flood` covers **701,483 attack windows over
17,174 destination hosts**; 15,873 of those clear the 30-window gate, and across
that gated set the per-host count is **mean 42.7, median 42, maximum 175**. An
earlier revision of this file printed **175** as the per-host figure. That is the
*maximum* of the distribution, read off the top of the ranked victim list, not the
typical value; 701,483 / 17,174 = 40.8 and 677,300 / 15,873 = 42.7 both corroborate
the corrected number. Anything downstream that quotes "175 windows each" inherited
the maximum and is wrong. These are the complete export's figures. No deposited
record holds this census, and the per-IP cache it was counted on is not
deposited.

`syn_flood` is by far the corpus's largest attack and has never appeared in the
panel, because it is **distributed** — the carpet-bomb case. The extraction step
builds one scenario per attack family on the single busiest host, and this
family's busiest host carries 175 windows against 360, 345, 301 and 299 for the four
that did materialize, so it ships no scenario. Note what that means for any
admissibility ledger built on this tree: the exclusion happens at
**materialization**, before the admissibility checks run, so `syn_flood` carries
**no verdict** and appears in no census row — even though its 701,483 windows are
17.2 times the 40,728 attack windows of the whole 31-candidate set. It
is the largest single exclusion in the study and it is not adjudicated by the
protocol.

Aggregating does not recover it. At `/24` the attack is **quieter than the
zone's own benign traffic**: p95 1,060 against 51,370 packets/s, a ratio of
**0.02×**. At `/16`, 0.3–0.5×. The `/24` and `/16` caches behind this
comparison, and the two subnet records cited below, were built from the
truncated export, not the complete file the scenarios above come from (see
`ComparisonResults/README.md`, 'LITNET-2020 records and their input'); do not
compare their figures with the complete-export census.

That was checked across **all 13 features this corpus had** when the check was
run, before `burst_factor` and `unique_flows` were added, not just volume, in
case composition carried the signal where packet rate did not. It does not: the
most discriminative feature is `icmp_ratio` at 1.6×, still under the 2× bar:

| feature | attack p95 | benign p95 | ratio |
|---|---:|---:|---:|
| icmp_ratio | 0.02 | 0.01 | 1.6× |
| dst_port_density | 165.08 | 144.22 | 1.1× |
| tcp_ratio | 0.94 | 1.00 | 0.9× |
| flows_per_sec | 101.00 | 530.40 | 0.2× |
| packets_per_sec | 1,060 | 51,370 | 0.02× |
| bytes_per_sec | 270,220 | 64,845,302 | 0.004× |

So the dilution is complete at every aggregation scale available in these
caches. This is direct evidence for the carpet-bomb argument, from the harder
direction: the attack is not merely *hard* to detect per host, it is *below
background* at subnet scale too.

This does not contradict the subnet-aggregation record, also from the truncated
export, `ComparisonResults/results/litnet_l1subnet_24_results.json`, in which the
engine's rule set detects 88.3% of `syn_flood`'s `/24` windows
(`per_attack_type.syn_flood.dr`), at **56.6% false alarms** on uninvolved
`/24` subnets (`split_metrics.fpr_on_uninvolved_pct`; 88.2% and 56.4% before the
record was re-run with the two engine columns); at `/16`
(`litnet_l1subnet_16_results.json`) no uninvolved subnet remains to measure a
false-alarm rate on. Both say the same thing: recovery at this dilution is
bought at a false-alarm rate that is not deployable.

## LITNET has 15 features, not 40

This is the only corpus built from **flow records** rather than packets, so its
windows carry 15 feature keys where the packet-capture slices in this tree
carry 40:

```
packets_per_sec  bytes_per_sec  flows_per_sec  tcp_ratio  udp_ratio  icmp_ratio
unique_dst_ports  unique_dst_ips  unique_src_ips  dst_port_density
flow_duration_avg  dir_ratio  ttl_mean  unique_flows  burst_factor
```

The last two are the engine columns computed from the flow records (the tree's
README defines them); `unique_flows` counts a window's distinct (source
address, protocol) pairs, and `packets_per_sec`, the input of `burst_factor`,
counts both directions of the records that start in the window. Thirteen of the
15 are names the shipped engine scores; `unique_dst_ips` and `dir_ratio` are not.

**All eight TCP-flag features are structurally absent**: `syn_per_sec`,
`syn_ack_per_sec`, `ack_per_sec`, `rst_per_sec`, `fin_per_sec`,
`syn_ack_ratio`, `rst_syn_ratio`, `tcp_completion_rate` appear nowhere in any
LITNET artifact in this tree. An earlier revision of this file described the
syn_flood sweep as covering "all 39 features … in case flag composition carried
the signal", which was not possible: 26 of the 40 packet-capture feature names
(26 of 38 at the time) do not exist here, and the flag composition it invoked is
exactly what a flow-record export does not record. The sweep itself is real and
reproduces: it is a 13-feature sweep that was labelled 39.

One consequence worth knowing before using `http_flood`: 9 of its 15 features
are constant across all 2,040 windows, `unique_flows` among them (it equals
`unique_src_ips`, 1, on every row), and because `unique_dst_ports` is 1.0
everywhere, `dst_port_density` is the exact reciprocal `1000/packets_per_sec` in
every row. Five non-redundant signals remain; their attack-to-benign p95
ratios are 1.07 to 1.10× for the three rate features, 0.90× for
`flow_duration_avg` and 0.51× for `burst_factor`.

## Caveat shared with the other corpora

All four scenarios draw benign windows from their own host, so they do not
share a pool with each other — unlike the CIC-IDS-2017, CSE-CIC-IDS2018 and
CIC-DDoS2019 sets. But each
uses that host's *entire* benign history rather than only pre-attack windows, so
the causal split's calibration slice may sit after an earlier attack on the same
host. Three of the four victims carry no other attack type. The fourth,
`code_red_worm`'s 193.219.81.138, also carries 64 `udp_f` attack windows
(2019-03-06 21:14:00–21:16:04 UTC), more than ten months before the worm; the
slice drops them, and the 237 benign windows around them (all on 2019-03-06)
are the host's earliest, so they fall in the fit portion of the causal split
(the first 1,645 of 2,742 pre-attack benign windows), not its calibration
slice. The point would matter more if further LITNET victims were added.

## The benign pool, and why it needed a role filter

`benign_pools/benign_pool_per_ip.json` has been rebuilt from the complete
`allFlows.csv` and role-filtered: **956 hosts, 414,702 windows.**

The role filter is the part worth knowing about. Membership used to rest on
`_is_attack` alone, and `litnet_loader` assigns that by aggregating over the
**destination** — so a host that only ever *sources* attack traffic accumulates
zero attack windows and qualifies as attack-free. Nine did.

The clearest case is `193.219.86.241`, which sources all 747 `smtp_b` flows in
the corpus. Every one of them is aimed at an external mail server (Yahoo's
`67.195.*`, `98.136.*`, `188.125.*`) outside the `193.219.*` / `83.171.*`
prefixes this pool is scoped to, so it never appeared as a victim anywhere and
nothing in the destination-side label could have caught it. The other eight each
source one or two `tcp_red_w` flows out of 1,255,702 corpus-wide.

All nine are now excluded on role and listed in the pool's `.meta.json`. They
were 5,211 of 419,913 windows — 1.2% of the false-alarm denominator — and they
were *not* concentrated at the loud end: the `smtp_b` source ranked 443rd of 965
by peak packet rate, against a pool whose loudest host peaks at 971,910 pkt/s.
Two of the eight worm-flow hosts did rank 39th and 98th, so excluding them
removes loud-but-benign windows; that moves a measured false-alarm rate in the
flattering direction, which is why the exclusion list ships with the pool.
