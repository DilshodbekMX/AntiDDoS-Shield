# LITNET-2020 — per-attack scenario caches

**Four** scenarios, one per concentrated attack. Produced by
`AntiDDOS_Shield/experiments_copy/export_litnet_scenarios.py`, from caches
rebuilt by `rebuild_litnet_caches.py` against the complete `allFlows.csv` — an
earlier extraction was 11.5% short and lost two attack types entirely.
No schedule was needed: `litnet_loader.py` already records `_attack_type` per
window from the corpus's own flow labels, so this is selection only.

`index.json` and `SHA256SUMS` are written by `write_extracted_index.py`. Verify
with `sha256sum -c SHA256SUMS` run **from this directory**.

## Only one is usable

| attack | victim | n_attack | ratio to own benign p95 | n_calib | n_test_benign | verdict |
|---|---|---:|---:|---:|---:|---|
| `code_red_worm.json` | 193.219.81.138 | 345 | **779.1×** | 1097 | 313 | **usable** |
| `smurf.json` | 193.219.88.36 | 299 | 117.3× | 1131 | **0** | volumetric, **FPR undefined** |
| `udp_f.json` | 193.219.81.137 | 301 | 3.3× | **0** | 0 | volumetric, **floor-limited** |
| `http_flood.json` | 23.32.104.60 | 360 | **1.1×** | 462 | 526 | **indistinguishable** |

**smurf** has `n_test_benign = 0` — the attack runs to the end of the capture, so
no benign traffic follows its onset. Its detection rate is valid; its
false-positive rate is **undefined, not zero**. Same failure mode as
CIC-IDS-2018 Tuesday LOIC-UDP.

**udp_f** is the mirror image, and it is the corpus's fourth-largest attack
(93,583 flows). It was absent from every cache until the rebuild; recovering it
did not make it usable. The attack occupies the *opening* minutes of this host's
record, so nothing benign precedes it: `n_calib = 0`, the conformal floor is 1,
and no detector can fire at any α. Both boundary failures are properties of
where the capture happens to start and stop, not of the attacks themselves.

**http_flood** carries 360 attack windows whose traffic is 1.1× the same host's
benign p95 — statistically the same traffic. It is in the manuscript's panel at
1.9% DR / 31.4% FPR; that pairing is a property of the data, not the detector.

## syn_flood is absent, and that is the interesting part

Five attack types have any host with ≥ 30 attack windows:

```
http_flood         1 host     360 windows
code_red_worm      1 host     345
udp_f              1 host     301
smurf              1 host     299
syn_flood     15,335 hosts    ~43 each (median 42, max 175)
```

(An earlier revision of this block listed four and omitted `udp_f`, contradicting
the scenario table above, which records it at 301 windows on 193.219.81.137. Four
families materialise a scenario; `syn_flood` is the fifth family clearing the gate
and the only one that materialises none. Anything downstream saying LITNET has
"three other families" inherited the short list.)

**Read that last row carefully.** `syn_flood` covers **678,911 attack windows over
16,509 destination hosts**; 15,335 of those clear the 30-window gate, and across
that gated set the per-host count is **mean 42.9, median 42, maximum 175**. An
earlier revision of this file printed **175** as the per-host figure. That is the
*maximum* of the distribution, read off the top of the ranked victim list, not the
typical value; 678,911 / 16,509 = 41.1 and 657,384 / 15,335 = 42.9 both corroborate
the corrected number. Anything downstream that quotes "175 windows each" inherited
the maximum and is wrong.

`syn_flood` is by far the corpus's largest attack and has never appeared in the
panel, because it is **distributed** — the carpet-bomb case. The extraction step
builds one scenario per attack family on the single busiest host, and this
family's busiest host carries 175 windows against 360, 345, 301 and 299 for the four
that did materialise, so it ships no scenario. Note what that means for any
admissibility ledger built on this tree: the exclusion happens at
**materialisation**, before the admissibility checks run, so `syn_flood` carries
**no verdict** and appears in no census row — even though its 678,911 windows are
4.3× the 158,725 attack windows of the whole 44-scenario candidate set. It is the
largest single exclusion in the study and it is not adjudicated by the protocol.

Aggregating does not recover it. At `/24` the attack is **quieter than the
zone's own benign traffic**: p95 1,060 against 51,370 packets/s, a ratio of
**0.02×**. At `/16`, 0.3–0.5×.

That was checked across **all 13 features this corpus has**, not just volume,
in case composition carried the signal where packet rate did not. It does not —
the most discriminative feature is `icmp_ratio` at 1.6×, still under the 2× bar:

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

This does not contradict the manuscript's subnet-aggregation result, which
reports 83.80% of attack zone-seconds recovered — at **54.57% FPR**. Both say
the same thing: recovery at this dilution is bought at a false-alarm rate that
is not deployable.

## LITNET has 13 features, not 39

This is the only corpus built from **flow records** rather than packets, so its
windows carry 13 keys where the pcap corpora carry 39:

```
packets_per_sec  bytes_per_sec  flows_per_sec  tcp_ratio  udp_ratio  icmp_ratio
unique_dst_ports  unique_dst_ips  unique_src_ips  dst_port_density
flow_duration_avg  dir_ratio  ttl_mean
```

**All eight TCP-flag features are structurally absent** — `syn_per_sec`,
`syn_ack_per_sec`, `ack_per_sec`, `rst_per_sec`, `fin_per_sec`,
`syn_ack_ratio`, `rst_syn_ratio`, `tcp_completion_rate` appear nowhere in any
LITNET artifact in this tree. An earlier revision of this file described the
syn_flood sweep as covering "all 39 features … in case flag composition carried
the signal", which was not possible: 26 of the 39 names do not exist here, and
the flag composition it invoked is exactly what a flow-record export does not
record. The sweep itself is real and reproduces — it is a 13-feature sweep that
was labelled 39.

One consequence worth knowing before using `http_flood`: 8 of its 13 features
are constant across all 2,040 windows, and because `unique_dst_ports` is 1.0
everywhere, `dst_port_density` is the exact reciprocal `1000/packets_per_sec` in
every row. Four non-redundant signals remain, separated by 1.07–1.10×.

## Caveat shared with the other corpora

All four scenarios draw benign windows from their own host, so they do not
share a pool with each other — unlike the CIC-IoT and CIC-IDS sets. But each
uses that host's *entire* benign history rather than only pre-attack windows, so
the causal split's calibration slice may sit after an earlier attack on the same
host. For these four victims no earlier attack of a different type is present,
so the point is moot here; it would matter if more LITNET victims were added.

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
