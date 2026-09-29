# CESNET-TimeSeries24 — benign reference, not a scenario set

**This corpus contains no attacks and no label column.** It is 40 weeks of
unlabelled benign monitoring from the CESNET3 ISP network (275,000 IPs, 66
billion flows), built for forecasting and anomaly-detection research.

No detection rate can be computed from it. There is no per-attack split to make,
which is why this directory holds one file rather than a scenario per attack.

| | |
|---|---|
| hosts | 174 (of 1,000 in the sample — see *Which hosts*) |
| windows | 970,277 |
| **attack windows** | **0** |
| window unit | **hourly** per-IP aggregate |
| features | **11** (`*_per_sec` names hold hourly **counts** — see *Units*) |
| source | `ip_addresses_sample.tar.gz`, `agg_1_hour` |
| DOI | 10.5281/zenodo.13382427 |

## Units — the `_per_sec` names do not mean rates here

`data_loader.FEATURE_MAP` renames CESNET's `n_flows` / `n_packets` / `n_bytes`
to `flows_per_sec` / `packets_per_sec` / `bytes_per_sec` and **never divides by
the 3,600-second window**. On this corpus, and only this corpus, those shared
feature names carry a count per hour where every sibling corpus carries a true
rate. The hourly row is the exact sum of its six 10-minute siblings (checked,
200 of 200 hours, ratio 1.0000), so it is a count by construction.

Divide by 3,600 for true rates: the median 158.0 "packets_per_sec" is
0.0439 pkt/s, and the p95 of 213,662 is 59.35 pkt/s.

**No published false-alarm rate depends on this.** The z-path is scale-invariant
and the 13.1% figure is computed consistently throughout. Rescaling is not free
either — the variance floor mirrored from `baselines.c:356` tests the mean
against an *absolute* 50.0, so dividing moves hosts across it and shifts the
headline 13.08% → 12.89%. The names are corrected in `index.json`
(`packets_per_hour_median`, with a `*_per_sec_*_equivalent` beside it) rather
than the data rescaled, which leaves every published number intact.

## Which hosts — the continuity gate keeps 174 of 1,000

`MIN_IP_ROWS_PER_IP = 3000` drops **826 of the sample's 1,000 IPs (82.6%)**.

It is a *continuity* filter, not a busy-host filter: kept and dropped hosts
differ by 24× in temporal coverage (median 93.3% of the 6,718 time slots against
3.8%) but only 1.5× in per-window volume (median-of-host-medians 157.0 against
106.8 packets per hourly window).

Scoring every evaluable host rather than the kept 174 raises the shipped
fixed-θ false-alarm rate from **13.08%** [12.58, 13.63] to **13.90%**
[13.49, 14.32] over 921 hosts and 352,792 windows. The published figure is
0.82 pp *optimistic* — which is conservative for the anti-artifact argument it
supports, since a higher floor on real ISP telemetry strengthens that claim.

## What it is for

Measuring false alarms on **real backbone traffic with no synthetic generator
behind it** — something no lab capture can do.

That is its role in the manuscript (`jcp_paper.md` §6.3): the anti-artifact
control. The per-window false-alarm floor measured on CIC-IDS-2017 could be
dismissed as an artifact of that corpus's B-Profile traffic generator. CESNET is
real ISP telemetry, has no generator, and still floors — which is what rules the
artifact explanation out. The corpus earns its place precisely by having no
attacks in it.

## Its numbers are not comparable to the pcap corpora

Two properties, both recorded in `index.json` rather than left implicit:

**Granularity.** Hourly windows against per-second everywhere else. A detector
making one decision per second per destination makes 86,400 decisions per
address per day; hourly makes 24. The manuscript measures the same detector at 71.8% per-second and 58.2%
per-flow on one CIC-IDS-2017 capture, and **13.1% hourly** here. Only the first
two are the same traffic at two accounting granularities; the hourly point is
this corpus, so the span across all three confounds granularity with corpus and
is not a range over one quantity. (An earlier revision of this note called all
three "the same traffic", which its own next clause then contradicted.)

**Feature set.** 11 features here against 39 for the pcap corpora: no
per-second packet rate, no TCP flag rates, no entropy features. Whatever is
computed here uses a reduced feature space.

Consequences the manuscript already draws from this, and which anyone re-running
should preserve: the adaptive-θ controller keys on alarm episodes under 10 s, so
on hourly telemetry — where the shortest possible episode is 3,600 s — it is
identically zero and cannot fire at all. Its "0 adjustments" outcome on CESNET
reflects non-applicability, not convergence.

## A defect that also kept it out

`config.py` sets `BASE = dirname(HERE)`, so from `experiments_copy` the archive
path resolves to `AntiDDOS_Shield/datasets/cesnet/…` — a directory holding only
a `.gitkeep`. **Every CESNET runner in that tree fails with
`FileNotFoundError`.** The sibling `experiment/` tree sits one level higher and
resolves correctly, which is why it went unnoticed.

Override when running anything CESNET from `experiments_copy`:

```bash
ANTIDDOS_BASE=/path/to/antiddos python3 <script>
```

## Schema note

`_dt` is normalised from a timezone-aware `datetime` to a unix epoch float, so a
consumer written against the pcap caches reads this file unchanged. The original
values are hourly UTC stamps.

## Not included

`ip_addresses_full.tar.gz` (38 GB) — the full per-IP series. The sample here is
what the manuscript uses. The larger file would add statistical power to the
false-alarm anchor but cannot change what is claimable from it, since it too
carries no labels.
