"""Generate datasets/extracted/SCENARIO_INVENTORY.md from the index.json files.

The paper's dataset sections need two things this tree does not present together:
the evaluable set as one list, and a per-corpus account of why the rest is not
evaluable. Both exist per-corpus in index.json and in six separate READMEs; a
reader assembling a methods section has to join them by hand, and a number
transcribed by hand is a number that drifts.

So this GENERATES the inventory rather than recording it. Every figure below is
read from index.json at run time. Re-run it after any regeneration or
re-classification and the file follows; do not hand-edit the output.

Usage:  python3 build_scenario_inventory.py [--out FILE]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, collections

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = _os.path.join(_BASE, 'datasets', 'extracted')
DEFAULT_OUT = os.path.join(TREE, 'SCENARIO_INVENTORY.md')

# Display order and the paper's corpus labels.
CORPORA = [
    ('CIC-IDS-2017',        'CIC-IDS-2017'),
    ('CIC-IDS2018',         'CSE-CIC-IDS2018'),
    ('CICDDoS2019',         'CIC-DDoS2019'),
    ('CIC_IOT_Dataset2023', 'CIC-IoT-2023'),
    ('LITNET-2020',         'LITNET-2020'),
    ('CESNET-TimeSeries24', 'CESNET-TimeSeries24'),
]

# Why a verdict disqualifies. Kept here, not in prose, so the wording is one
# thing rather than six.
VERDICT_MEANING = {
    'NOT-DDOS':        'not a denial-of-service attack, so out of scope for a DDoS panel',
    'NO-FPR':          'the attack runs to the end of the capture, so no benign traffic follows its '
                       'onset; `n_test_benign = 0` and the false-positive rate is **undefined, not zero**',
    'FLOOR-LIMITED':   'split-conformal p-values cannot go below `1/(n_calib+1)`; where that exceeds '
                       'alpha no detector can fire and every method reads 0.0% by arithmetic',
    'ATTACKER-SIDE':   'the labelled host is the attack **source**, established from the corpus CSVs\' '
                       'own direction counts, not from a heuristic',
    'ROLE-UNVERIFIED': 'the host\'s role could not be established. The direction heuristic that '
                       'originally excluded these is **inverted** on this corpus (it flags 15 of 16 '
                       'confirmed flood targets and 0 of 10 confirmed sources), so the exclusion is '
                       'retained but the stated reason is now "unverified" rather than "attacker-side"',
    'INSEPARABLE':     'attack traffic is statistically indistinguishable from the same host\'s own '
                       'benign traffic',
}

# Caveats that must travel WITH a corpus's numbers into any dataset section.
# Sourced from the 2026-08-25/26 six-corpus audit (CHANGE 196-209).
CAVEATS = {
    'CIC-IDS-2017': [
        "Labels are a per-flow **5-tuple CSV join**, not a schedule; the published schedule is used "
        "only to separate one attack from another within a day.",
        "A 180 s **guard band** quarantines benign windows adjacent to any labelled attack span "
        "(edge bands only, never the span interior). `n_benign_quarantined` is recorded per scenario.",
        "All five Wednesday/Friday scenarios share victim `192.168.10.50`; the four Wednesday slices "
        "share one benign pool. **A mean over them counts that benign sample more than once.**",
    ],
    'CIC-IDS2018': [
        "The CSVs are IP-sanitized, so `_is_attack` comes from the published Table-2 **schedule**, "
        "not from a per-flow join. This is the weakest labelling of the three CIC-IDS corpora.",
        "A 180 s **guard band** is applied for the same reason as CIC-IDS-2017: the schedule minute "
        "is not the attack edge, and traffic outside it was reaching the calibration set.",
        "Same-day slices share that day's benign pool; each day's two scenarios are not independent.",
        "Positives are **diluted**: some windows inside a documented span carry only background "
        "traffic (85/917 GoldenEye, 69/844 Hulk). This bias is CONSERVATIVE — it understates DR.",
    ],
    'CICDDoS2019': [
        "Labels are the dataset's own per-flow CSV labels. **No schedule and no timezone derivation** "
        "are used anywhere in this corpus.",
        "`_attack_type` is the **dominant** label in a window. Read a slice's span as \"windows this "
        "label won\", not as \"when this attack ran\".",
        "All six victim scenarios share one 3,183-window benign pool.",
        "`Portmap` is absent by design: it starts at capture open, leaving `n_pre_benign` of 1, below "
        "the gate of 30. Only the 03-11 day is extracted; 01-12 ships CSVs but no scenarios.",
    ],
    'CIC_IOT_Dataset2023': [
        "**Labels are directory-derived**: every window of a family capture is marked attack "
        "regardless of host, so `_is_attack` means *captured during this attack session*, not "
        "*contains attack traffic*. No per-flow join is possible — the CSVs ship without IPs or timestamps.",
        "**Benign comes from a separate capture**, so detection rates here include a component of "
        "discrimination between two recording sessions. A session-matched control (the victim's "
        "windows drawn from captures targeting a *different* host) reproduces 86.5-100% of each "
        "scenario's reported DR against a within-benign null of 0.1-3.1%. **Treat "
        "`best_dr_at_5pct_fpr` as a separability gate, not as evidence of attack detection.** "
        "This applies to all thirteen scenarios, not only the excluded ones.",
        "Victim selection ranks candidate hosts by attack-window count, which under directory-derived "
        "labelling means *busiest during the capture*, not *attacked*.",
        "Three of the six usable scenarios (`SYN_Flood`, `TCP_Flood`, `UDP_Flood`) share victim "
        "`192.168.137.99` and one benign block.",
    ],
    'LITNET-2020': [
        "The only corpus built from **flow records rather than packets**. Rows carry **13 features, "
        "not 39** — all eight TCP-flag features are structurally absent, as are the entropy features.",
        "Built from the complete 26.9 GB `allFlows.csv`. A truncated 88.5% export exists on disk "
        "(`parts/`, `allFlows.csv.truncated`) and was the pipeline default until CHANGE 207; any "
        "number predating it is suspect.",
        "`syn_flood` is the corpus's largest attack \u2014 **678,911 attack windows over 16,509 "
        "destination hosts**, 15,335 of them above the 30-window gate at **mean 42.9 / median 42 "
        "windows each (maximum 175)** \u2014 and it ships no scenario: it is distributed, and no single "
        "host carries enough of it for the one-scenario-per-family materialisation rule. The "
        "exclusion happens at materialisation, *before* the four admissibility checks, so it carries "
        "**no verdict** and appears in no census row, despite being 4.3x the 158,725 attack windows "
        "of the entire 44-scenario candidate set. (An earlier revision printed \"~175 windows each\"; "
        "175 is the maximum of the per-host distribution, not its typical value.) At /24 it is "
        "*quieter* than the zone's own benign traffic (0.02x).",
        "The four scenarios have four different victims, so unlike the other corpora they do not "
        "share a benign pool with each other.",
    ],
    'CESNET-TimeSeries24': [
        "**No attacks and no label column.** No detection rate can be computed. Its role is the "
        "anti-artifact control: real ISP backbone telemetry with no synthetic generator, so a "
        "false-alarm floor measured here cannot be a testbed artifact.",
        "**Hourly** windows against per-second elsewhere, and **11 features** against 39. Per-window "
        "rates are not commensurable across those units.",
        "KNOWN DEFECT (open): the three volume features are hourly COUNTS carried under per-SECOND "
        "names — `data_loader.py` maps them 1:1 with no division by 3,600. No published FPR moves "
        "(the z-path is scale-invariant), but the field names mean true rates in every sibling corpus.",
        "174 of the sample's 1,000 IPs clear the >=3,000-row gate, which selects on temporal presence "
        "(93.3% vs 3.8% coverage), not volume. Scoring all 921 evaluable hosts gives 13.90% against "
        "the shipped 13.08% — the published figure is the conservative end.",
    ],
}


def load(corpus):
    p = os.path.join(TREE, corpus, 'index.json')
    return json.load(open(p)) if os.path.exists(p) else {}


def main():
    out = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'), DEFAULT_OUT)
    L = []
    W = L.append

    data = {c: load(c) for c, _ in CORPORA}
    usable, excluded, benign_ref = [], [], []
    for corpus, label in CORPORA:
        for k, v in data[corpus].items():
            if str(v.get('kind', '')).startswith('benign reference'):
                benign_ref.append((label, k, v)); continue
            (usable if v.get('usable_as_ddos_scenario') else excluded).append((label, k, v))

    victims = {(c, v.get('victim')) for c, _, v in usable}
    n_scen = len(usable) + len(excluded)

    W("# Scenario inventory — what is evaluable, and why the rest is not\n")
    W("**Generated** by `AntiDDOS_Shield/experiments_copy/build_scenario_inventory.py` from each")
    W("corpus's `index.json`. Do not hand-edit — re-run it after any regeneration or")
    W("re-classification. Every figure here is read from the tree at generation time.\n")
    W(f"**{len(usable)} usable of {n_scen} scenarios**, across {len(victims)} distinct victims, ")
    W(f"plus {len(benign_ref)} benign reference with no attacks.\n")
    W("Verdicts come from `classify_scenarios.py`, which applies four independent checks and records")
    W("all of them per file: traffic **direction**, **separability**, the **conformal floor**, and")
    W("whether an FPR is **measurable** at all.\n")

    # ---- usable ----
    W("\n---\n\n## The evaluable set\n")
    W("| corpus | scenario | victim | n_attack | n_benign | n_calib | n_test_benign | split |")
    W("|---|---|---|---:|---:|---:|---:|---|")
    for label, k, v in usable:
        W(f"| {label} | `{k}` | `{v.get('victim')}` | {v.get('n_attack_windows')} | "
          f"{v.get('n_benign_windows')} | {v.get('n_calib')} | "
          f"{v.get('n_test_benign', v.get('n_benign_test', '—'))} | {v.get('split_mode', '—')} |")

    # shared-victim warning, computed not asserted
    byv = collections.Counter((c, v.get('victim')) for c, _, v in usable)
    shared = {k: n for k, n in byv.items() if n > 1}
    if shared:
        W("\n### Not independent — shared victims and benign pools\n")
        W("Scenarios sharing a victim draw on the same benign windows. The causal split partitions")
        W("them differently, so their FPR rows are not identical, but it is the same traffic.")
        W("**A mean over them counts that benign sample more than once.** Aggregate per victim, or")
        W("deduplicate — and note that at the deduplicated n the minimum attainable Wilcoxon p may")
        W("sit above a Bonferroni-corrected alpha, which is a power floor, not evidence of absence.\n")
        for (c, ip), n in sorted(shared.items(), key=lambda x: -x[1]):
            names = [k for cc, k, vv in usable if cc == c and vv.get('victim') == ip]
            W(f"- **{c}** `{ip}` carries {n}: {', '.join('`%s`' % x for x in names)}")
        W(f"\nSo the {len(usable)} scenarios represent **{len(victims)} distinct victims**.")

    # ---- exclusions ----
    W("\n---\n\n## Why the rest is not evaluable\n")
    W("Grouped by corpus so each block can be lifted into that corpus's dataset section.\n")
    for corpus, label in CORPORA:
        rows = [(k, v) for c, k, v in excluded if c == label]
        if not rows:
            continue
        W(f"\n### {label} — {len(rows)} excluded\n")
        byverdict = collections.defaultdict(list)
        for k, v in rows:
            byverdict[v.get('verdict', '?')].append((k, v))
        for verd, items in sorted(byverdict.items()):
            W(f"**{verd}** ({len(items)}) — {VERDICT_MEANING.get(verd, 'see index.json')}.\n")
            for k, v in items:
                bits = []
                if v.get('n_calib') is not None:
                    bits.append(f"n_calib={v['n_calib']}")
                if v.get('p_floor') is not None:
                    bits.append(f"p_floor={v['p_floor']}")
                ntb = v.get('n_test_benign', v.get('n_benign_test'))
                if ntb is not None:
                    bits.append(f"n_test_benign={ntb}")
                if v.get('attack_to_benign_p95_ratio') is not None:
                    bits.append(f"atk/ben p95={v['attack_to_benign_p95_ratio']}x")
                if v.get('best_auc') is not None:
                    bits.append(f"AUC={v['best_auc']}")
                W(f"- `{k}` — victim `{v.get('victim')}`, {v.get('n_attack_windows')} attack windows"
                  + (f" ({', '.join(bits)})" if bits else ""))
            W("")

    # ---- per-corpus caveats ----
    W("\n---\n\n## Caveats that must travel with the numbers\n")
    W("From the six-corpus extraction audit (CHANGE 196-209). These are not optional context: each")
    W("changes how a figure from that corpus should be read.\n")
    for corpus, label in CORPORA:
        W(f"\n### {label}\n")
        for c in CAVEATS.get(corpus, []):
            W(f"- {c}")

    # ---- benign reference ----
    if benign_ref:
        W("\n---\n\n## Benign reference (no attacks)\n")
        for label, k, v in benign_ref:
            W(f"**{label}** — `{k}`: {v.get('n_hosts')} hosts, {v.get('n_windows'):,} windows, "
              f"{v.get('attack_windows')} attack windows, {v.get('window_unit')}, "
              f"{v.get('n_features')} features.")
            W(f"\n> {v.get('role', '')}\n")

    W("\n---\n\n## Verifying this file\n")
    W("```bash")
    W("python3 AntiDDOS_Shield/experiments_copy/build_scenario_inventory.py   # regenerate")
    W("python3 AntiDDOS_Shield/experiments_copy/verify_extracted_tree.py      # data vs itself")
    W("python3 AntiDDOS_Shield/experiments_copy/verify_readme_claims.py       # prose vs data")
    W("```")

    open(out, 'w').write('\n'.join(L) + '\n')
    print(f"wrote {out}")
    print(f"  {len(usable)} usable / {n_scen} scenarios, {len(victims)} distinct victims, "
          f"{len(excluded)} excluded, {len(benign_ref)} benign reference")


if __name__ == '__main__':
    main()
