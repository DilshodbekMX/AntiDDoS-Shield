"""Generate datasets/extracted/SCENARIO_INVENTORY.md from the index.json files.

The paper's dataset sections need two things this tree does not present together:
the evaluable set as one list, and a per-corpus account of why the rest is not
evaluable. Both exist per-corpus in index.json and in four separate READMEs; a
reader assembling a methods section has to join them by hand, and a number
transcribed by hand is a number that drifts.

So this GENERATES the inventory rather than recording it. The tables are read
from index.json at run time; the caveat text lives in CAVEATS below. Re-run it
after any regeneration or re-classification and the file follows; do not
hand-edit the output.

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
    ('LITNET-2020',         'LITNET-2020'),
]

# Why a verdict disqualifies. Kept here, not in prose, so the wording is one
# thing rather than four.
VERDICT_MEANING = {
    'NOT-DDOS':        'not a denial-of-service attack, so out of scope for a DDoS panel',
    'NO-FPR':          'the attack runs to the end of the capture, so no benign traffic follows its '
                       'onset; `n_test_benign = 0` and the false-positive rate is **undefined, not zero**',
    'FLOOR-LIMITED':   'split-conformal p-values cannot go below `1/(n_calib+1)`; where that exceeds '
                       'alpha no detector can fire and every method reads 0.0% by arithmetic',
    'ATTACKER-SIDE':   'the labelled host is the attack **source**, established from the corpus CSVs\' '
                       'own direction counts, not from a heuristic',
    'INSEPARABLE':     'on every feature the screen measures, the attack traffic is statistically '
                       'indistinguishable from the same host\'s own benign traffic: no feature reaches '
                       'rank-AUC 0.75 with 20% detection at a 5%-FPR threshold',
}

# LITNET-2020 syn_flood attack windows, from the census of the per-IP cache built from the
# complete export. One constant feeds both the caveat text and its ratio to the candidate set,
# so correcting the census changes a single number.
LITNET_SYN_FLOOD_WINDOWS = 701483

# Caveats that must travel WITH a corpus's numbers into any dataset section.
# Sourced from the 2026-08-25/26 extraction audit.
# Each caveat is a str.format template filled in main(); write a literal brace as {{ or }}.
CAVEATS = {
    'CIC-IDS-2017': [
        "Labels are a per-flow **5-tuple CSV join**, not a schedule; the published schedule is used "
        "only to separate one attack from another within a day.",
        "A 180 s **guard band** quarantines benign windows adjacent to any labelled attack span "
        "(edge bands only, never the span interior). `n_benign_quarantined` is recorded per scenario.",
        "All five usable scenarios share victim `192.168.10.50`; its four Wednesday slices share one "
        "benign pool. **A mean over them counts that benign sample more than once.**",
    ],
    'CIC-IDS2018': [
        "The CSVs are IP-sanitized, so `_is_attack` comes from the published attack **schedule**, "
        "not from a per-flow join. This is the weakest labelling of the three CIC corpora.",
        "A 180 s **guard band** is applied for the same reason as CIC-IDS-2017: the schedule minute "
        "is not the attack edge, and traffic outside it was reaching the calibration set.",
        "Same-day slices share that day's benign pool; each day's two scenarios are not independent.",
        "Positives are **diluted**: the schedule labels every window inside a documented span, "
        "including windows whose traffic looks like background; 258 of 917 GoldenEye and 69 of 844 "
        "Hulk attack windows sit at or below the slice's highest benign packet rate. This bias is "
        "CONSERVATIVE — it understates DR.",
    ],
    'CICDDoS2019': [
        "Labels are the dataset's own per-flow CSV labels. **No schedule and no timezone derivation** "
        "are used anywhere in this corpus.",
        "`_attack_type` is the **dominant** label in a window. Read a slice's span as \"windows this "
        "label won\", not as \"when this attack ran\".",
        "All six victim scenarios share one 3,183-window benign pool.",
        "`Portmap` is absent by design: it starts at capture open, leaving `n_pre_benign` of 1 on the "
        "victim and 11 on `172.16.0.5`, below the gate of 30. Only the 03-11 day is extracted; 01-12 "
        "ships CSVs but no scenarios.",
    ],
    'LITNET-2020': [
        "The only corpus built from **flow records rather than packets**. Rows carry **15 feature "
        "columns against the packet corpora's 40**: 26 of those 40 are structurally absent, among "
        "them all 13 TCP-flag-derived features and both entropy features, and one column, "
        "`unique_dst_ips`, exists only here.",
        "Built from the complete 26.9 GB `allFlows.csv`. A truncated export of that file, which "
        "loses `udp_f` entirely, was once the pipeline default; any number computed from it is "
        "suspect. Both deposited subnet records, `litnet_l1subnet_16_results.json` and "
        "`litnet_l1subnet_24_results.json` in `ComparisonResults/results/`, were scored on it and "
        "were not re-run.",
        "`syn_flood` is the corpus's largest attack — **{syn_flood_windows} attack windows over "
        "17,174 destination hosts**, 15,873 of them above the 30-window gate at **mean 42.7 / median 42 "
        "windows each (maximum 175)**, counted on the complete-export per-IP cache; no deposited "
        "record holds this census — and it ships no scenario: it is distributed, and "
        "`export_litnet_scenarios.py` builds one scenario per concentrated attack family from a "
        "hand-written victim list. The exclusion happens at that step, *before* the four "
        "admissibility checks, so it carries **no verdict** and appears in no census row, despite "
        "being {syn_flood_ratio} the {candidate_windows} attack windows of the entire "
        "{n_candidates}-scenario candidate set. (An earlier revision printed \"~175 windows each\"; "
        "175 is the maximum of the per-host distribution, not its typical value.) Its behaviour "
        "under subnet aggregation is described in the LITNET-2020 README, from caches and records "
        "built on the truncated export.",
        "The four scenarios have four different victims, so unlike the other corpora they do not "
        "share a benign pool with each other.",
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
    usable, excluded = [], []
    for corpus, label in CORPORA:
        for k, v in data[corpus].items():
            (usable if v.get('usable_as_ddos_scenario') else excluded).append((label, k, v))

    victims = {(c, v.get('victim')) for c, _, v in usable}
    n_scen = len(usable) + len(excluded)

    # Figures for the LITNET-2020 syn_flood caveat, read from the same index.json entries.
    entries = [v for c, _ in CORPORA for v in data[c].values()]
    cand_windows = sum(v['n_attack_windows'] for v in entries)
    fill = {'syn_flood_windows': f'{LITNET_SYN_FLOOD_WINDOWS:,}',
            'n_candidates': len(entries),
            'candidate_windows': f'{cand_windows:,}',
            'syn_flood_ratio': (f'{LITNET_SYN_FLOOD_WINDOWS / cand_windows:.1f}x'
                                if cand_windows else 'n/a')}

    W("# Scenario inventory — what is evaluable, and why the rest is not\n")
    W("**Generated** by `ComparisonResults/extraction/build_scenario_inventory.py` from each")
    W("corpus's `index.json`. Do not hand-edit — re-run it after any regeneration or")
    W("re-classification. The tables are read from the tree at generation time; the caveat")
    W("figures are fixed in the script, apart from the `syn_flood` ratio and candidate counts.\n")
    W(f"**{len(usable)} usable of {n_scen} scenarios**, across {len(victims)} distinct victims.\n")
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
    W("From the extraction audit. These are not optional context: each")
    W("changes how a figure from that corpus should be read.\n")
    for corpus, label in CORPORA:
        W(f"\n### {label}\n")
        for c in CAVEATS.get(corpus, []):
            W(f"- {c.format_map(fill)}")

    W("\n---\n\n## Verifying this file\n")
    W("```bash")
    W("python3 ComparisonResults/extraction/build_scenario_inventory.py   # regenerate")
    W("python3 ComparisonResults/extraction/verify_extracted_tree.py      # data vs itself")
    W("python3 ComparisonResults/extraction/verify_readme_claims.py       # prose vs data")
    W("```")

    open(out, 'w').write('\n'.join(L) + '\n')
    print(f"wrote {out}")
    print(f"  {len(usable)} usable / {n_scen} scenarios, {len(victims)} distinct victims, "
          f"{len(excluded)} excluded")


if __name__ == '__main__':
    main()
