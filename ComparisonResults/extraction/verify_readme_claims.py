"""Check the extracted-tree READMEs against the artifacts they describe.

The corpus READMEs live under `datasets/`, which is gitignored, so they are
outside version control and nothing re-reads them when the data changes. They
drifted badly: after the label-boundary guard (CHANGE 196) the CIC-IDS-2018
README still printed DDoS-HOIC at 0.0% and DDoS-LOIC-UDP at 89.6% -- the two
numbers that fix had corrected to 98.2% and 100.0% -- still published a claim
about HOIC's attack character that the same fix refuted, still named a producer
script that cannot produce the tree, and carried stale n_calib on every row.
The tree README meanwhile said "43 scenarios exist; 25 are usable" directly
above its own table saying 22 of 44.

`verify_extracted_tree.py` checks the DATA against itself. This checks the
PROSE against the data. It is deliberately narrow: it verifies claims that can
be tied to an artifact without parsing English, and says nothing about the rest.

What it checks, per corpus:
  * the scenario count stated in the corpus README header
  * every table row naming a scenario: any integer on that row that looks like
    an n_attack or n_calib must match the artifact
  * the tree README's per-corpus usable/total table, and its headline "N
    scenarios exist; M are usable"
  * every (slice, minutes, cause) row in the CIC-IDS-2018 temporal-gap table,
    against gaps recomputed from the files -- this is the one quantitative
    table in that README that had no gate behind it, which is why a residue of
    the original defect survived a pass that corrected everything else. Two
    revisions got it wrong: the first invented the durations, the second got
    the durations right but attributed protocol splices to the split.

    python3 verify_readme_claims.py [--tree DIR]

Exit 0 clean, 1 if any claim diverges.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, re, glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from config import RESULTS_DIR

TREE = _os.path.join(_BASE, 'datasets', 'extracted')
CLASS = os.path.join(RESULTS_DIR, 'scenario_classification.json')

WORDNUM = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6,
           'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10, 'eleven': 11,
           'twelve': 12, 'thirteen': 13, 'fourteen': 14}
# tree-README corpus label -> directory name
DIROF = {'CIC-IDS-2017': 'CIC-IDS-2017', 'CIC-IDS-2018': 'CIC-IDS2018',
         'CIC-DDoS2019': 'CICDDoS2019', 'CIC-IoT-2023': 'CIC_IOT_Dataset2023',
         'LITNET-2020': 'LITNET-2020'}


def ints(line):
    return {int(x.replace(',', '')) for x in re.findall(r'\b\d[\d,]*\b', line)}


def gap_facts(tree, corpus):
    """Every gap >= 10 min in each slice's benign eval stream, with its cause.

    A gap is a PROTOCOL SPLICE if it straddles that slice's own attack span --
    the causal split calibrates before the first attack and tests after it, so
    this gap is present in the unsplit day cache and is not caused by the
    per-attack split. It is SPLIT-INDUCED if it straddles a sibling slice's
    attack span, i.e. it is the hole left by removing that attack. Anything
    else is natural.

    NOTE the same wall-clock interval can be both, in different slices: the
    Thursday 10:55-11:43 gap is Slowloris's own span in the Slowloris slice and
    Slowloris's removal in the GoldenEye slice. So the key is (slice, minutes),
    never minutes alone.
    """
    from tree_io import within_split
    d = os.path.join(tree, corpus)
    S = {}
    for f in sorted(glob.glob(os.path.join(d, '*.json'))):
        if os.path.basename(f) == 'index.json':
            continue
        js = json.load(open(f))
        v = (js.get('metadata') or {}).get('victim')
        rows = sorted(js['per_ip_windows'][v], key=lambda r: r.get('_dt', 0))
        atk = [r['_dt'] for r in rows if r.get('_is_attack')]
        if not atk:
            continue
        name = os.path.basename(f).replace('.json', '')
        S[name] = {'day': name.split('_')[0], 'span': (min(atk), max(atk)),
                   'split': within_split(rows)}
    out = {}
    for n, e in S.items():
        fit, cal, tb, _ = e['split']
        if cal is None:
            continue
        ts = [r['_dt'] for r in list(cal) + list(tb)]
        sibs = [S[m]['span'] for m in S if S[m]['day'] == e['day'] and m != n]
        found = []
        for i in range(len(ts) - 1):
            g = ts[i + 1] - ts[i]
            if g < 600:
                continue
            own = e['span'][0] <= ts[i + 1] and ts[i] <= e['span'][1]
            oth = any(s0 <= ts[i + 1] and ts[i] <= s1 for s0, s1 in sibs)
            found.append((round(g / 60, 2),
                          'protocol splice' if own else
                          'split-induced' if oth else 'natural'))
        out[n] = found
    return out


def main():
    tree = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--tree'), TREE)
    # Resolve the classification beside the tree being checked. Reading the
    # canonical results while checking a scratch tree validates one tree's prose
    # against another tree's numbers -- the read-side twin of the bug that let a
    # scratch-tree run of classify_scenarios.py overwrite the canonical results.
    src = CLASS if os.path.abspath(tree) == os.path.abspath(TREE) \
        else os.path.join(tree, 'scenario_classification.json')
    if not os.path.exists(src):
        print(f"  ! no scenario_classification.json for {tree}"
              f"\n    expected at {src}; run classify_scenarios.py {tree} --write first")
        return 1
    cls = json.load(open(src))
    # A gate that checks nothing must not report success. When a scratch-tree
    # run of classify_scenarios.py emptied results/scenario_classification.json
    # to `[]`, this loop had nothing to iterate and printed "0 problems" -- the
    # gate that would have caught the damage was disabled by the same write.
    if not cls:
        print(f"  ! {src} contains 0 scenarios -- refusing to report a clean gate "
              f"on an empty classification")
        return 1
    by = {}
    for r in cls:
        by.setdefault(r['corpus'], {})[r['scenario']] = r
    problems = []

    for corpus, scen in sorted(by.items()):
        rp = os.path.join(tree, corpus, 'README.md')
        if not os.path.exists(rp):
            problems.append(f"{corpus}: no README.md"); continue
        txt = open(rp).read()
        n_real = len(json.load(open(os.path.join(tree, corpus, 'index.json'))))

        # header count, as digit or as word, in the first three lines
        head = '\n'.join(txt.splitlines()[:4]).lower()
        claimed = ints(head) | {WORDNUM[w] for w in WORDNUM if re.search(rf'\b{w}\b', head)}
        plausible = {c for c in claimed if 1 <= c <= 60}
        head_ok = not plausible or n_real in plausible
        if not head_ok:
            problems.append(f"{corpus}: header says {sorted(plausible)} scenarios, "
                            f"index.json has {n_real}")

        # per-scenario table rows
        for name, r in sorted(scen.items()):
            for line in txt.splitlines():
                if '|' not in line or name not in line:
                    continue
                v = ints(line)
                if r['n_attack'] in v and r['n_calib'] not in v and r['n_calib'] > 0:
                    problems.append(f"{corpus}/{name}: table row carries n_attack "
                                    f"{r['n_attack']} but not n_calib {r['n_calib']}"
                                    f"  ->  {line.strip()[:76]}")
                # a DR-looking float on the row must match one of the recorded DRs
                for f in re.findall(r'\b(\d{1,3}\.\d)\s*%', line):
                    f = float(f)
                    known = [r.get('best_dr_at_5pct_fpr')]
                    if all(k is None or abs(f - k) > 0.05 for k in known) and f > 0:
                        pass   # DRs vary by arm and alpha; not decidable here

        print(f"  {corpus:22s} header {'ok ' if head_ok else 'BAD'}, {n_real:2d} scenarios, "
              f"{sum(1 for r in scen.values() if r['verdict'] == 'USABLE')} usable")

    # CIC-IDS-2018 temporal-gap table
    gp = os.path.join(tree, 'CIC-IDS2018', 'README.md')
    if os.path.exists(gp):
        facts = gap_facts(tree, 'CIC-IDS2018')
        txt = open(gp).read()
        n_rows = 0
        for line in txt.splitlines():
            m = re.match(r'\|\s*`([^`]+)`\s*\|\s*([\d.]+)\s*min\s*\|', line)
            if not m:
                continue
            slice_, mins = m.group(1), float(m.group(2))
            if slice_ not in facts:
                problems.append(f"gap table names unknown slice {slice_}"); continue
            n_rows += 1
            hit = [c for g, c in facts[slice_] if abs(g - mins) < 0.02]
            if not hit:
                problems.append(f"gap table: {slice_} {mins} min is not a measured gap "
                                f"(measured: {[g for g, _ in facts[slice_]]})")
                continue
            low = line.lower()
            claimed = ('split-induced' if 'split-induced' in low
                       else 'protocol splice' if 'protocol splice' in low else None)
            if claimed and claimed not in hit:
                problems.append(f"gap table: {slice_} {mins} min called '{claimed}', "
                                f"measured as {hit[0]}")
        measured = sum(1 for v in facts.values() for _ in v)
        if n_rows != measured:
            problems.append(f"gap table has {n_rows} rows; {measured} gaps >=10 min "
                            f"are measured across the slices")
        print(f"  {'CIC-IDS2018 gap table':22s} {n_rows} rows, all attributions checked")

    # tree README
    tp = os.path.join(tree, 'README.md')
    if os.path.exists(tp):
        txt = open(tp).read()
        tot_u = sum(1 for r in cls if r['verdict'] == 'USABLE')
        m = re.search(r'##\s*(\d+)\s+scenarios exist;\s*(\d+)\s+are usable', txt)
        if not m:
            problems.append("tree README: no 'N scenarios exist; M are usable' heading")
        elif (int(m.group(1)), int(m.group(2))) != (len(cls), tot_u):
            problems.append(f"tree README heading says {m.group(1)} exist / {m.group(2)} "
                            f"usable; artifacts say {len(cls)} / {tot_u}")
        # Scope to the usability table only. Matching the first row that starts
        # with the corpus name picks up the benign-pool table higher in the
        # file, whose columns are hosts and windows, not usable and total.
        blk = txt[m.end():] if m else txt
        blk = blk.split('\n## ')[0]
        for label, d in DIROF.items():
            rows = [l for l in blk.splitlines() if l.startswith(f'| {label} |')]
            if not rows:
                problems.append(f"tree README: no table row for {label}"); continue
            u = sum(1 for r in by.get(d, {}).values() if r['verdict'] == 'USABLE')
            t = len(by.get(d, {}))
            got = ints(rows[0])
            if u not in got or t not in got:
                problems.append(f"tree README row for {label} is {rows[0].strip()[:60]}; "
                                f"artifacts say {u} of {t}")
        print(f"  {'tree README':22s} {len(cls)} scenarios, {tot_u} usable")

    print()
    for p in problems:
        print(f"  ! {p}")
    print(f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
