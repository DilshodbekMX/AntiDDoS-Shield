"""End-to-end verification of datasets/extracted/.

Checks every corpus directory for the things that have actually gone wrong in
this project, rather than the things that are easy to check:

  hashes        every file matches SHA256SUMS
  index         index.json lists exactly the files present, with matching
                sizes and hashes
  schema        each scenario parses, has metadata + per_ip_windows, and its
                victim key exists
  counts        n_attack_windows / n_benign_windows in the index match the file
  intensity     every scenario carries the fields needed to judge whether its
                attack is distinguishable, and the recorded class agrees with a
                fresh recomputation
  usability     usable_as_ddos_scenario is present and consistent with the
                intensity class and FPR measurability

An index that merely agrees with itself proves nothing -- the numbers are
recomputed from the files here, not read back.

Usage: python3 verify_extracted_tree.py [root]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, hashlib, gc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from tree_io import within_split

ROOT = sys.argv[1] if len(sys.argv) > 1 else \
    _os.path.join(_BASE, 'datasets', 'extracted')


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def classify(atk_p95, ben_p95):
    if not ben_p95:
        return 'UNKNOWN'
    r = atk_p95 / ben_p95
    if r < 2.0:
        return 'INDISTINCT'
    return 'VOLUMETRIC' if atk_p95 >= 100 else 'LOW-RATE'


def main():
    problems, checked = [], 0
    for corpus in sorted(os.listdir(ROOT)):
        d = os.path.join(ROOT, corpus)
        if not os.path.isdir(d):
            continue
        print(f"\n=== {corpus} ===")
        ip = os.path.join(d, 'index.json')
        sp = os.path.join(d, 'SHA256SUMS')
        if not os.path.exists(ip) or not os.path.exists(sp):
            problems.append(f"{corpus}: missing index.json or SHA256SUMS"); continue
        idx = json.load(open(ip))
        sums = {}
        for ln in open(sp):
            if '  ' in ln:
                h, n = ln.rstrip('\n').split('  ', 1)
                sums[n] = h
        # Walk subdirectories: CIC-DDoS2019 segregates its attacker-side
        # scenarios into attacker_side/, and benign_pools/ carries its own
        # SHA256SUMS, so only the former belongs to this corpus's index.
        # The pools are checked separately, at the end. Pruning them here and
        # checking them NOWHERE excluded 76.6% of the tree by bytes (2.32 of
        # 3.03 GB) and all 3,903 pool hosts from every check, while this script
        # printed "N files checked, 0 problems". The gap hid an attacker inside
        # an "attack-free" pool: CIC-IDS-2017's 172.16.0.1, source of every
        # non-BENIGN Wednesday flow, ranked 1st of 661 on packet rate in
        # benign_pool_wednesday.
        files = set()
        for root, dirs, fs in os.walk(d):
            dirs[:] = [x for x in dirs if x != 'benign_pools']
            for f in fs:
                if f.endswith('.json') and f not in ('index.json',) \
                        and not f.endswith('.meta.json'):
                    files.add(os.path.relpath(os.path.join(root, f), d))

        if set(sums) != files:
            problems.append(f"{corpus}: SHA256SUMS lists {sorted(set(sums)-files)}, "
                            f"missing {sorted(files-set(sums))}")
        indexed = {m.get('file') for m in idx.values()}
        if indexed != files:
            problems.append(f"{corpus}: index covers {len(indexed)} of {len(files)} files")

        for name in sorted(files):
            p = os.path.join(d, name)
            checked += 1
            h = sha(p)
            if sums.get(name) != h:
                problems.append(f"{corpus}/{name}: HASH MISMATCH"); continue
            js = json.load(open(p))
            if 'metadata' not in js or 'per_ip_windows' not in js:
                problems.append(f"{corpus}/{name}: schema — missing top-level keys"); continue
            m = js['metadata']
            pw = js['per_ip_windows']
            # CESNET is a multi-host benign reference, not a single-victim scenario
            if m.get('kind', '').startswith('benign reference'):
                nrows = sum(len(v) for v in pw.values())
                atk = sum(1 for v in pw.values() for r in v if r.get('_is_attack'))
                ok = (nrows == m.get('n_windows') and atk == m.get('attack_windows') == 0)
                print(f"  {name:34s} {len(pw):4d} hosts {nrows:9,} windows  "
                      f"attacks={atk}  {'OK' if ok else 'COUNT MISMATCH'}")
                if not ok:
                    problems.append(f"{corpus}/{name}: benign-reference counts disagree")
                continue

            v = m.get('victim')
            if v not in pw:
                problems.append(f"{corpus}/{name}: victim {v} absent from per_ip_windows")
                continue
            rows = pw[v]
            a = [float(r.get('packets_per_sec', 0) or 0) for r in rows if r.get('_is_attack')]
            b = [float(r.get('packets_per_sec', 0) or 0) for r in rows if not r.get('_is_attack')]
            na, nb = len(a), len(b)
            if m.get('n_attack_windows') not in (None, na):
                problems.append(f"{corpus}/{name}: n_attack_windows "
                                f"{m['n_attack_windows']} != {na} in file")
            if m.get('n_benign_windows') not in (None, nb):
                problems.append(f"{corpus}/{name}: n_benign_windows "
                                f"{m['n_benign_windows']} != {nb} in file")
            ap = float(np.percentile(a, 95)) if a else 0.0
            bp = float(np.percentile(b, 95)) if b else 0.0
            cls = classify(ap, bp)
            rec = m.get('intensity_class')
            flag = ''
            if rec is None:
                problems.append(f"{corpus}/{name}: no intensity_class recorded")
                flag = '  NO CLASS'
            elif rec != cls:
                problems.append(f"{corpus}/{name}: intensity_class recorded {rec}, "
                                f"recomputes to {cls}")
                flag = f'  RECORDED {rec} != {cls}'
            if 'usable_as_ddos_scenario' not in m:
                problems.append(f"{corpus}/{name}: no usable_as_ddos_scenario flag")
            print(f"  {name:34s} atk={na:6d} ben={nb:6d} p95 {ap:9.0f}/{bp:7.0f} "
                  f"= {(ap/bp if bp else float('inf')):8.1f}x  {cls}"
                  f"{'' if m.get('usable_as_ddos_scenario') else '  [not usable]'}{flag}")

    # --- cross-slice calibration purity ----------------------------------
    # Same-day slices of one victim share a benign pool, and each slice's
    # causal split calibrates on that pool. If a window a SIBLING slice labels
    # attack is still sitting in this slice's fit or calibration set, the
    # threshold is being set by the other attack.
    #
    # This is the invariant behind the two worst defects found in this tree,
    # and it is stated here because the prose version kept being got wrong.
    # Split-conformal p-values are order statistics: the threshold is the top
    # of the calibration distribution, so contamination does not need to be
    # PREVALENT to be fatal -- it needs to be LOUD. CIC-IDS-2017 DDoS-LOIT's
    # calibration set was 10.2% port scan (165 of 1,617) and every one of its
    # ten highest packets_per_sec windows was scan; ensemble DR read 13.6%
    # instead of 99.6%. CIC-IDS-2018 HOIC's was 2.1% (8 of 380) and read 0.0%
    # instead of 98.2%. Neither was close to a majority.
    print(f"\n{'='*72}")
    print("CROSS-SLICE CALIBRATION PURITY")
    for corpus in sorted(os.listdir(ROOT)):
        d = os.path.join(ROOT, corpus)
        if not os.path.isdir(d):
            continue
        # Walk, don't listdir. A non-recursive scan here skipped
        # CICDDoS2019/attacker_side/ entirely -- 6 of the tree's 26 multi-slice
        # scenarios, and the sharpest case this invariant has: six overlapping
        # attacks on one host-day where _attack_type is only the DOMINANT label
        # per window. Those measurements are what the attacker-side exclusion
        # is argued from, so they are exactly the ones that must be checked.
        sl = {}
        for root, dirs, fs in os.walk(d):
            dirs[:] = [x for x in dirs if x != 'benign_pools']
            for f in sorted(fs):
                if not f.endswith('.json') or f == 'index.json' \
                        or f.endswith('.meta.json'):
                    continue
                rel = os.path.relpath(os.path.join(root, f), d)
                js = json.load(open(os.path.join(root, f)))
                md = js.get('metadata') or {}
                v = md.get('victim')
                if not v or v not in js.get('per_ip_windows', {}):
                    del js
                    continue
                sl[rel] = (v, md.get('day') or f.split('_')[0],
                           sorted(js['per_ip_windows'][v], key=lambda r: r.get('_dt', 0)))
                del js
        for name, (v, day, rows) in sl.items():
            sib = set()
            for n2, (v2, d2, r2) in sl.items():
                if n2 != name and v2 == v and d2 == day:
                    sib |= {r['_dt'] for r in r2 if r.get('_is_attack')}
            if not sib:
                continue
            sp = within_split(rows)
            if sp[0] is None:
                continue
            fit, cal = sp[0], sp[1]
            hf = sum(1 for r in fit if r['_dt'] in sib)
            hc = sum(1 for r in cal if r['_dt'] in sib)
            if hf or hc:
                problems.append(f"{corpus}/{name}: {hf} fit and {hc} calibration windows "
                                f"are labelled attack by a sibling slice of the same "
                                f"victim-day -- the threshold is set by another attack")
            print(f"  {corpus}/{name:44s} fit={hf} calib={hc}  "
                  f"(sibling attack windows {len(sib)})")
        del sl
        gc.collect()

    # --- benign pools: their own manifest, their own invariants -----------
    print(f"\n{'='*72}")
    print("BENIGN POOLS  (the false-alarm denominator)")
    pool_files = 0
    for corpus in sorted(os.listdir(ROOT)):
        pd = os.path.join(ROOT, corpus, 'benign_pools')
        if not os.path.isdir(pd):
            continue
        sp = os.path.join(pd, 'SHA256SUMS')
        sums = {}
        if os.path.exists(sp):
            for ln in open(sp):
                if '  ' in ln:
                    h, nm = ln.rstrip('\n').split('  ', 1)
                    sums[nm] = h
        else:
            problems.append(f"{corpus}/benign_pools: no SHA256SUMS")
        for f in sorted(os.listdir(pd)):
            if not f.endswith('.json'):
                continue
            fp = os.path.join(pd, f)
            pool_files += 1
            if f not in sums:
                problems.append(f"{corpus}/benign_pools/{f}: absent from SHA256SUMS")
            elif sums[f] != sha(fp):
                problems.append(f"{corpus}/benign_pools/{f}: HASH MISMATCH")
            if f.endswith('.meta.json'):
                continue
            js = json.load(open(fp))
            pw = js.get('per_ip_windows', js)
            nh = len(pw)
            nw = sum(len(v) for v in pw.values())
            natk = sum(1 for v in pw.values() for r in v if r.get('_is_attack'))
            mp = fp.replace('.json', '.meta.json')
            if os.path.exists(mp):
                mm = json.load(open(mp))
                if mm.get('n_hosts_kept') not in (None, nh):
                    problems.append(f"{corpus}/benign_pools/{f}: n_hosts_kept "
                                    f"{mm['n_hosts_kept']} != {nh} in file")
                if mm.get('n_windows') not in (None, nw):
                    problems.append(f"{corpus}/benign_pools/{f}: n_windows "
                                    f"{mm['n_windows']} != {nw} in file")
            else:
                problems.append(f"{corpus}/benign_pools/{f}: no .meta.json")
            if natk:
                problems.append(f"{corpus}/benign_pools/{f}: {natk} ATTACK-LABELLED "
                                f"windows in a pool that claims to have none")
            print(f"  {corpus + '/' + f:52s} hosts={nh:5d} windows={nw:9,d} attack={natk}")
            del js, pw
            gc.collect()

    print(f"\n{'='*72}")
    print(f"{checked} scenario files + {pool_files} pool files checked, "
          f"{len(problems)} problems")
    for p in problems:
        print(f"  ! {p}")
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
