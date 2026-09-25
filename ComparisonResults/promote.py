#!/usr/bin/env python3
"""Promote named records from reproduction/ into results/, with an audit trail.

The overwrite guard in safe_out.py sends a re-run of a deposited record to
reproduction/ instead of replacing the deposit. That is correct, and it is also why a
record whose content SHOULD change -- new keys, a normalised spelling, a renamed
cluster key -- cannot reach the deposit by re-running. Promotion is that step, and it
is deliberate rather than a flag flipped by hand.

For every named record this prints the exact diff against the deposit, refuses to move
anything unless --apply is given with an explicit record list, and rewrites
SHA256SUMS.results from inside results/ once the copies are in place.

  python3 promote.py --list                      show what is promotable
  python3 promote.py rec1.json rec2.json         dry run, diff only
  python3 promote.py rec1.json rec2.json --apply promote and rewrite the manifest
"""
import argparse, hashlib, json, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, 'results')
REPRO = os.path.join(HERE, 'reproduction')
MANIFEST = os.path.join(HERE, 'SHA256SUMS.results')


def diff(a, b, path='', out=None):
    if out is None:
        out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append((path + '/' + k, 'REMOVED'))
            elif k not in b:
                out.append((path + '/' + k, 'ADDED'))
            else:
                diff(a[k], b[k], path + '/' + k, out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append((path, f'length {len(b)} -> {len(a)}'))
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                diff(x, y, f'{path}[{i}]', out)
    elif a != b:
        out.append((path, f'{b!r} -> {a!r}'))
    return out


SPELLINGS = {'CIC-IDS-2018': 'CSE-CIC-IDS2018', 'CIC-IDS2018': 'CSE-CIC-IDS2018',
             'CICDDoS2019': 'CIC-DDoS2019', 'CIC_IOT_Dataset2023': 'CIC-IoT-2023'}


def bucket(paths):
    """Group added paths by their final key name, so a category is one line."""
    out = {}
    for p in paths:
        k = p.rsplit('/', 1)[-1]
        k = ''.join('N' if ch.isdigit() else ch for ch in k) if k[:1].isdigit() else k
        out[k] = out.get(k, 0) + 1
    return out


def kinds(changed):
    """Classify a changed leaf: a corpus spelling normalisation, or something else."""
    out = {}
    for p, v in changed:
        s = str(v)
        lab = 'other'
        for raw, cn in SPELLINGS.items():
            if raw in s and cn in s:
                lab = f'corpus spelling {raw} -> {cn}'
                break
        out[lab] = out.get(lab, 0) + 1
    return out


def classify(changes):
    added = [p for p, v in changes if v == 'ADDED']
    removed = [p for p, v in changes if v == 'REMOVED']
    changed = [(p, v) for p, v in changes if v not in ('ADDED', 'REMOVED')]
    return added, removed, changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('records', nargs='*')
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--list', action='store_true')
    a = ap.parse_args()

    if a.list:
        for f in sorted(os.listdir(REPRO)) if os.path.isdir(REPRO) else []:
            print(' ', f)
        return 0
    if not a.records:
        ap.error('name the records to promote, or use --list')

    staged = []
    for name in a.records:
        src, dst = os.path.join(REPRO, name), os.path.join(RESULTS, name)
        if not os.path.exists(src):
            print(f'!! {name}: not in reproduction/'); return 1
        new = json.load(open(src))
        if os.path.exists(dst):
            changes = diff(new, json.load(open(dst)))
            added, removed, changed = classify(changes)
            print(f'\n== {name}: {len(changes)} differing paths '
                  f'({len(added)} added, {len(removed)} removed, {len(changed)} changed)')
            print('   ADDED, by key name:')
            for k, c in sorted(bucket(added).items(), key=lambda x: -x[1]):
                print(f'     {c:6d}  {k}')
            print('   CHANGED, by kind:')
            for k, c in sorted(kinds(changed).items(), key=lambda x: -x[1]):
                print(f'     {c:6d}  {k}')
            for p_, v in changed[:4]:
                print(f'     e.g. {p_}  {str(v)[:88]}')
            if removed:
                print(f'   !! {len(removed)} REMOVED keys -- review before promoting')
                for p_ in removed[:6]:
                    print(f'        {p_}')
        else:
            print(f'\n== {name}: NEW record, not currently in the deposit')
        staged.append((src, dst, name))

    if not a.apply:
        print('\ndry run. re-run with --apply to promote and rewrite the manifest.')
        return 0

    for src, dst, name in staged:
        shutil.copy2(src, dst)
        print(f'promoted {name}')
    # Manifest covers the JSON result records and nothing else. Walking everything under
    # results/ silently swept in rescued/ABLATION_README.md when this step first ran; a
    # manifest should widen only when someone says so.
    lines = []
    for root, _, files in os.walk(RESULTS):
        for f in sorted(files):
            if not f.endswith('.json'):
                continue
            p = os.path.join(root, f)
            rel = os.path.relpath(p, RESULTS)
            h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
            lines.append(f'{h}  {rel}\n')
    lines.sort(key=lambda l: l.split('  ', 1)[1])
    open(MANIFEST, 'w').writelines(lines)
    print(f'\nrewrote {MANIFEST} with {len(lines)} entries')
    r = subprocess.run(['sha256sum', '-c', os.path.relpath(MANIFEST, RESULTS)],
                       cwd=RESULTS, capture_output=True, text=True)
    ok = sum(1 for l in r.stdout.splitlines() if l.endswith(': OK'))
    print(f'verification from inside results/: {ok} of {len(lines)} OK')
    return 0 if ok == len(lines) else 1


if __name__ == '__main__':
    sys.exit(main())
