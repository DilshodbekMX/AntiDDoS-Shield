"""Rebuild the LITNET per-IP cache from the COMPLETE allFlows.csv.

Every LITNET number in this project came from a cache built on an allFlows.csv
that was extracted 11.5% short and ended mid-record (CHANGE 188). Two attack
types were entirely absent from that file:

    udp_f    93,583 flows -- the corpus's fourth-largest attack, never evaluated
    smtp_b      747 flows

and two more were substantially short (icmp_smf +44%, icmp_f +43%). The
complete file is now on disk at 26,943,158,910 bytes, byte-exact against the
zip member.

WHY THIS IS WORTH THE PASS, checked before running it rather than assumed. The
cache keeps only destinations matching KEEP_PREFIXES ('193.219.', '83.171.')
plus one external victim -- LITNET records outbound traffic to the whole
internet, so without that filter the per-IP dict exhausts memory. udp_f could
therefore have been filtered out regardless of the truncation, making the
rebuild pointless. It is not: 43,472 of its 93,583 flows target 193.219.*, well
inside the kept range.

No re-split is needed. litnet_loader.py falls back to a monolithic allFlows.csv
when a parts directory holds no allFlows_part_*.csv, so pointing it at
datasets/LITNET-2020/ reads the complete file directly. The existing parts/
directory is a split of the TRUNCATED file and must not be used.

The old cache is preserved as litnet_per_ip_cache.truncated.json for comparison.

Usage: python3 rebuild_litnet_caches.py [--out CACHE] [--dry-run]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, time, shutil
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from config import CACHE_DIR
from litnet_loader import load_litnet_per_ip

SRC = _os.path.join(_BASE, 'datasets', 'LITNET-2020')
KEEP_PREFIXES = ('193.219.', '83.171.')
KEEP_EXACT = {'23.32.104.60'}
MIN_WINDOWS = 100


def main():
    out = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'),
               os.path.join(CACHE_DIR, 'litnet_per_ip_cache.json'))
    mono = os.path.join(SRC, 'allFlows.csv')
    size = os.path.getsize(mono)
    print(f"  source : {mono}\n  size   : {size:,} bytes")
    if size != 26_943_158_910:
        print(f"  !! expected 26,943,158,910 -- this is not the complete file")
    if any(f.startswith('allFlows_part_') for f in os.listdir(SRC)):
        sys.exit("  !! part files present in SRC; the loader would read those "
                 "instead of the complete file")
    if '--dry-run' in sys.argv:
        print("  DRY RUN"); return

    if os.path.exists(out):
        keep = out.replace('.json', '.truncated.json')
        if not os.path.exists(keep):
            shutil.copyfile(out, keep)
            print(f"  preserved old cache -> {os.path.basename(keep)}")

    t0 = time.time()
    d = load_litnet_per_ip(SRC, window_sec=1, min_windows=MIN_WINDOWS,
                           keep_prefixes=KEEP_PREFIXES, keep_exact=KEEP_EXACT)
    print(f"\n  hosts kept: {len(d)}   windows: {sum(len(v) for v in d.values()):,}")

    import collections
    types = collections.Counter(r.get('_attack_type') for v in d.values() for r in v
                                if r.get('_is_attack'))
    print(f"\n  attack types now present per-window:")
    for k, n in types.most_common():
        print(f"    {str(k):18s} {n:8,}")

    # _dt is a datetime in memory; the cache format stores it as ISO text
    ser = {ip: [{**r, '_dt': r['_dt'].isoformat() if hasattr(r.get('_dt'), 'isoformat')
                 else r.get('_dt')} for r in rows] for ip, rows in d.items()}
    json.dump(ser, open(out, 'w'))
    print(f"\n  wrote {out}  ({os.path.getsize(out)/1e6:.0f} MB, {time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
