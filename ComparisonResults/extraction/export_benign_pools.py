"""Export attack-free host pools -- the false-alarm denominator.

Every scenario file carries the VICTIM's own benign windows, which is what the
causal split calibrates on. That is not a false-alarm measurement. A detector's
operational cost is what it does to the hosts that are never attacked at all,
and those hosts are absent from the scenario tree entirely.

This extracts them: every destination with ZERO attack-labelled windows in a
capture. That is the population the manuscript's 71.8% per-window floor is
measured on (its "530 completely clean, uninvolved background hosts"), and the
one number a scenario file cannot give.

SELECTION. A host qualifies if it has no attack window anywhere in the capture
and at least MIN_WINDOWS of traffic. EVERY qualifying host is kept; what is
capped is windows PER HOST, chronological prefix.

That ordering matters. Capping total windows instead keeps a handful of the
busiest hosts and discards the rest -- it kept 5 of 479 CIC-IoT hosts and 137
of 800 on CIC-IDS-2017 Monday. A false-alarm rate is an average over HOSTS, so
diversity is the quantity to preserve and depth is what to trade away. The
manuscript's own pool is 530 hosts averaging ~274 windows each, not a few deep
ones.

A NOTE ON WHAT "ATTACK-FREE" MEANS HERE. It is label-derived: no window of this
host carries _is_attack. For CIC-IoT that is weaker than it sounds, because the
corpus labels every window of a family capture as attack regardless of host, so
an uninvolved host inside an attack capture is still labelled attacked. Its pool
therefore comes from the dedicated benign capture instead.

Usage: python3 export_benign_pools.py [--out DIR] [--min 100] [--max 250000]
       [--only CORPUS]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, gc, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'negatives'))
import tree_io as R
from config import BASE

DEFAULT_OUT = _os.path.join(_BASE, 'datasets', 'extracted')
MIN_WINDOWS = 100
MAX_PER_HOST = 3000

# "Zero attack-labelled windows" is NOT the same as "not involved in an attack",
# because _is_attack is assigned by a DIRECTION-SENSITIVE 5-tuple lookup: the
# label CSVs list flows attacker->victim, the lookup key is the packet's own
# (src, sport, dst, dport, proto), so packets travelling victim->attacker never
# match. A host that only ever RECEIVES return traffic from its own victim
# therefore accumulates zero attack windows and qualifies as "attack-free".
#
# That is how 172.16.0.1 -- the source of every non-BENIGN flow on CIC-IDS-2017
# Wednesday (Hulk 231,073, GoldenEye 10,293, slowloris 5,796, Slowhttptest
# 5,499) -- shipped in benign_pool_wednesday as the LOUDEST of its 661 hosts,
# ranked 1st on both max (6,243 pps) and p99 (5,981) against a pool
# median-of-medians of 2.0 pps. Friday escaped only by accident: its DDoS CSV
# happens to carry 3 role-reversed rows, which gave the attacker 7 attack
# windows and disqualified it. Wednesday's CSV has none.
#
# So membership is now decided on ROLE, not on the direction-sensitive label: a
# host appearing as EITHER endpoint of any non-BENIGN flow is excluded.
#
# The role check is wired per corpus, because each one carries its ground truth
# somewhere different, and for two of them it does not exist at all. Every pool
# now records WHICH case it is in `role_check`, so a pool that was never
# role-checked says so in its own metadata instead of looking checked:
#
#   CIC-IDS-2017   per-day TrafficLabelling CSVs, Source/Destination IP + Label.
#   CIC-DDoS2019   per-attack CSVs under 03-11/, cols 3/5 = Source/Destination
#                  IP, last col = Label. Verified to exclude nothing further:
#                  attacker 172.16.0.5 and victim 192.168.50.4 are both already
#                  absent from the 88-host pool.
#   LITNET-2020    allFlows.csv, 26.9 GB, CRLF, field 85 attack_a, 15/16 sa/da.
#                  Streamed once and cached -- see litnet_attack_endpoints().
#                  This is the pool the check was missing on: 9 of its 965 hosts
#                  SOURCE attack flows, among them 193.219.86.241, which sources
#                  all 747 smtp_b flows in the corpus. They qualified because
#                  litnet_loader aggregates per DESTINATION, so an outbound-only
#                  attacker accumulates zero attack windows.
#   CIC-IDS2018    IMPOSSIBLE from the corpus labels: the CSE-CIC-IDS2018 CSVs
#                  carry no IP columns at all (80 cols beginning at "Dst Port").
#                  Checked empirically instead -- all 300 pool hosts across the
#                  three days are internal 172.31.*, and no host in CIC's
#                  documented external attacker range (18.*/13.*) is in any pool.
#   CIC-IoT-2023   IMPOSSIBLE in kind: the labels are directory-derived (every
#                  window of an attack capture is attack regardless of host), so
#                  there is no per-host ground truth to check a role against, and
#                  this pool comes from the dedicated benign capture anyway.
CSV_DIR_2017 = os.path.join(BASE, 'datasets', 'CIC-IDS-2017', 'CSVs',
                            'TrafficLabelling ')   # trailing space is CIC's
ATTACK_ENDPOINT_CSVS = {
    ('CIC-IDS-2017', 'wednesday'): ['Wednesday-workingHours.pcap_ISCX.csv'],
    ('CIC-IDS-2017', 'friday'): ['Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
                                 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
                                 'Friday-WorkingHours-Morning.pcap_ISCX.csv'],
    ('CIC-IDS-2017', 'monday'): [],   # benign-only capture, no attack CSV exists
}

CSV_DIR_2019 = os.path.join(BASE, 'datasets', 'CICDDoS2019', '03-11')
# 88-column CICFlowMeter export: 3 = Source IP, 5 = Destination IP, 88 = Label.
COL_2019_SRC, COL_2019_DST, COL_2019_LABEL = 2, 4, 87

LITNET_ALLFLOWS = os.path.join(BASE, 'datasets', 'LITNET-2020', 'allFlows.csv')
LITNET_COMPLETE_BYTES = 26_943_158_910
# 85-column CRLF export: 15 = sa, 16 = da, 84 = attack_t, 85 = attack_a.
COL_LITNET_SA, COL_LITNET_DA, COL_LITNET_AT = 14, 15, 83
LITNET_ENDPOINT_CACHE = os.path.join(HERE, 'cache', 'litnet_attack_endpoints.json')

# Pools for which a label-derived role check cannot exist. Recorded rather than
# silently skipped -- the previous code returned None for every corpus but 2017
# and the resulting pools carried no trace of it.
# Some pools are narrower than "every uninvolved host in the capture", and that
# is a property of the upstream cache rather than of this exporter. It used to be
# hand-added to the shipped .meta.json after the fact, so the first re-export
# silently dropped it. Generated here instead.
SCOPE_CAVEATS = {
    ('LITNET-2020', 'per_ip'): (
        'NOT the corpus\'s full uninvolved population. The cache keeps only destinations matching '
        '193.219.* / 83.171.* plus the external victim 23.32.104.60 (run_litnet.py KEEP_PREFIXES) -- '
        'LITNET records outbound traffic to the whole internet and without that filter the per-IP '
        'dict exhausts memory. These are attack-free destinations of the PROTECTED network, which is '
        'the right population for a per-destination detector but is not every uninvolved host in the '
        'capture. One consequence is visible in the role check: 193.219.86.241 sources all 747 smtp_b '
        'flows in the corpus, but every smtp_b victim is an external mail server outside these '
        'prefixes, so it accumulated zero attack windows and had to be excluded on role instead.'),
    ('CIC_IOT_Dataset2023', 'benign_capture'): (
        'destinations of the dedicated benign capture, which includes public internet services and '
        'multicast groups (224.0.0.0/4) alongside the 192.168.137.* testbed hosts'),
}

_WHY_2018 = ('the CSE-CIC-IDS2018 CSVs carry no IP columns (80 columns beginning at '
             '"Dst Port"), so no label-derived role check is possible. Checked empirically '
             'instead: all 100 pool hosts are internal 172.31.*, and no host in CIC\'s '
             'documented external attacker range (18.*/13.*) appears in the pool')
_WHY_IOT = ('CIC-IoT-2023 labels are directory-derived -- every window of an attack capture is '
            'attack regardless of host -- so there is no per-host ground truth for a role check. '
            'This pool is the dedicated benign capture, which carries no attack labels at all')
ROLE_CHECK_IMPOSSIBLE = {
    ('CIC-IDS2018', 'wed'): _WHY_2018,
    ('CIC-IDS2018', 'thu'): _WHY_2018,
    ('CIC-IDS2018', 'fri'): _WHY_2018,
    ('CIC_IOT_Dataset2023', 'benign_capture'): _WHY_IOT,
}


def litnet_attack_endpoints():
    """Every IP that is source OR destination of an attack flow in LITNET-2020.

    LITNET's ground truth is one 26.9 GB CSV, so this streams it line by line and
    caches the (small) answer. Two things matter and both have bitten before:

      * the file is CRLF, so the last field carries a trailing \\r -- comparing
        it against '"1"' without allowing for that silently yields ZERO attack
        rows, which looks exactly like a clean corpus;
      * attack_a is the LAST column, so a row is an attack row iff the line ends
        with ,"1". Testing that before splitting keeps the scan to one string
        comparison for the ~92% of rows that are benign.

    A truncated source is refused outright: parts/ and allFlows.csv.truncated are
    88.5% of the corpus and contain 0 of the 93,583 udp_f and 0 of the 747 smtp_b
    flows, so a role check run against either would report a clean pool.
    """
    if os.path.exists(LITNET_ENDPOINT_CACHE):
        c = json.load(open(LITNET_ENDPOINT_CACHE))
        if c.get('source_bytes') == LITNET_COMPLETE_BYTES:
            return set(c['endpoints'])
        print(f"    !! stale LITNET endpoint cache ({c.get('source_bytes')} bytes), rebuilding")
    if not os.path.exists(LITNET_ALLFLOWS):
        print(f"    !! LITNET allFlows.csv absent, cannot role-check")
        return None
    size = os.path.getsize(LITNET_ALLFLOWS)
    if size != LITNET_COMPLETE_BYTES:
        print(f"    !! LITNET allFlows.csv is {size:,} B, not the complete "
              f"{LITNET_COMPLETE_BYTES:,} -- refusing to role-check against a truncated source")
        return None
    ips, n_attack, n_rows = set(), 0, 0
    with open(LITNET_ALLFLOWS, 'r', encoding='utf-8', errors='replace', newline='') as fh:
        fh.readline()
        for line in fh:
            n_rows += 1
            if not line.rstrip('\r\n').endswith(',"1"'):
                continue
            n_attack += 1
            parts = line.rstrip('\r\n').split(',')
            if len(parts) < 85:
                continue
            ips.add(parts[COL_LITNET_SA].strip('"'))
            ips.add(parts[COL_LITNET_DA].strip('"'))
    ips.discard('')
    print(f"    LITNET: streamed {n_rows:,} flows, {n_attack:,} attack-labelled, "
          f"{len(ips):,} distinct attack endpoints from {LITNET_ALLFLOWS} ({size:,} B)")
    os.makedirs(os.path.dirname(LITNET_ENDPOINT_CACHE), exist_ok=True)
    json.dump({'source': LITNET_ALLFLOWS, 'source_bytes': size, 'n_rows': n_rows,
               'n_attack_flows': n_attack, 'endpoints': sorted(ips)},
              open(LITNET_ENDPOINT_CACHE, 'w'))
    return ips


def cicddos2019_attack_endpoints():
    """Every IP that is source OR destination of a non-BENIGN flow on 03-11."""
    if not os.path.isdir(CSV_DIR_2019):
        print(f"    !! CICDDoS2019 CSV dir absent, cannot role-check")
        return None
    ips = set()
    for fn in sorted(os.listdir(CSV_DIR_2019)):
        if not fn.endswith('.csv'):
            continue
        with open(os.path.join(CSV_DIR_2019, fn), 'r', encoding='utf-8', errors='replace') as fh:
            fh.readline()
            for line in fh:
                parts = line.rstrip('\r\n').split(',')
                if len(parts) <= COL_2019_LABEL:
                    continue
                if parts[COL_2019_LABEL].strip().upper() in ('BENIGN', 'LABEL', ''):
                    continue
                ips.add(parts[COL_2019_SRC].strip())
                ips.add(parts[COL_2019_DST].strip())
    ips.discard('')
    return ips


def attack_endpoints(corpus, name):
    """Every IP appearing as source OR destination of a non-BENIGN flow.

    Streams the CSVs by line rather than parsing them -- these are 90-270 MB
    and this host has been OOM-killed before. Column positions in the 85-column
    TrafficLabelling files: 2 = Source IP, 4 = Destination IP, 85 = Label.
    """
    if (corpus, name) in ROLE_CHECK_IMPOSSIBLE:
        return None
    if corpus == 'LITNET-2020':
        return litnet_attack_endpoints()
    if corpus == 'CICDDoS2019':
        return cicddos2019_attack_endpoints()
    files = ATTACK_ENDPOINT_CSVS.get((corpus, name))
    if files is None:
        return None                      # no ground truth wired for this pool
    ips = set()
    for fn in files:
        path = os.path.join(CSV_DIR_2017, fn)
        if not os.path.exists(path):
            print(f"    !! endpoint CSV absent, cannot role-check: {fn}")
            continue
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            fh.readline()
            for line in fh:
                parts = line.rstrip('\r\n').split(',')
                if len(parts) < 85:
                    continue
                if parts[84].strip().upper() in ('BENIGN', 'LABEL', ''):
                    continue
                ips.add(parts[1].strip())
                ips.add(parts[3].strip())
    ips.discard('')
    return ips

# corpus -> [(pool name, cache, note)]
POOLS = [
    ('CIC-IDS-2017', 'monday',    'cicids2017_pcap_monday.json',
     'benign-only capture day; every host is attack-free by construction'),
    ('CIC-IDS-2017', 'wednesday', 'cicids2017_pcap_wednesday.json',
     'DoS day; hosts other than the two victims'),
    ('CIC-IDS-2017', 'friday',    'cicids2017_pcap_friday.json',
     'DDoS/PortScan/Botnet day; hosts other than the victim'),
    ('CIC-IDS2018',  'wed',       'cicids2018_pcap_wed.json',  'hosts other than the victim'),
    ('CIC-IDS2018',  'thu',       'cicids2018_pcap_thu.json',  'hosts other than the victim'),
    ('CIC-IDS2018',  'fri',       'cicids2018_pcap_fri.json',  'hosts other than the victim'),
    ('CICDDoS2019',  '03-11',     'cicddos_03-11_typed.json',
     'hosts other than the victim and the attacker'),
    ('LITNET-2020',  'per_ip',    'litnet_per_ip_cache.json',
     'attack-free destinations of the protected network. The cache is the one '
     'rebuilt from the COMPLETE allFlows.csv (26,943,158,910 B) -- verified by '
     '193.219.81.137, the target of 42,072 udp_f flows, carrying 301 attack '
     'windows here and none in the truncated build. Do not confuse it with the '
     'sibling litnet_per_ip_cache.truncated.json / .HELD in the same directory'),
    ('CIC_IOT_Dataset2023', 'benign_capture', 'cicios2023_benign.json',
     'the dedicated benign capture: CIC-IoT labels every window of an ATTACK '
     'capture as attack regardless of host, so uninvolved hosts cannot be '
     'recovered from those files'),
]


def main():
    out_root = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'), DEFAULT_OUT)
    minw = int(sys.argv[sys.argv.index('--min') + 1]) if '--min' in sys.argv else MIN_WINDOWS
    maxw = int(sys.argv[sys.argv.index('--max') + 1]) if '--max' in sys.argv else MAX_PER_HOST
    # Rebuilding every pool re-reads ~6 GB of caches. --only lets a corpus whose
    # source cache actually changed be redone on its own.
    only = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--only'), None)

    print(f"  {'corpus':21s} {'pool':16s} {'hosts':>7s} {'kept':>6s} {'windows':>10s} "
          f"{'trunc':>6s}  size")
    print("  " + "-" * 96)
    for corpus, name, cache, note in POOLS:
        if only and corpus != only:
            continue
        try:
            d = R.load_perip(cache)
        except Exception as e:
            print(f"  {corpus:21s} {name:16s} cache load failed: {str(e)[:40]}")
            continue
        endpoints = attack_endpoints(corpus, name)
        if endpoints is None:
            print(f"    role check: NOT PERFORMED -- "
                  f"{ROLE_CHECK_IMPOSSIBLE.get((corpus, name), 'no ground truth wired')[:88]}")
        clean = [(ip, rows) for ip, rows in d.items()
                 if len(rows) >= minw and not any(r.get('_is_attack') for r in rows)]
        n_role_excluded, role_excluded = 0, []
        if endpoints:
            before = {ip for ip, _ in clean}
            clean = [(ip, rows) for ip, rows in clean if ip not in endpoints]
            role_excluded = sorted(before - {ip for ip, _ in clean})
            n_role_excluded = len(role_excluded)
            if n_role_excluded:
                print(f"    role check: excluded {n_role_excluded} host(s) that are an "
                      f"endpoint of a non-BENIGN flow: {', '.join(role_excluded[:6])}"
                      + (' ...' if n_role_excluded > 6 else ''))
        clean.sort(key=lambda kv: -len(kv[1]))
        kept, total, truncated = [], 0, 0
        for ip, rows in clean:
            r = sorted(rows, key=lambda x: x.get('_id_time', x.get('_dt', 0)))
            if len(r) > maxw:
                r = r[:maxw]; truncated += 1
            kept.append((ip, r)); total += len(r)
        dropped = 0

        outdir = os.path.join(out_root, corpus, 'benign_pools')
        os.makedirs(outdir, exist_ok=True)
        fn = f'benign_pool_{name}.json'
        meta = {
            'corpus': corpus, 'pool': name, 'derived_from': cache, 'note': note,
            'kind': 'ATTACK-FREE HOST POOL — false-alarm denominator, no attacks',
            'selection': (f'every destination with zero attack-labelled windows '
                          f'and >= {minw} windows; each truncated to its first '
                          f'{maxw:,} windows chronologically'),
            'n_hosts_eligible': len(clean), 'n_hosts_kept': len(kept),
            'n_hosts_excluded_as_attack_endpoint': n_role_excluded,
            'hosts_excluded_as_attack_endpoint': role_excluded,
            'role_check': ('endpoint of any attack-labelled flow in the corpus ground truth, '
                           'source OR destination -- _is_attack alone is '
                           'direction-sensitive and lets attackers through'
                           if endpoints is not None else
                           ROLE_CHECK_IMPOSSIBLE.get((corpus, name),
                           'NOT PERFORMED -- no ground truth wired for this pool; membership '
                           'rests on the direction-sensitive _is_attack label only, which does '
                           'not exclude hosts that only SOURCE attack flows')),
            'role_check_performed': endpoints is not None,
            'n_hosts_truncated': truncated,
            **({'scope_caveat': SCOPE_CAVEATS[(corpus, name)]}
               if (corpus, name) in SCOPE_CAVEATS else {}),
            'n_windows': total, 'min_windows_per_host': minw,
            'max_windows_per_host': maxw,
            'usable_for': 'false-positive rate only — there are no attacks here',
        }
        p = os.path.join(outdir, fn)
        json.dump({'metadata': meta, 'per_ip_windows': dict(kept)}, open(p, 'w'))
        meta['bytes'] = os.path.getsize(p)
        meta['sha256'] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        json.dump(meta, open(os.path.join(outdir, fn.replace('.json', '.meta.json')), 'w'), indent=2)
        print(f"  {corpus:21s} {name:16s} {len(clean):7d} {len(kept):6d} {total:10,} "
              f"{truncated:6d}  {meta['bytes']/1e6:.0f} MB")
        del d, clean, kept
        gc.collect()

    # one SHA256SUMS per corpus pool directory
    for corpus in sorted({c for c, *_ in POOLS}):
        pd = os.path.join(out_root, corpus, 'benign_pools')
        if not os.path.isdir(pd):
            continue
        lines = []
        for f in sorted(os.listdir(pd)):
            if f.endswith('.json'):
                h = hashlib.sha256(open(os.path.join(pd, f), 'rb').read()).hexdigest()
                lines.append(f"{h}  {f}")
        open(os.path.join(pd, 'SHA256SUMS'), 'w').write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
