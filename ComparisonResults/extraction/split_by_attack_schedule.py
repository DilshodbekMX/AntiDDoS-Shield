"""Split per-DAY caches into per-ATTACK-TYPE caches, for CIC-IDS-2017 and -2018.

Generalises split_cicids2018_by_attack.py to both corpora. The day-level caches
blend distinct attacks into one scenario, and the blend describes none of them.
CIC-IDS-2017 Wednesday is the worst case: four separate DoS attacks in one
cache. Its Friday cache is the more consequential one, because it backs the
manuscript's headline cross-day scenario while 261 of its 1,427 attack windows
are PortScan, which is not a denial-of-service attack at all.

No pcap is re-parsed; the caches already carry per-window unix timestamps.

TIMEZONES DIFFER BETWEEN THE TWO CORPORA AND ARE DERIVED, NOT ASSUMED. Each was
fixed by matching the EXISTING _is_attack labels against the published
schedule:

  CIC-IDS-2018 -> UTC-4.  Thursday's labelled blocks are UTC 13:26:44-14:08:56
    and 14:59:05-15:39:59 against a schedule of 09:26-10:09 and 10:59-11:40.
  CIC-IDS-2017 -> UTC-3.  Heartbleed is labelled 18:12:15-18:31:59 UTC against
    a schedule of 15:12-15:32. At UTC-4 every 2017 attack lands exactly one
    hour early, so the capture clock is NOT the EDT the calendar implies.

Assuming a single offset for both would have shifted every 2017 attack by an
hour and silently mislabelled the lot.

LABELS ARE NEVER REWRITTEN. _is_attack is preserved exactly; only _attack_type
is added, from whichever scheduled window contains the timestamp. Windows
labelled attack but outside every scheduled window are reported and excluded,
never absorbed.

BUT THE SCHEDULE IS NOT THE ATTACK EDGE, and the difference contaminates the
benign pool. THIS APPLIES TO CIC-IDS-2018 ONLY: it is the corpus that labels
_is_attack from the published schedule. CIC-IDS-2017 does not -- there
_is_attack comes from a time-blind 5-tuple join against CIC's own labelled-flow
CSVs, and the schedule is used only to separate one attack from another once a
window is already labelled. An earlier revision of this docstring asserted that
both corpora label from the schedule, which is false and is why 2017's orphan
windows (attack-labelled but outside every scheduled span) can exist at all.

On CIC-IDS-2018, then: traffic that starts before or drains after a scheduled
minute is carried as BENIGN -- and lands in the split-conformal calibration set,
where a single flood window sets a threshold no later attack can cross. Three
leaks are measured (all reproducible from the files this script reads):

  Wed-21-02 LOIC-UDP   CIC's own CSV labels the flood from 10:08:51; the
                       schedule says 10:09. 8 windows of 39k-100k pps at
                       udp_ratio 1.000 ship as benign, and they are the
                       calibration maximum for BOTH Wednesday slices --
                       48x HOIC's own attack maximum.
  Wed-21-02 HOIC       runs unbroken across its 15:05 boundary at ~1,100 pps
                       and decays to 103 pps at 15:05:53 before a 100x cliff
                       to 1 pps. 54 windows of drain labelled benign. The
                       Wednesday CSV is 12-hour and truncated at 14:33, so
                       this one is provable only from the packets.
  Thu-15-02 Slowloris  CSV runs to 11:42:01 against a schedule ending 11:40.
                       121 s -- the largest measured leak, and the reason
                       GUARD_SEC is 180 rather than 120.

The correction is a GUARD BAND, not a relabelling. Benign windows within
GUARD_SEC of any labelled attack span on that day are QUARANTINED: dropped
from the slice entirely, counted as neither attack nor benign. Three properties
make this defensible where a per-corpus fix would not be:

  * it is magnitude-blind. The rule is temporal proximity to a labelled
    attack. It contains no packets-per-second test, so it cannot be accused of
    selecting away the benign windows that happen to be inconvenient.
  * it never invents a positive. DR denominators are unchanged, so every
    change in DR comes from a calibration set that is cleaner, not larger.
  * it needs no timestamped CSV. CIC-IDS-2017 ships only the ML-CVE flow
    files, which have no Timestamp column at all -- a CSV-union rule would
    have been available for 2018 and not for 2017, and the two corpora would
    have been corrected under different definitions.

Each emitted cache is a single-attack scenario: the victim's benign windows for
that day plus only that attack's windows. See the caveats in the README this
writes -- same-day slices share a benign pool, and removing the other attacks
leaves temporal holes that recursive detectors cannot see.

Usage:  python3 split_by_attack_schedule.py [2017|2018|all] [--dry-run] [--out DIR]
                                             [--guard SECONDS]

--out defaults to datasets/extracted/<corpus>/, matching the other exporters.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, gc
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from config import CACHE_DIR

TREE_DIR = _os.path.join(_BASE, 'datasets', 'extracted')
# corpus key -> its directory name in the tree (CIC's own naming is inconsistent)
TREE_SUBDIR = {'2017': 'CIC-IDS-2017', '2018': 'CIC-IDS2018'}

# Quarantine half-width. Sized from the largest MEASURED leak (Thu-15-02
# Slowloris, 121 s past its scheduled end per CIC's CSV) plus ~50% margin.
# Cost at 180 s is 4-13% of each day's benign pool; see --guard for sweeps.
GUARD_SEC = 180

# corpus -> (utc_offset_hours, [(day-key, cache, date, [(attack, victim, start, end)])])
CORPORA = {
    '2018': (-4, [
        ('Thu-15-02', 'cicids2018_pcap_thu.json', '2018-02-15', [
            ('DoS-GoldenEye',    '172.31.69.25', '09:26', '10:09'),
            ('DoS-Slowloris',    '172.31.69.25', '10:59', '11:40')]),
        ('Fri-16-02', 'cicids2018_pcap_fri.json', '2018-02-16', [
            ('DoS-SlowHTTPTest', '172.31.69.25', '10:12', '11:08'),
            ('DoS-Hulk',         '172.31.69.25', '13:45', '14:19')]),
        # Tuesday's capture ENDS at 13:29:16 local, so LOIC-UDP is truncated
        # three minutes short of its scheduled 13:32 finish. 905 windows are
        # present, which is ample, but the slice is not the full attack.
        ('Tue-20-02', 'cicids2018_pcap_tue.json', '2018-02-20', [
            ('DDoS-LOIC-HTTP',   '172.31.69.25', '10:12', '11:17'),
            ('DDoS-LOIC-UDP',    '172.31.69.25', '13:13', '13:32')]),
        ('Wed-21-02', 'cicids2018_pcap_wed.json', '2018-02-21', [
            ('DDoS-LOIC-UDP',    '172.31.69.28', '10:09', '10:43'),
            ('DDoS-HOIC',        '172.31.69.28', '14:05', '15:05')]),
    ]),
    '2017': (-3, [
        ('Wed-05-07', 'cicids2017_pcap_wednesday.json', '2017-07-05', [
            ('DoS-Slowloris',    '192.168.10.50', '09:47', '10:10'),
            ('DoS-Slowhttptest', '192.168.10.50', '10:14', '10:35'),
            ('DoS-Hulk',         '192.168.10.50', '10:43', '11:00'),
            ('DoS-GoldenEye',    '192.168.10.50', '11:10', '11:23'),
            ('Heartbleed',       '192.168.10.51', '15:12', '15:32')]),
        ('Fri-07-07', 'cicids2017_pcap_friday.json', '2017-07-07', [
            ('PortScan',         '192.168.10.50', '13:55', '15:27'),
            ('DDoS-LOIT',        '192.168.10.50', '15:56', '16:16')]),
        # Friday Botnet-ARES targets 192.168.10.5/.8/.9/.14/.15, never .50, so
        # the cached Friday victim carries none of it -- confirmed, 0 windows.
    ]),
}


def main():
    which = next((a for a in sys.argv[1:] if a in ('2017', '2018', 'all')), 'all')
    dry = '--dry-run' in sys.argv
    # Defaults to the extracted tree, as every other exporter does. It used to
    # default to CACHE_DIR while both READMEs invoked it with no --out, so
    # following the documented recipe wrote 15 slices into experiments_copy/cache/
    # under filenames IDENTICAL to the shipped tree's -- a stale pre-guard
    # shadow set that any load-by-basename would pick up instead.
    outdir = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'), None)
    guard = int(next((sys.argv[i + 1] for i, a in enumerate(sys.argv)
                      if a == '--guard'), GUARD_SEC))
    keys = ['2017', '2018'] if which == 'all' else [which]
    written = []

    for corpus in keys:
        out_corpus = outdir or os.path.join(TREE_DIR, TREE_SUBDIR[corpus])
        off, days = CORPORA[corpus]
        TZ = timezone(timedelta(hours=off))
        loc = lambda t: datetime.fromtimestamp(t, TZ).strftime('%H:%M:%S')

        def ep(date, hhmm):
            y, mo, dd = (int(x) for x in date.split('-'))
            h, m = (int(x) for x in hhmm.split(':'))
            return datetime(y, mo, dd, h, m, tzinfo=TZ).timestamp()

        print(f"\n########## CIC-IDS-{corpus}   (UTC{off:+d}) ##########")
        for daykey, cache, date, attacks in days:
            path = os.path.join(CACHE_DIR, cache)
            if not os.path.exists(path):
                print(f"  {cache}: ABSENT"); continue
            d = json.load(open(path))
            d = d.get('per_ip_windows', d)
            print(f"\n{cache}")
            for victim in sorted({a[1] for a in attacks}):
                rows = sorted(d.get(victim, []), key=lambda r: r.get('_dt', 0))
                if not rows:
                    print(f"  victim {victim}: absent"); continue
                mine = [a for a in attacks if a[1] == victim]
                spans = {a: (ep(date, s), ep(date, e)) for a, _, s, e in mine}
                for r in rows:
                    t = r.get('_dt', 0)
                    r['_attack_type'] = next(
                        (a for a, (s, e) in spans.items() if s <= t <= e), None)
                lab = [r for r in rows if r.get('_is_attack')]
                orph = [r for r in lab if r['_attack_type'] is None]
                print(f"  victim {victim}: {len(rows)} windows, {len(lab)} attack-labelled")
                if orph:
                    print(f"    !! {len(orph)} attack-labelled outside every scheduled window "
                          f"({loc(min(r['_dt'] for r in orph))}-{loc(max(r['_dt'] for r in orph))}) "
                          f"-- excluded")
                # Label-boundary guard, anchored on the SCHEDULED span.
                #
                # This used to compute a union with the "observed extent" of
                # each attack's labelled windows. That term was dead code:
                # _attack_type is assigned only where schedule_start <= t <=
                # schedule_end, so the observed extent is by construction a
                # SUBSET of the schedule and min()/max() against it can only
                # ever return the schedule bounds. Rebuilding with the term
                # removed reproduces the shipped benign counts exactly. The
                # comment that used to sit here asserted the opposite of what
                # the code did, which is worse than having no comment.
                #
                # What the term was reaching for is real but is NOT reachable
                # this way: an attack that overruns its schedule leaves
                # ORPHANS -- attack-labelled windows outside every scheduled
                # span -- and those are excluded from every slice rather than
                # guarded around. Measured, the benign kept within GUARD_SEC of
                # an orphan is unremarkable: 181 windows at a maximum of 137
                # pps on 2017 Wed .50 and 248 at 84 pps on Fri .50, against
                # kept-benign maxima of 234 and 441 pps on those same victims.
                # There is no calibration-poisoning signature there, so the
                # guard is left schedule-anchored rather than widened to
                # orphans, which would discard ~430 more benign windows on
                # 2017 for no measurable gain.
                # EDGE BANDS ONLY -- never the span interior. A benign-labelled
                # window DURING a labelled attack must stay in the pool: if the
                # detector fires on it that is a false positive and has to be
                # counted. Quarantining the interior would delete precisely the
                # windows the detector is most likely to alarm on, and would
                # cut 1,393 of CIC-IDS-2017 Friday's 4,390 benign windows --
                # a 32% reduction of the FPR denominator, in our own favour.
                guards = []
                for a, (lo, hi) in spans.items():
                    guards.append((lo - guard, lo - 1e-9))
                    guards.append((hi + 1e-9, hi + guard))
                allben = [r for r in rows if not r.get('_is_attack')]
                ben = [r for r in allben
                       if not any(g0 <= r.get('_dt', 0) <= g1 for g0, g1 in guards)]
                qrows = [r for r in allben
                         if any(g0 <= r.get('_dt', 0) <= g1 for g0, g1 in guards)]
                n_quar = len(qrows)
                if n_quar:
                    qmax = max(r.get('packets_per_sec', 0) or 0 for r in qrows)
                    bmax = max((r.get('packets_per_sec', 0) or 0 for r in ben), default=0)
                    print(f"    guard +/-{guard}s: quarantined {n_quar} of {len(allben)} benign "
                          f"windows  [max pps {qmax:,.0f} removed vs {bmax:,.0f} kept]")
                for atk, _, s, e in mine:
                    arows = [r for r in rows if r['_attack_type'] == atk and r.get('_is_attack')]
                    if not arows:
                        print(f"    {atk:18s} 0 windows in {s}-{e} -- skipped"); continue
                    name = f"{daykey}_{atk}.json"
                    print(f"    {atk:18s} {len(arows):5d} attack + {len(ben):5d} benign -> {name}"
                          f"  [{loc(min(r['_dt'] for r in arows))}-{loc(max(r['_dt'] for r in arows))}]")
                    if not dry:
                        os.makedirs(out_corpus, exist_ok=True)
                        json.dump({'metadata': {
                            'corpus': f'CIC-IDS-{corpus}', 'derived_from': cache,
                            'day': daykey, 'date': date, 'victim': victim,
                            'attack_type': atk, 'schedule_local': f'{s}-{e}',
                            'timezone': f'UTC{off:+d} (derived from label/schedule match)',
                            'n_attack_windows': len(arows), 'n_benign_windows': len(ben),
                            'guard_seconds': guard,
                            'n_benign_before_guard': len(allben),
                            'n_benign_quarantined': n_quar,
                            'note': ('single-attack slice of a per-day cache; _is_attack '
                                     'preserved from the source and never rewritten, '
                                     '_attack_type added from the published schedule; '
                                     f'benign windows within {guard}s of any labelled attack '
                                     'span that day are quarantined -- dropped from the slice, '
                                     'counted as neither attack nor benign -- because the '
                                     'schedule bounds do not coincide with the true attack '
                                     'edges and the leakage lands in the calibration set'),
                        }, 'per_ip_windows': {victim: sorted(ben + arows, key=lambda r: r['_dt'])}},
                            open(os.path.join(out_corpus, name), 'w'))
                        written.append(name)
            del d; gc.collect()

    dest = outdir or f"{TREE_DIR}/<corpus>/"
    print(f"\n{'DRY RUN -- nothing written' if dry else f'wrote {len(written)} caches to {dest}'}")


if __name__ == '__main__':
    main()
