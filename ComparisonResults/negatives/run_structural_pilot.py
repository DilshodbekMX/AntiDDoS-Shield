"""Single-feature separation pilot for inbound-only L3/L4 STRUCTURAL discriminators.

Principle under test: organic benign traffic is heterogeneous; attack-tool traffic is homogeneous /
non-completing. Discriminate by regularity and header structure, not volume. Each candidate must pass
"anomalous-for-flood AND normal-for-benign-burst" as a SINGLE-FEATURE separation BEFORE any
integration (l2-detector-prototyping discipline; no tuning, no per-corpus direction flips).

What this does NOT do: re-extract pcaps. It uses only counters already in the committed caches
(Group 0 + the already-stubbed Group-1/2 fields that happen to be populated). Group-1/2 features that
need new extraction (ttl_entropy, src_port_entropy, pkt_size_entropy, IAT variance) are out of scope
here — this pilot decides whether the FREE inbound ratios are worth anything first.

Candidate features (committed one-sided direction from mechanism; NOT chosen to flatter a corpus):
  ack_to_syn          low  = anomalous  (spoofed/non-completing flood: SYNs without ACK follow-through)
  nonsyn_to_syn       low  = anomalous  (mostly-SYN traffic = handshake flood)
  tcp_completion_rate low  = anomalous  (existing field; low completion = flood)
  bytes_per_packet    low  = anomalous  (tiny uniform packets = tool flood)
  small_pkt_ratio     high = anomalous  (uniform small packets)
  syn_share           high = anomalous  (SYN-dominated arrival mix)

Metrics per (case, feature):
  AUC_all   ROC-AUC(attack vs ALL benign), committed direction.
  AUC_burst ROC-AUC(attack vs HIGH-VOLUME benign), top-quartile benign by packets_per_sec — the
            "normal-for-benign-burst" test: a feature that only tracks volume collapses here.
A feature "clears" on a case if AUC_all >= 0.70 AND AUC_burst >= 0.70 (separates attack from benign
bursts, not just from quiet benign). Direction is fixed; AUC<0.5 means it works the OPPOSITE way on
that corpus (reported honestly, not flipped).

Deterministic. Output: experiment/results/structural_pilot_results.json
"""
import os, sys, json, time
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from config import CACHE_DIR, RESULTS_DIR
from sklearn.metrics import roc_auc_score

EPS = 1e-6
CAP = 1e6
CLEAR = 0.70
OUT = os.path.join(RESULTS_DIR, 'structural_pilot_results.json')


def F(r, k):
    return float(r.get(k, 0.0) or 0.0)


def features(r):
    syn = F(r, 'syn_per_sec'); ack = F(r, 'ack_per_sec'); pkts = F(r, 'packets_per_sec')
    return {
        'ack_to_syn':          ('low',  min(ack / (syn + EPS), CAP)),
        'nonsyn_to_syn':       ('low',  min(max(pkts - syn, 0.0) / (syn + EPS), CAP)),
        'tcp_completion_rate': ('low',  F(r, 'tcp_completion_rate')),
        'bytes_per_packet':    ('low',  F(r, 'bytes_per_packet')),
        'small_pkt_ratio':     ('high', F(r, 'small_pkt_ratio')),
        'syn_share':           ('high', syn / (pkts + EPS)),
    }


FEATS = list(features({}).keys())


def oriented(vals, direction):
    v = np.array(vals, dtype=float)
    return v if direction == 'high' else -v


def auc_safe(y, score):
    if len(set(y)) < 2:
        return None
    s = np.array(score, dtype=float)
    if np.all(s == s[0]):
        return 0.5
    return round(float(roc_auc_score(y, s)), 3)


def evaluate_case(label, attack_rows, benign_rows):
    if len(attack_rows) < 20 or len(benign_rows) < 40:
        return None
    # high-volume benign = top quartile by packets_per_sec (the "burst" population)
    bpps = np.array([F(r, 'packets_per_sec') for r in benign_rows])
    thr = np.quantile(bpps, 0.75)
    burst_benign = [r for r, p in zip(benign_rows, bpps) if p >= thr]
    out = {'label': label, 'n_attack': len(attack_rows), 'n_benign': len(benign_rows),
           'n_benign_burst': len(burst_benign), 'features': {}}
    for f in FEATS:
        d = features(attack_rows[0])[f][0]
        a = [features(r)[f][1] for r in attack_rows]
        b = [features(r)[f][1] for r in benign_rows]
        bb = [features(r)[f][1] for r in burst_benign]
        y_all = [1] * len(a) + [0] * len(b)
        auc_all = auc_safe(y_all, list(oriented(a, d)) + list(oriented(b, d)))
        y_brs = [1] * len(a) + [0] * len(bb)
        auc_brs = auc_safe(y_brs, list(oriented(a, d)) + list(oriented(bb, d))) if bb else None
        clears = (auc_all is not None and auc_all >= CLEAR and
                  auc_brs is not None and auc_brs >= CLEAR)
        out['features'][f] = {'dir': d, 'auc_all': auc_all, 'auc_burst': auc_brs, 'clears': clears}
    return out


def load(path):
    d = json.load(open(os.path.join(CACHE_DIR, path)))
    return d.get('per_ip_windows', d)


def main():
    t0 = time.time()
    cases = []

    def add(label, atk, ben):
        r = evaluate_case(label, atk, ben)
        if r:
            cases.append(r)
            cl = [f for f, v in r['features'].items() if v['clears']]
            print(f"{label:42s} atk={r['n_attack']:6d} ben={r['n_benign']:5d} "
                  f"burst={r['n_benign_burst']:4d}  clears: {cl if cl else '—'}")
        else:
            print(f"{label:42s} (skipped)")

    # CIC-IDS-2017 victim (LOIC HTTP DDoS) — benign = Monday + Friday-benign
    try:
        mon = load('cicids2017_pcap_monday.json'); fri = load('cicids2017_pcap_friday.json')
        v = '192.168.10.50'
        atk = [r for r in fri.get(v, []) if r.get('_is_attack')]
        ben = [r for r in mon.get(v, []) if not r.get('_is_attack')] + \
              [r for r in fri.get(v, []) if not r.get('_is_attack')]
        add('CIC-IDS-2017 (LOIC HTTP DDoS)', atk, ben)
        del mon, fri
    except Exception as ex:
        print("CIC-2017 skipped:", ex)

    # CIC-IDS-2018 Wed/Thu/Fri
    for cache, v, tag in [('cicids2018_pcap_wed.json', '172.31.69.28', 'Wed LOIC-UDP+HOIC'),
                          ('cicids2018_pcap_thu.json', '172.31.69.25', 'Thu GoldenEye+Slowloris'),
                          ('cicids2018_pcap_fri.json', '172.31.69.25', 'Fri Hulk+SlowHTTPTest')]:
        try:
            d = load(cache)
            rows = d.get(v, [])
            add(f'CIC-IDS-2018 {tag}', [r for r in rows if r.get('_is_attack')],
                [r for r in rows if not r.get('_is_attack')])
        except Exception as ex:
            print(f"CIC-2018 {tag} skipped:", ex)

    # CIC-DDoS2019
    try:
        d = load('cicddos_pcap_features.json'); v = '192.168.50.4'; rows = d.get(v, [])
        add('CIC-DDoS2019 (victim flood)', [r for r in rows if r.get('_is_attack')],
            [r for r in rows if not r.get('_is_attack')])
    except Exception as ex:
        print("CIC-DDoS2019 skipped:", ex)

    # LITNET victims
    try:
        lit = json.load(open(os.path.join(CACHE_DIR, 'litnet_per_ip_cache.json')))
        for v, tag in [('193.219.81.138', 'Code Red worm'), ('193.219.88.36', 'Smurf'),
                       ('23.32.104.60', 'HTTP flood')]:
            rows = lit.get(v, [])
            add(f'LITNET {tag}', [r for r in rows if r.get('_is_attack')],
                [r for r in rows if not r.get('_is_attack')])
        del lit
    except Exception as ex:
        print("LITNET skipped:", ex)

    # CIC-IoT-2023 per-family victims (same IPs the AUC harness selected)
    try:
        ben = load('cicios2023_benign.json')
        for fam, v in [('DDoS-SlowLoris', '192.168.137.82'), ('DDoS-SYN_Flood', '192.168.137.99'),
                       ('DDoS-ICMP_Fragmentation', '192.168.137.41'),
                       ('DDoS-HTTP_Flood', '192.168.137.82'), ('Mirai-udpplain', '192.168.137.209')]:
            fp = f'cicios2023_{fam}.json'
            if not os.path.exists(os.path.join(CACHE_DIR, fp)):
                continue
            fam_d = load(fp)
            atk = [r for r in fam_d.get(v, []) if r.get('_is_attack')]
            bn = [r for r in ben.get(v, []) if not r.get('_is_attack')]
            add(f'CIC-IoT-2023 {fam}', atk, bn)
            del fam_d
        del ben
    except Exception as ex:
        print("CIC-IoT skipped:", ex)

    # summary: per-feature, how many cases cleared
    summary = {f: {'cleared_cases': sum(1 for c in cases if c['features'][f]['clears']),
                   'n_cases': len(cases),
                   'median_auc_all': round(float(np.median(
                       [c['features'][f]['auc_all'] for c in cases
                        if c['features'][f]['auc_all'] is not None])), 3) if cases else None,
                   'median_auc_burst': round(float(np.median(
                       [c['features'][f]['auc_burst'] for c in cases
                        if c['features'][f]['auc_burst'] is not None])), 3) if cases else None}
               for f in FEATS}
    print("\n=== per-feature: cases cleared (AUC_all>=0.70 AND AUC_burst>=0.70) ===")
    for f, s in summary.items():
        print(f"  {f:22s} {s['cleared_cases']}/{s['n_cases']}  "
              f"med AUC_all={s['median_auc_all']}  med AUC_burst={s['median_auc_burst']}")

    json.dump({'metadata': {'clear_threshold': CLEAR, 'directions_committed': True,
                            'note': 'inbound-only, no re-extraction; one-sided per mechanism; '
                                    'AUC_burst = attack vs top-quartile-volume benign',
                            'runtime_s': round(time.time() - t0, 1)},
               'per_feature_summary': summary, 'cases': cases}, open(OUT, 'w'), indent=2)
    print("Saved:", OUT)


if __name__ == '__main__':
    main()
