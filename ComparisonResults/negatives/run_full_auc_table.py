"""Full threshold-free ROC-AUC table (Table 13, extended) across all 13 victim cases.

Computes EVERY detector on identical splits / active features / eval order (benign-before-attack), so
it both reproduces the published columns and adds our two prototype paths:

  Our detectors:   level z-path (shipped), Innovation (forecast-error), Mahalanobis (Ledoit-Wolf)
  Baselines:       AnEWMA [5], Entropy [4], CUSUM [25], EWMA-CC [27], Shewhart, PEWMA [30], CV [33]

All training-free (fit on benign train; labels score AUC only). CESNET excluded (synthetic attacks).
Deterministic. Output: experiment/results/full_auc_table_results.json
"""
import os, sys, json, time
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from config import CACHE_DIR, RESULTS_DIR
from sklearn.metrics import roc_auc_score
import run_crosscorpus_auc as R
from anewma import anewma_scores
from entropy_detector import entropy_scores
from streaming_baselines import (cusum_scores, ewma_cc_scores, shewhart_scores,
                                 pewma_scores, cv_scores)
from mahalanobis import maha_scores
from innovation_path import innov_scores

OUT = os.path.join(RESULTS_DIR, 'full_auc_table_results.json')

# column key -> (display label, scorer or None for our_zscores)
SCORERS = [
    ('ours_z',   'Ours (z-path)',  R.our_zscores),
    ('innov',    'Ours-Innov',     innov_scores),
    ('maha',     'Ours-Maha',      maha_scores),
    ('anewma',   'AnEWMA [5]',     anewma_scores),
    ('entropy',  'Entropy [4]',    entropy_scores),
    ('cusum',    'CUSUM [25]',     cusum_scores),
    ('ewma_cc',  'EWMA-CC [27]',   ewma_cc_scores),
    ('shewhart', 'Shewhart',       shewhart_scores),
    ('pewma',    'PEWMA [30]',     pewma_scores),
    ('cv',       'CV [33]',        cv_scores),
]
COLS = [k for k, _, _ in SCORERS]


def eval_case(label, train, test):
    benign = [r for r in test if not r.get('_is_attack')]
    attack = [r for r in test if r.get('_is_attack')]
    if len(attack) < 5 or len(benign) < 5 or len(train) < 30:
        return None
    feats = R.active_features(train)
    if not feats:
        return None
    eval_rows = benign + attack                      # benign first → no recursive-detector poisoning
    y = np.array([0] * len(benign) + [1] * len(attack))
    row = {'label': label, 'n_attack': int(y.sum()), 'n_benign_test': int((y == 0).sum()),
           'n_features': len(feats), 'auc': {}}
    for key, _, fn in SCORERS:
        try:
            s = fn(train, eval_rows, feats)
            row['auc'][key] = None if s is None else round(float(roc_auc_score(y, s)), 3)
        except Exception as ex:
            row['auc'][key] = None
            print(f"    [{label}] {key} failed: {ex}")
    return row


def build_cases():
    """Same 13 cases as run_anewma_allsets.main (identical victims/splits)."""
    cases = []

    def add(label, train, test):
        r = eval_case(label, train, test)
        if r:
            cases.append(r)
            cells = "  ".join(f"{k}={r['auc'][k]}" for k in ('ours_z', 'innov', 'maha'))
            print(f"  {label:44s} atk={r['n_attack']:6d} feats={r['n_features']:2d}  {cells}")
        else:
            print(f"  {label:44s} (skipped)")

    mon = R.load_perip('cicids2017_pcap_monday.json'); fri = R.load_perip('cicids2017_pcap_friday.json')
    v = '192.168.10.50'
    if v in mon and v in fri:
        train = [r for r in mon[v] if not r.get('_is_attack')]
        test = sorted(fri[v], key=lambda r: r.get('_id_time', r.get('_dt', 0)))
        add('CIC-IDS-2017 Friday (cross-day)', train, test)
    del mon, fri

    for cache, v, tag in [('cicids2018_pcap_wed.json', '172.31.69.28', 'Wed (LOIC-UDP+HOIC)'),
                          ('cicids2018_pcap_thu.json', '172.31.69.25', 'Thu (GoldenEye+Slowloris)'),
                          ('cicids2018_pcap_fri.json', '172.31.69.25', 'Fri (Hulk+SlowHTTPTest)')]:
        try:
            d = R.load_perip(cache)
            if v in d:
                tr, te = R.split_within_cache(d[v]); add(f'CIC-IDS-2018 {tag}', tr, te)
        except Exception as ex:
            print(f"  CIC-2018 {tag} skipped: {ex}")

    try:
        d = R.load_perip('cicddos_pcap_features.json'); v = '192.168.50.4'
        if v in d:
            tr, te = R.split_within_cache(d[v]); add('CIC-DDoS2019 (victim flood)', tr, te)
    except Exception as ex:
        print("  CIC-DDoS2019 skipped:", ex)

    try:
        lit = json.load(open(os.path.join(CACHE_DIR, 'litnet_per_ip_cache.json')))
        for v, tag in [('193.219.81.138', 'Code Red'), ('193.219.88.36', 'Smurf'),
                       ('23.32.104.60', 'HTTP flood')]:
            if v in lit:
                tr, te = R.split_within_cache(lit[v]); add(f'LITNET {tag}', tr, te)
        del lit
    except Exception as ex:
        print("  LITNET skipped:", ex)

    try:
        ben = R.load_perip('cicios2023_benign.json')
        for fam, v in [('DDoS-SlowLoris', '192.168.137.82'), ('DDoS-SYN_Flood', '192.168.137.99'),
                       ('DDoS-ICMP_Fragmentation', '192.168.137.41'),
                       ('DDoS-HTTP_Flood', '192.168.137.82'), ('Mirai-udpplain', '192.168.137.209')]:
            fp = f'cicios2023_{fam}.json'
            if not os.path.exists(os.path.join(CACHE_DIR, fp)):
                continue
            fam_d = R.load_perip(fp)
            brows = sorted([r for r in ben.get(v, []) if not r.get('_is_attack')],
                           key=lambda r: r.get('_id_time', r.get('_dt', 0)))
            arows = [r for r in fam_d.get(v, []) if r.get('_is_attack')]
            n = len(brows); ntr = int(n * 0.6); nbr = int(n * 0.2)
            train = brows[:ntr + nbr]
            test = sorted(brows[ntr + nbr:] + arows, key=lambda r: r.get('_id_time', r.get('_dt', 0)))
            add(f'CIC-IoT {fam}', train, test)
            del fam_d
        del ben
    except Exception as ex:
        print("  CIC-IoT skipped:", ex)
    return cases


def main():
    t0 = time.time()
    cases = build_cases()
    # mean / min per column (skip None for that column; report n)
    summary = {}
    for k in COLS:
        vals = [c['auc'][k] for c in cases if c['auc'][k] is not None]
        summary[k] = {'mean': round(float(np.mean(vals)), 3) if vals else None,
                      'min': round(float(np.min(vals)), 3) if vals else None, 'n': len(vals)}

    labels = {k: lbl for k, lbl, _ in SCORERS}
    # markdown table
    hdr = "| Corpus (victim) | " + " | ".join(labels[k] for k in COLS) + " |"
    sep = "|" + "---|" * (len(COLS) + 1)
    lines = [hdr, sep]
    for c in cases:
        cells = " | ".join("n/a" if c['auc'][k] is None else f"{c['auc'][k]:.3f}" for k in COLS)
        lines.append(f"| {c['label']} | {cells} |")
    mean_cells = " | ".join("n/a" if summary[k]['mean'] is None else
                            (f"{summary[k]['mean']:.3f}" + ("" if summary[k]['n'] == len(cases)
                             else f" ({summary[k]['n']})")) for k in COLS)
    min_cells = " | ".join("n/a" if summary[k]['min'] is None else f"{summary[k]['min']:.3f}" for k in COLS)
    lines.append(f"| **Mean ({len(cases)} cases)** | {mean_cells} |")
    lines.append(f"| **Min (worst-case)** | {min_cells} |")
    table_md = "\n".join(lines)
    print("\n" + table_md)

    json.dump({'metadata': {'n_cases': len(cases), 'columns': labels,
                            'eval': 'threshold-free ROC-AUC, benign-before-attack, identical splits/feats',
                            'cesnet': 'excluded (synthetic attacks)',
                            'runtime_s': round(time.time() - t0, 1)},
               'summary': summary, 'cases': cases, 'table_markdown': table_md},
              open(OUT, 'w'), indent=2)
    print("\nSaved:", OUT)


if __name__ == '__main__':
    main()
