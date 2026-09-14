"""DR and FPR for every detector across all 13 victim cases, at a matched conformal operating point.

Each detector emits a per-window score; we conformally calibrate it on a held-out BENIGN slice and
alarm when the right-tail p-value <= alpha (target per-window FPR). Then:
  DR  = fraction of ATTACK test windows alarmed
  FPR = fraction of BENIGN test windows alarmed
Same statistic ranking as the AUC table, but now at a fixed operating point so "high DR / low FPR" is
directly visible. Single conformal paths (not the OR ensemble): "Ours (z)" is the level path alone.

Splits (benign only in fit/calib — training-free):
  within-cache cases: benign 60% fit / 20% calib / 20% test  + all attack -> test
  CIC-IDS-2017       : cross-day — fit 80% Monday benign / calib 20% Monday benign / test = Friday
Eval order benign-before-attack so a sustained attack cannot poison recursive detectors.
Deterministic. alpha grid reported; headline alpha = 0.01. Output: results/full_drfpr_table_results.json
"""
import os, sys, json, time
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from config import CACHE_DIR, RESULTS_DIR
import run_crosscorpus_auc as R
from run_fpr_conformal import pval
from anewma import anewma_scores
from entropy_detector import entropy_scores
from streaming_baselines import (cusum_scores, ewma_cc_scores, shewhart_scores, pewma_scores, cv_scores)
from mahalanobis import maha_scores
from innovation_path import innov_scores

OUT = os.path.join(RESULTS_DIR, 'full_drfpr_table_results.json')
ALPHA = 0.01
ALPHA_GRID = [0.001, 0.01, 0.05]

SCORERS = [
    ('ours_z',   'Ours (z)',     R.our_zscores),
    ('innov',    'Ours-Innov',   innov_scores),
    ('maha',     'Ours-Maha',    maha_scores),
    ('anewma',   'AnEWMA [5]',   anewma_scores),
    ('entropy',  'Entropy [4]',  entropy_scores),
    ('cusum',    'CUSUM [25]',   cusum_scores),
    ('ewma_cc',  'EWMA-CC [27]', ewma_cc_scores),
    ('shewhart', 'Shewhart',     shewhart_scores),
    ('pewma',    'PEWMA [30]',   pewma_scores),
    ('cv',       'CV [33]',      cv_scores),
]
COLS = [k for k, _, _ in SCORERS]
LABELS = {k: l for k, l, _ in SCORERS}


def drfpr(fit_rows, calib_rows, test_benign, attack, feats, alphas):
    """Return {col: {alpha: (DR, FPR)}} for all detectors on one case."""
    eval_rows = list(calib_rows) + list(test_benign) + list(attack)
    nB = len(test_benign); nA = len(attack); nc = len(calib_rows)
    out = {}
    for key, _, fn in SCORERS:
        try:
            s = fn(fit_rows, eval_rows, feats)
        except Exception:
            s = None
        if s is None:
            out[key] = {a: (None, None) for a in alphas}
            continue
        cs = np.sort(np.asarray(s[:nc], dtype=float))
        ts = np.asarray(s[nc:], dtype=float)              # aligns with test_benign + attack
        pv = np.array([pval(cs, x) for x in ts])
        res = {}
        for a in alphas:
            dec = pv <= a
            dr = round(100.0 * dec[nB:nB + nA].mean(), 1) if nA else None
            fpr = round(100.0 * dec[:nB].mean(), 1) if nB else None
            res[a] = (dr, fpr)
        out[key] = res
    return out


def within_split(rows):
    rows = sorted(rows, key=lambda r: r.get('_id_time', r.get('_dt', 0)))
    ben = [r for r in rows if not r.get('_is_attack')]
    atk = [r for r in rows if r.get('_is_attack')]
    n = len(ben); a = int(n * 0.6); b = int(n * 0.8)
    return ben[:a], ben[a:b], ben[b:], atk          # fit, calib, test_benign, attack


def main():
    t0 = time.time()
    cases = []

    def add(label, fit_rows, calib_rows, test_benign, attack):
        if len(attack) < 5 or len(test_benign) < 5 or len(fit_rows) < 30 or len(calib_rows) < 10:
            print(f"  {label:42s} (skipped)"); return
        feats = R.active_features(fit_rows)
        if not feats:
            print(f"  {label:42s} (no feats)"); return
        res = drfpr(fit_rows, calib_rows, test_benign, attack, feats, ALPHA_GRID)
        cases.append({'label': label, 'n_attack': len(attack), 'n_benign_test': len(test_benign),
                      'n_features': len(feats), 'drfpr': {k: {str(a): res[k][a] for a in ALPHA_GRID}
                                                          for k in COLS}})
        z = res['ours_z'][ALPHA]; iv = res['innov'][ALPHA]
        print(f"  {label:42s} a=0.01  ours(z) DR={z[0]} FPR={z[1]}   innov DR={iv[0]} FPR={iv[1]}")

    # CIC-IDS-2017 cross-day
    mon = R.load_perip('cicids2017_pcap_monday.json'); fri = R.load_perip('cicids2017_pcap_friday.json')
    v = '192.168.10.50'
    if v in mon and v in fri:
        mben = sorted([r for r in mon[v] if not r.get('_is_attack')],
                      key=lambda r: r.get('_id_time', r.get('_dt', 0)))
        cut = int(len(mben) * 0.8)
        ftest = sorted(fri[v], key=lambda r: r.get('_id_time', r.get('_dt', 0)))
        tben = [r for r in ftest if not r.get('_is_attack')]
        tatk = [r for r in ftest if r.get('_is_attack')]
        add('CIC-IDS-2017 Friday (cross-day)', mben[:cut], mben[cut:], tben, tatk)
    del mon, fri

    for cache, v, tag in [('cicids2018_pcap_wed.json', '172.31.69.28', 'Wed (LOIC-UDP+HOIC)'),
                          ('cicids2018_pcap_thu.json', '172.31.69.25', 'Thu (GoldenEye+Slowloris)'),
                          ('cicids2018_pcap_fri.json', '172.31.69.25', 'Fri (Hulk+SlowHTTPTest)')]:
        try:
            d = R.load_perip(cache)
            if v in d:
                f_, c_, tb, ta = within_split(d[v]); add(f'CIC-IDS-2018 {tag}', f_, c_, tb, ta)
        except Exception as ex:
            print(f"  CIC-2018 {tag} skipped: {ex}")

    try:
        d = R.load_perip('cicddos_pcap_features.json'); v = '192.168.50.4'
        if v in d:
            f_, c_, tb, ta = within_split(d[v]); add('CIC-DDoS2019 (victim flood)', f_, c_, tb, ta)
    except Exception as ex:
        print("  CIC-DDoS2019 skipped:", ex)

    try:
        lit = json.load(open(os.path.join(CACHE_DIR, 'litnet_per_ip_cache.json')))
        for v, tag in [('193.219.81.138', 'Code Red'), ('193.219.88.36', 'Smurf'),
                       ('23.32.104.60', 'HTTP flood')]:
            if v in lit:
                f_, c_, tb, ta = within_split(lit[v]); add(f'LITNET {tag}', f_, c_, tb, ta)
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
            n = len(brows); a = int(n * 0.6); b = int(n * 0.8)
            add(f'CIC-IoT {fam}', brows[:a], brows[a:b], brows[b:], arows)
            del fam_d
        del ben
    except Exception as ex:
        print("  CIC-IoT skipped:", ex)

    # build DR and FPR markdown tables at headline alpha
    def tbl(metric_idx, title):
        hdr = "| Corpus (victim) | " + " | ".join(LABELS[k] for k in COLS) + " |"
        sep = "|" + "---|" * (len(COLS) + 1)
        lines = [f"**{title} (conformal α={ALPHA})**", "", hdr, sep]
        for c in cases:
            cells = []
            for k in COLS:
                val = c['drfpr'][k][str(ALPHA)][metric_idx]
                cells.append("n/a" if val is None else f"{val:.1f}")
            lines.append(f"| {c['label']} | " + " | ".join(cells) + " |")
        # mean row
        means = []
        for k in COLS:
            vals = [c['drfpr'][k][str(ALPHA)][metric_idx] for c in cases
                    if c['drfpr'][k][str(ALPHA)][metric_idx] is not None]
            means.append("n/a" if not vals else f"{np.mean(vals):.1f}" +
                         ("" if len(vals) == len(cases) else f" ({len(vals)})"))
        lines.append(f"| **Mean** | " + " | ".join(means) + " |")
        return "\n".join(lines)

    dr_md = tbl(0, "Detection Rate (DR %)")
    fpr_md = tbl(1, "False-Positive Rate (FPR %)")
    print("\n" + dr_md + "\n\n" + fpr_md)
    json.dump({'metadata': {'alpha': ALPHA, 'alpha_grid': ALPHA_GRID, 'n_cases': len(cases),
                            'columns': LABELS, 'note': 'single conformal paths; DR/FPR at matched alpha; '
                            'CIC-2017 cross-day, others within-cache 60/20/20; benign-before-attack',
                            'runtime_s': round(time.time()-t0, 1)},
               'cases': cases, 'dr_table_markdown': dr_md, 'fpr_table_markdown': fpr_md},
              open(OUT, 'w'), indent=2)
    print("\nSaved:", OUT)


if __name__ == '__main__':
    main()
