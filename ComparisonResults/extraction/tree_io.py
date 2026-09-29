"""Two helpers the extraction scripts import, carried here so the deposit is self-contained.

within_split: the causal split used at extraction time to decide whether a scenario has enough
pre-attack benign windows (fit = first 60% of pre-attack benign, calibration = the rest, test =
everything from the first attack window on). It is the rule Section 3.5 of the article describes.
load_perip: reads a per-IP window cache from ComparisonResults/cache/.
Both were taken verbatim from the authors' development tree (run_demo_multicorpus_benchmark.py and
run_crosscorpus_auc.py at commit c8cc797), which the deposit does not carry in full.
"""
import json, os
from config import CACHE_DIR


def within_split(rows, min_pre=30):
    rows = sorted(rows, key=lambda r: r.get('_id_time', r.get('_dt', 0)))
    atk_indices = [i for i, r in enumerate(rows) if r.get('_is_attack')]
    if not atk_indices:
        return None, None, None, None
    first_atk_idx = atk_indices[0]
    pre_benign = [r for r in rows[:first_atk_idx] if not r.get('_is_attack')]
    if len(pre_benign) < min_pre:
        return None, None, None, None
    n_pre = len(pre_benign)
    n_fit = int(n_pre * 0.6)
    fit_rows = pre_benign[:n_fit]
    calib_rows = pre_benign[n_fit:]
    test_rows = rows[first_atk_idx:]
    test_benign = [r for r in test_rows if not r.get('_is_attack')]
    test_attack = [r for r in test_rows if r.get('_is_attack')]
    return fit_rows, calib_rows, test_benign, test_attack


def load_perip(path):
    d = json.load(open(os.path.join(CACHE_DIR, path)))
    return d['per_ip_windows'] if 'per_ip_windows' in d else d
