"""Classify every extracted scenario on four independent grounds.

Replaces check_scenario_intensity.py, whose verdicts an adversarial audit
showed to be wrong in both directions. Two defects in that gate:

  it read packets_per_sec ONLY. CIC-IDS-2017 Slowloris was condemned at a
  0.83x p95 ratio; src_port_entropy separates it with rank-AUC 0.9998 and
  99.9% DR at a 5%-FPR threshold. Slow-HTTP attacks are invisible in packet
  rate by design.

  it used a RATIO OF PERCENTILES, which is a poor separability statistic even
  on the feature it read. CIC-IDS-2018 Slowloris scored 1.5x and was
  condemned; rank-AUC on that same packets_per_sec is 0.963 with 67.5% DR,
  because the distributions barely overlap even though the percentiles are
  close.

Four checks, each able to disqualify on its own:

DIRECTION   Is the host a target or the attack source? Windows are keyed by
            destination, so the flag mix is what ARRIVES. Calibrated on the two
            CIC-DDoS2019 hosts whose roles the corpus CSVs establish:
                victim   192.168.50.4  syn 0.9945  ack 0.0020  rst 0.0002
                attacker 172.16.0.5    syn 0.0000  ack 0.9981  rst 0.9773
            A host receiving almost no SYNs while receiving ACKs, SYN-ACKs or
            RSTs did not receive the flood -- it sent it. Only applied where
            TCP flags are present: a UDP flood legitimately shows no flags.

SEPARABLE   Does ANY feature distinguish attack from benign? Rank-AUC over
            every numeric feature, plus detection rate at the benign-p95
            threshold (a 5%-FPR operating point). Rank-AUC is invariant to
            scale and shape and does not assume the separating feature is
            volume.

FLOOR       1/(n_calib+1) <= alpha, or no detector can fire and every method
            reads 0.0% by arithmetic.

FPR         n_test_benign >= 5, or the false-positive rate is undefined rather
            than zero.

Usage: python3 classify_scenarios.py [tree] [--alpha 0.01] [--write]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, hashlib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'negatives'))
from tree_io import within_split
from corpus_names import in_scope

TREE = _os.path.join(_BASE, 'datasets', 'extracted')
# Roles that are DOCUMENTED, not inferred. CIC-IDS-2017/2018 publish an
# attacker/victim table; CIC-DDoS2019's per-attack CSVs carry Source IP and
# Destination IP. Where a role is documented it overrides the flag heuristic,
# which assumes flood semantics and cannot tell a single-connection exploit's
# victim from an attacker: CIC-IDS-2017 Heartbleed's documented victim
# 192.168.10.51 shows syn=0.0000, ack=0.9951, 1 flow/s, 1 source -- the same
# profile as CIC-DDoS2019's confirmed attacker.
# Hosts whose ATTACKER role is established from corpus ground truth rather than
# inferred. 172.16.0.5 was measured over all seven CIC-DDoS2019 03-11 CSVs
# (20,364,525 rows): 20,299,481 flows out to 192.168.50.4 against 8,079 back --
# 2,513:1, see stamp_cicddos_roles.py. Recording it here means those six
# verdicts no longer rest on the flag heuristic, which is nominally what they
# rested on even though the quarantine itself was argued from the CSVs.
DOCUMENTED_ATTACKERS = {'172.16.0.5'}

DOCUMENTED_VICTIMS = {
    '192.168.10.50', '192.168.10.51',            # CIC-IDS-2017 schedule
    '172.31.69.25', '172.31.69.28',              # CIC-IDS-2018 schedule
    '192.168.50.4',                              # CIC-DDoS2019 CSV Destination IP
}
# Corpora on which the inbound-flag heuristic below was checked against ground
# truth and found NOT to hold. The rule works where a flood provokes a reply the
# victim sends back -- the SYN-flood case it was built on. It cannot work where
# the flood provokes nothing (RST+FIN, PSH+ACK, fragmented-ACK floods): on such a
# corpus the authors measured it inverted, flagging confirmed flood targets as
# sources. That corpus is outside the four this deposit covers, so the set is
# empty and role_unverified is False on every scenario classified here. On a
# corpus listed here an inferred attacker is ROLE-UNVERIFIED instead of
# ATTACKER-SIDE: still excluded, because an unknown role cannot anchor a
# detection claim, but excluded for a reason that is true.
FLAG_HEURISTIC_INVALID = frozenset()

# Attacks that are not denial-of-service. Kept as data, excluded from a DDoS
# panel regardless of how well they separate.
NOT_DDOS = {'Heartbleed', 'PortScan'}

AUC_BAR = 0.75          # below this nothing usefully separates
DR_BAR = 20.0           # detection at a 5%-FPR threshold, percent
SYN_FLOOR = 0.05        # a TCP victim receives at least this share as bare SYN
RESP_BAR = 0.50         # ACK/SYN-ACK/RST share indicating replies to own sends


def rank_auc(a, b):
    """Mann-Whitney AUC with TIES AVERAGED.

    Without tie correction a feature that is constant in the attack rows and
    mostly-constant in the benign rows scores a spurious AUC of 1.0 purely from
    the sort order of equal values. That defect made icmp_ratio and
    topk_flow_share the "most discriminative feature" on almost every scenario
    while their detection rate was 0.0% -- an AUC of 1.000 beside a DR of 0.0%
    is the signature of it.
    """
    from scipy.stats import rankdata
    n1, n0 = len(a), len(b)
    if not n1 or not n0:
        return 0.5
    r = rankdata(np.r_[a, b])          # average ranks for ties
    auc = (r[:n1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)
    return max(auc, 1 - auc)


def split_for(rows, mode):
    """The split the producing script actually used.

    within / crossday : causal -- calibrate only on benign preceding the first
                        attack window.
    """
    if mode not in ('within', 'crossday'):
        raise ValueError(f'unknown split mode {mode!r}; expected within or crossday')
    return within_split(rows)


def analyse(rows, alpha, mode='within', victim=None, scenario='', corpus=None):
    a = [r for r in rows if r.get('_is_attack')]
    b = [r for r in rows if not r.get('_is_attack')]
    out = {'n_attack': len(a), 'n_benign': len(b)}
    if not a or not b:
        out['verdict'] = 'DEGENERATE'; return out

    feats = [k for k in a[0] if not k.startswith('_')]
    best = (0.5, 0.0, None)
    for f in feats:
        av = np.array([float(r.get(f, 0) or 0) for r in a], dtype=float)
        bv = np.array([float(r.get(f, 0) or 0) for r in b], dtype=float)
        if av.std() == 0 and bv.std() == 0:
            continue
        auc = rank_auc(av, bv)
        # two-sided: separation can be in either direction. A TCP flood drives
        # icmp_ratio DOWN, which is just as detectable as driving it up, and a
        # one-sided test scored those at DR 0.0% while AUC read 1.000.
        dr = max(100.0 * float((av > np.percentile(bv, 95)).mean()),
                 100.0 * float((av < np.percentile(bv, 5)).mean()))
        if (dr, auc) > (best[1], best[0]):
            best = (auc, dr, f)
    out.update(best_auc=round(best[0], 4), best_dr_at_5pct_fpr=round(best[1], 1),
               best_feature=best[2])

    tot = sum(float(r.get('packets_per_sec', 0) or 0) for r in a) or 1.0
    g = lambda k: sum(float(r.get(k, 0) or 0) for r in a) / tot
    syn, sa, ack, rst = g('syn_per_sec'), g('syn_ack_per_sec'), g('ack_per_sec'), g('rst_per_sec')
    # Require the flags to describe a meaningful share of the inbound stream.
    # At 0.05 the test fired on UDP-flood victims whose few TCP packets happened
    # to be ACKs, and on CIC-IDS-2017 Heartbleed, which is not a flood at all.
    tcp_present = (syn + sa + ack + rst) > 0.30
    out.update(inbound_syn_share=round(syn, 4), inbound_ack_share=round(ack, 4),
               inbound_rst_share=round(rst, 4), inbound_syn_ack_share=round(sa, 4))
    inferred_attacker = bool(tcp_present and syn < SYN_FLOOR and max(ack, sa, rst) > RESP_BAR)
    # Two different kinds of "documented", and they point opposite ways: a
    # documented VICTIM overrides the heuristic to KEEP the scenario, while a
    # documented ATTACKER overrides it to EXCLUDE. Folding both into one flag
    # inverts the second -- it made all six CIC-DDoS2019 attacker slices USABLE.
    documented = victim in DOCUMENTED_VICTIMS
    documented_attacker = victim in DOCUMENTED_ATTACKERS
    heuristic_valid = corpus not in FLAG_HEURISTIC_INVALID
    attacker_side = bool(documented_attacker or
                         (inferred_attacker and not documented and heuristic_valid))
    role_unverified = bool(not documented_attacker and inferred_attacker
                           and not documented and not heuristic_valid)
    out['role_unverified'] = role_unverified
    out['role_documented_attacker'] = documented_attacker
    out.update(attacker_side=attacker_side,
               role_documented=bool(documented or documented_attacker),
               flag_profile_suggests_source=inferred_attacker)
    if documented and inferred_attacker:
        out['role_note'] = ('documented victim whose inbound flag profile '
                            'resembles a source: single-connection or '
                            'reflected attack, not a flood')

    fit, cal, tb, ta = split_for(rows, mode)
    n_cal = len(cal) if cal else 0
    n_tb = len(tb) if tb else 0
    floor = 1.0 / (n_cal + 1) if n_cal else 1.0
    out.update(n_calib=n_cal, n_test_benign=n_tb, p_floor=round(floor, 6),
               floor_limited=bool(floor > alpha), fpr_measurable=bool(n_tb >= 5))

    if any(k in scenario for k in NOT_DDOS):
        out['verdict'] = 'NOT-DDOS'
    elif attacker_side:
        out['verdict'] = 'ATTACKER-SIDE'
    elif role_unverified:
        out['verdict'] = 'ROLE-UNVERIFIED'
    elif floor > alpha:
        out['verdict'] = 'FLOOR-LIMITED'
    elif n_tb < 5:
        out['verdict'] = 'NO-FPR'
    elif best[0] < AUC_BAR or best[1] < DR_BAR:
        out['verdict'] = 'INSEPARABLE'
    else:
        out['verdict'] = 'USABLE'
    return out


def main():
    args = sys.argv[1:]
    skip = {i + 1 for i, a in enumerate(args) if a == '--alpha'}   # the value after --alpha is not a tree
    tree = next((a for i, a in enumerate(args) if not a.startswith('--') and i not in skip), TREE)
    alpha = float(sys.argv[sys.argv.index('--alpha') + 1]) if '--alpha' in sys.argv else 0.01
    write = '--write' in sys.argv
    rows_out, skipped = [], []
    for corpus in sorted(os.listdir(tree)):
        d = os.path.join(tree, corpus)
        ip = os.path.join(d, 'index.json')
        if not os.path.isdir(d) or not os.path.exists(ip):
            continue
        if not in_scope(corpus):
            skipped.append(corpus)
            continue
        idx = json.load(open(ip))
        for k, m in sorted(idx.items()):
            if m.get('kind', '').startswith('benign reference'):
                continue
            p = os.path.join(d, m['file'])
            if not os.path.exists(p):
                continue
            js = json.load(open(p))
            v = m['victim']
            mode = m.get('mode') or 'within'
            r = analyse(sorted(js['per_ip_windows'][v], key=lambda x: x.get('_dt', 0)),
                        alpha, mode, victim=v,
                        scenario=os.path.basename(m['file']).replace('.json', ''),
                        corpus=corpus)
            r['split_mode'] = mode
            r.update(corpus=corpus, scenario=os.path.basename(m['file']).replace('.json', ''),
                     victim=v)
            rows_out.append(r)
            if write:
                js['metadata'].update({kk: vv for kk, vv in r.items()
                                       if kk not in ('corpus', 'scenario', 'victim')})
                js['metadata']['usable_as_ddos_scenario'] = (r['verdict'] == 'USABLE')
                # The payload carries a `bytes`/`sha256` pair describing the
                # file as it was BEFORE this rewrite. Folding the embedded
                # metadata straight into the index published those stale values
                # over the correct ones -- 8 of 8 entries corrupted on a
                # re-run, e.g. 2517310 recorded for a 2516494-byte file, so
                # every hash in SHA256SUMS then failed. Re-measure from disk
                # after the write instead, and never let the payload speak for
                # the file.
                js['metadata'].pop('bytes', None)
                js['metadata'].pop('sha256', None)
                json.dump(js, open(p, 'w'))
                m.update(js['metadata'])
                m['bytes'] = os.path.getsize(p)
                h = hashlib.sha256()
                with open(p, 'rb') as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b''):
                        h.update(chunk)
                m['sha256'] = h.hexdigest()
            del js
        if write:
            json.dump(idx, open(ip, 'w'), indent=2)
    if skipped:
        print(f"  skipped out-of-scope corpus directories: {', '.join(skipped)}")

    print(f"  {'corpus':21s} {'scenario':34s} {'AUC':>6s} {'DR@5%':>6s} {'feature':18s} "
          f"{'n_cal':>6s}  verdict")
    print("  " + "-" * 118)
    for r in rows_out:
        print(f"  {r['corpus']:21s} {r['scenario']:34s} {r.get('best_auc',0):6.3f} "
              f"{r.get('best_dr_at_5pct_fpr',0):5.1f}% {str(r.get('best_feature'))[:18]:18s} "
              f"{r.get('n_calib',0):6d}  {r['verdict']}")
    print("  " + "-" * 118)
    from collections import Counter
    c = Counter(r['verdict'] for r in rows_out)
    print(f"  {dict(c)}")
    print(f"  USABLE: {c['USABLE']} of {len(rows_out)}")
    # Write beside the tree that was actually read. The output path used to be
    # hardcoded to results/scenario_classification.json regardless of --tree, so
    # running this against a scratch tree -- which is exactly what you do to test
    # the "skips corpora lacking index.json" behaviour -- silently overwrote the
    # canonical results with whatever that tree produced. It overwrote them with
    # `[]`, and nothing complained, because writing an empty list is what the
    # skip behaviour correctly produces.
    if os.path.abspath(tree) == os.path.abspath(TREE):
        from config import RESULTS_DIR
        out = os.path.join(RESULTS_DIR, 'scenario_classification.json')
    else:
        out = os.path.join(tree, 'scenario_classification.json')
        print(f"  [non-default --tree: writing to {out}, NOT the canonical results]")
    json.dump(rows_out, open(out, 'w'), indent=2)


if __name__ == '__main__':
    main()
