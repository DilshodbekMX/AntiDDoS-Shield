"""Admissibility ledger: one verdict per extracted candidate scenario, from stored statistics.

Applies the scope filter and the four admissibility checks to the per-candidate statistics in
admissibility_inputs.json, assigns each candidate exactly one verdict by a fixed precedence, joins
the clock-only null from clock_null.json, and writes admissibility_ledger.json: the per-candidate
ledger, the census by verdict and corpus, the usable fraction per corpus, every check each
candidate fails (not only the one that set its verdict), and the census at three values of the
conformal-floor bar. Cross-checks the verdicts against the two deposited records that store one
(clock_null.json for all 44 candidates, scenarios29_corrected_results.json for 29).

Reads three deposited records; scores no detector and reads no traffic. The feature statistics
themselves (rank-AUC, detection rate, inbound flag shares, split sizes) were measured on the
derived feature tree and are read here, not recomputed.

Verdict precedence (first match wins):
  NOT-DDOS         scope filter: the attack is a declared non-denial-of-service name
  ATTACKER-SIDE    direction: documented attack source, or inbound flag profile of a source
                   on a corpus where that heuristic is valid and the host is not a documented victim
  ROLE-UNVERIFIED  direction: the flag profile of a source on a corpus where the heuristic is
                   declared invalid, host role undocumented
  FLOOR-LIMITED    conformal floor 1/(n_calib+1) above alpha_conf (1.0 when n_calib = 0)
  NO-FPR           fewer than 5 benign test windows
  INSEPARABLE      best feature's two-sided rank-AUC below 0.75 or its detection rate at the
                   5%-FPR benign thresholds below 20%
  USABLE           none of the above
"""
import os, sys, json
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    sys.path.insert(0, p)

from config import RESULTS_DIR
from corpus_names import canon, CANONICAL, spelling_census
import safe_out

# ---- thresholds -------------------------------------------------------------------------------
ALPHA_CONF = 0.01           # conformal-floor bar
ALPHA_SWEEP = (0.0075, 0.01, 0.0125)
AUC_BAR = 0.75              # separability: two-sided rank-AUC of the best feature
DR_BAR = 20.0               # separability: detection (%) at the 5%-FPR benign thresholds
MIN_TEST_BENIGN = 5         # FPR measurability
TCP_PRESENT_BAR = 0.30      # direction: flags describe a meaningful share of inbound packets
SYN_FLOOR = 0.05            # direction: a TCP flood target receives at least this bare-SYN share
RESP_BAR = 0.50             # direction: ACK / SYN-ACK / RST share indicating replies to own sends
SHARE_DECIMALS = 4          # the stored flag shares are rounded to this many decimals

# ---- declared manual inputs: adjudicated from documentation, not computed here ----------------
# Scope filter. A name match, applied to the scenario name; the adjudication that these two
# are not denial-of-service loads was made from the corpus flow records.
NOT_DDOS_NAMES = ('Heartbleed', 'PortScan')
# Documented victims (corpus schedule or CSV destination) override the flag heuristic to keep.
DOCUMENTED_VICTIMS = {
    'CIC-IDS-2017': {'192.168.10.50', '192.168.10.51'},
    'CIC-IDS2018': {'172.31.69.25', '172.31.69.28'},
    'CICDDoS2019': {'192.168.50.4'},
}
# Documented attack sources override it to exclude. 172.16.0.5: over the seven 03-11 CSVs,
# 20,299,481 flows to 192.168.50.4 against 8,079 in reverse.
DOCUMENTED_ATTACKERS = {'CICDDoS2019': {'172.16.0.5'}}
# Corpora on which the flag heuristic is declared invalid: on CIC-IoT-2023, pcap-derived roles
# show it flagging 15 of 16 confirmed RSTFINFlood targets and 0 of 10 confirmed sources.
HEURISTIC_INVALID_CORPORA = {'CIC-IoT-2023'}   # canonical names; compare with canon()

# ---- labels -----------------------------------------------------------------------------------
# One mapping for the whole harness: corpus_names.canon. This file used to carry two of its
# own, LEDGER_LABEL and CENSUS_LABEL, which disagreed on the 2018 corpus and put both
# spellings into one record. Both now resolve through canon, so the ledger and the census
# cannot drift apart again.
CORPUS_ORDER = ['CIC-IDS-2017', 'CIC-IDS2018', 'CICDDoS2019', 'CIC_IOT_Dataset2023', 'LITNET-2020']
LEDGER_LABEL = {c: canon(c) for c in CORPUS_ORDER}
CENSUS_LABEL = LEDGER_LABEL
VERDICT_ORDER = ['USABLE', 'ROLE-UNVERIFIED', 'ATTACKER-SIDE', 'FLOOR-LIMITED', 'NOT-DDOS',
                 'NO-FPR', 'INSEPARABLE']
CHECK_LABEL = {'USABLE': 'all four pass', 'NOT-DDOS': 'scope filter',
               'ATTACKER-SIDE': 'direction (source host)',
               'ROLE-UNVERIFIED': 'direction (role unproven)',
               'FLOOR-LIMITED': 'conformal floor', 'NO-FPR': 'FPR undefined',
               'INSEPARABLE': 'separability screen'}


def p_floor(n_calib):
    return 1.0 / (n_calib + 1) if n_calib else 1.0


def assess(c, alpha):
    corpus, victim = c['corpus_dir'], c['victim']
    syn, ack = c['inbound_syn_share'], c['inbound_ack_share']
    rst, sa = c['inbound_rst_share'], c['inbound_syn_ack_share']
    in_scope = not any(t in c['scenario'] for t in NOT_DDOS_NAMES)
    tcp_present = (syn + sa + ack + rst) > TCP_PRESENT_BAR
    flag_source = bool(tcp_present and syn < SYN_FLOOR and max(ack, sa, rst) > RESP_BAR)
    doc_victim = victim in DOCUMENTED_VICTIMS.get(corpus, set())
    doc_attacker = victim in DOCUMENTED_ATTACKERS.get(corpus, set())
    heuristic_valid = canon(corpus) not in HEURISTIC_INVALID_CORPORA
    attacker_side = doc_attacker or (flag_source and not doc_victim and heuristic_valid)
    role_unverified = (not doc_attacker) and flag_source and not doc_victim and not heuristic_valid
    floor = p_floor(c['n_calib'])
    floor_ok = floor <= alpha
    fpr_ok = c['n_test_benign'] >= MIN_TEST_BENIGN
    separable = c['best_auc'] >= AUC_BAR and c['best_dr_at_5pct_fpr'] >= DR_BAR

    failed = [name for name, bad in (('scope', not in_scope),
                                     ('direction', attacker_side or role_unverified),
                                     ('conformal floor', not floor_ok),
                                     ('FPR measurability', not fpr_ok),
                                     ('separability', not separable)) if bad]
    if not in_scope:
        verdict = 'NOT-DDOS'
    elif attacker_side:
        verdict = 'ATTACKER-SIDE'
    elif role_unverified:
        verdict = 'ROLE-UNVERIFIED'
    elif not floor_ok:
        verdict = 'FLOOR-LIMITED'
    elif not fpr_ok:
        verdict = 'NO-FPR'
    elif not separable:
        verdict = 'INSEPARABLE'
    else:
        verdict = 'USABLE'

    # distance of the stored (rounded) shares from each direction threshold they are compared with
    half_unit = 0.5 * 10 ** -SHARE_DECIMALS
    margins = [abs((syn + sa + ack + rst) - TCP_PRESENT_BAR) - 4 * half_unit,
               abs(syn - SYN_FLOOR) - half_unit, abs(max(ack, sa, rst) - RESP_BAR) - half_unit]
    if doc_attacker:
        direction = 'documented source'
    elif attacker_side:
        direction = 'flag profile of a source'
    elif role_unverified:
        direction = 'flag profile of a source; heuristic declared invalid on this corpus'
    elif doc_victim:
        direction = 'documented victim' + (' (flag profile of a source overridden)' if flag_source else '')
    else:
        direction = 'flag heuristic silent' if tcp_present else 'flag heuristic silent (TCP flags under 30% of inbound packets)'
    return {'verdict': verdict, 'check': CHECK_LABEL[verdict], 'checks_failed': failed,
            'in_scope': in_scope, 'direction': direction, 'flag_profile_suggests_source': flag_source,
            'direction_rounding_sensitive': bool(min(margins) <= 0),
            'p_floor': round(floor, 6), 'floor_ok': floor_ok, 'fpr_measurable': fpr_ok,
            'separable': separable}


def main():
    inputs = json.load(open(os.path.join(RESULTS_DIR, 'admissibility_inputs.json')))['candidates']
    clock = json.load(open(os.path.join(RESULTS_DIR, 'clock_null.json')))['candidates']
    s29 = json.load(open(os.path.join(RESULTS_DIR, 'scenarios29_corrected_results.json')))['per_scenario']

    ledger = []
    for c in sorted(inputs, key=lambda c: (CORPUS_ORDER.index(c['corpus_dir']), c['scenario'])):
        a = assess(c, ALPHA_CONF)
        cl = [r for r in clock if r['corpus'] == c['corpus_dir'] and r['file'] == c['file']
              and r['victim'] == c['victim']]
        if len(cl) != 1:
            raise SystemExit(f"clock join failed for {c['corpus_dir']} {c['file']}: {len(cl)} rows")
        cl = cl[0]
        ledger.append({'corpus': LEDGER_LABEL[c['corpus_dir']], 'corpus_dir': c['corpus_dir'],
                       'scenario': c['scenario'], 'victim': c['victim'],
                       'clock_separability': cl.get('clock_separability'),
                       'clock_label_runs': cl.get('label_runs'),
                       **a,
                       'best_feature': c['best_feature'], 'best_auc': c['best_auc'],
                       'best_dr_at_5pct_fpr': c['best_dr_at_5pct_fpr'],
                       'n_calib': c['n_calib'], 'n_test_benign': c['n_test_benign'],
                       '_clock_stored_verdict': cl.get('verdict')})
    if len(ledger) != 44:
        print(f"  WARNING: {len(ledger)} candidates, the census names 44")

    # cross-checks against the deposited records that store a verdict
    agree_clock = sum(r['verdict'] == r['_clock_stored_verdict'] for r in ledger)
    dis_clock = [(r['corpus'], r['scenario'], r['verdict'], r['_clock_stored_verdict'])
                 for r in ledger if r['verdict'] != r['_clock_stored_verdict']]
    # Join on the CANONICAL corpus, the file stem and the address. Both sides used to be
    # keyed on whatever spelling their own producer happened to write, so a normalised
    # record would have missed every row of the three two-spelling corpora -- and a miss
    # here does not raise, it is counted as a verdict disagreement. Canonicalise both
    # sides and fail loudly if any row fails to join.
    by_key = {(canon(r['corpus_dir']), r['scenario'], r['victim']): r for r in ledger}
    dis_29, n29, unmatched = [], 0, []
    for s in s29:
        k = (canon(s['corpus']), s['file'].replace('.json', ''), s['victim'].split('/', 1)[-1])
        n29 += 1
        r = by_key.get(k)
        if r is None:
            unmatched.append(k)
            continue
        if r['verdict'] != s['verdict']:
            dis_29.append((k, s['verdict'], r['verdict']))
    if unmatched:
        raise SystemExit(f"scenarios29 join failed for {len(unmatched)} of {n29} rows: "
                         f"{unmatched[:3]}")

    census = {v: {'n': 0, 'corpora': {}} for v in VERDICT_ORDER}
    for r in ledger:
        e = census[r['verdict']]
        e['n'] += 1
        lab = CENSUS_LABEL[r['corpus_dir']]
        e['corpora'][lab] = e['corpora'].get(lab, 0) + 1
    usable_fraction = {}
    for cd in CORPUS_ORDER:
        rows = [r for r in ledger if r['corpus_dir'] == cd]
        usable_fraction[CENSUS_LABEL[cd]] = f"{sum(r['verdict'] == 'USABLE' for r in rows)}/{len(rows)}"
    usable = [r for r in ledger if r['verdict'] == 'USABLE']

    sweep = {}
    for alpha in ALPHA_SWEEP:
        vs = {(r['corpus_dir'], r['scenario']): assess(c, alpha)['verdict']
              for r, c in zip(ledger, sorted(inputs, key=lambda c: (CORPUS_ORDER.index(c['corpus_dir']),
                                                                    c['scenario'])))}
        cnt = Counter(vs.values())
        sweep[f'{alpha}'] = {'USABLE': cnt['USABLE'], 'FLOOR-LIMITED': cnt['FLOOR-LIMITED'],
                             'verdicts': {f'{k[0]}/{k[1]}': v for k, v in vs.items()}}
    changed = sorted({k for a in sweep.values() for k, v in a['verdicts'].items()
                      if len({sweep[b]['verdicts'][k] for b in sweep}) > 1})
    for a in sweep.values():
        a['verdicts'] = {k: a['verdicts'][k] for k in changed}
    floors = {f"{r['corpus_dir']}/{r['scenario']}": r['p_floor'] for r in ledger
              if f"{r['corpus_dir']}/{r['scenario']}" in changed}

    sep_fail = [{k: r[k] for k in ('corpus', 'scenario', 'verdict', 'best_auc', 'best_dr_at_5pct_fpr')}
                for r in ledger if 'separability' in r['checks_failed']]
    multi_fail = [{k: r[k] for k in ('corpus', 'scenario', 'verdict', 'checks_failed')}
                  for r in ledger if len(r['checks_failed']) > 1]
    surviving = [r for r in ledger if r['floor_ok']]
    top_surv = max(surviving, key=lambda r: r['p_floor'])

    print(f"  {len(ledger)} candidates; census " +
          ', '.join(f"{v} {census[v]['n']}" for v in VERDICT_ORDER))
    for v in VERDICT_ORDER:
        print(f"    {v:16s} {census[v]['n']:2d}  {census[v]['corpora']}")
    print(f"  usable fraction {usable_fraction}; {len(usable)} usable on "
          f"{len({(r['corpus_dir'], r['victim']) for r in usable})} victims")
    print(f"  verdict agreement: clock_null.json {agree_clock}/{len(ledger)}, "
          f"scenarios29_corrected_results.json {n29 - len(dis_29)}/{n29}")
    for d in dis_clock + dis_29:
        print(f"    DISAGREES {d}")
    print(f"  alpha_conf sweep: " + ', '.join(f"{a}: USABLE {s['USABLE']} FLOOR-LIMITED {s['FLOOR-LIMITED']}"
                                             for a, s in sweep.items()))
    print(f"  separability failures (any precedence): {[(r['scenario'], r['best_auc'], r['best_dr_at_5pct_fpr']) for r in sep_fail]}")
    print(f"  candidates failing more than one check: {[(r['scenario'], r['checks_failed']) for r in multi_fail]}")
    print(f"  rounding-sensitive direction calls: {[r['scenario'] for r in ledger if r['direction_rounding_sensitive']]}")

    dst = safe_out.resolve(RESULTS_DIR, 'admissibility_ledger.json', 'AL')
    json.dump({'note': ('Admissibility ledger over the extracted candidate scenarios: one verdict each, by the '
                        'precedence NOT-DDOS > ATTACKER-SIDE > ROLE-UNVERIFIED > FLOOR-LIMITED > NO-FPR > '
                        'INSEPARABLE > USABLE, applied to the statistics of admissibility_inputs.json; '
                        'checks_failed lists every check a candidate fails, of which the verdict records the '
                        'first. clock_separability = max(AUC, 1-AUC) of the clock-only null, joined from '
                        'clock_null.json (reported, not used to exclude). Reads no traffic and scores no '
                        'detector; the scope filter, the documented roles and the corpus on which the direction '
                        'heuristic is declared invalid are declared inputs, not measurements.'),
               'inputs': ['admissibility_inputs.json', 'clock_null.json', 'scenarios29_corrected_results.json'],
               'thresholds': {'alpha_conf': ALPHA_CONF, 'auc_bar': AUC_BAR, 'dr_bar_pct': DR_BAR,
                              'min_test_benign': MIN_TEST_BENIGN, 'tcp_present_bar': TCP_PRESENT_BAR,
                              'syn_floor': SYN_FLOOR, 'resp_bar': RESP_BAR},
               'declared_inputs': {'not_ddos_names': list(NOT_DDOS_NAMES),
                                   'documented_victims': {k: sorted(v) for k, v in DOCUMENTED_VICTIMS.items()},
                                   'documented_attackers': {k: sorted(v) for k, v in DOCUMENTED_ATTACKERS.items()},
                                   'heuristic_invalid_corpora': sorted(HEURISTIC_INVALID_CORPORA)},
               'census': census,
               'usable_fraction': usable_fraction,
               'n_usable_victims': len({(r['corpus_dir'], r['victim']) for r in usable}),
               'verdict_agreement': {'clock_null.json': f'{agree_clock}/{len(ledger)}',
                                     'scenarios29_corrected_results.json': f'{n29 - len(dis_29)}/{n29}'},
               'separability_failures': sep_fail,
               'multiple_check_failures': multi_fail,
               'highest_surviving_floor': {'scenario': f"{top_surv['corpus']} {top_surv['scenario']}",
                                           'p_floor': top_surv['p_floor'], 'n_calib': top_surv['n_calib']},
               'alpha_conf_sensitivity': {'counts': {a: {'USABLE': s['USABLE'], 'FLOOR-LIMITED': s['FLOOR-LIMITED']}
                                                     for a, s in sweep.items()},
                                          'changed': {k: {'p_floor': floors[k],
                                                          **{a: s['verdicts'][k] for a, s in sweep.items()}}
                                                      for k in changed}},
               'ledger': [{k: v for k, v in r.items() if not k.startswith('_')} for r in ledger]},
              open(dst, 'w'), indent=1)
    print(f"  wrote {dst}")


if __name__ == '__main__':
    main()
