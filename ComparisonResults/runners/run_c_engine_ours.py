"""Score OUR arm with the SHIPPED C Layer 2 engine, directly.

No detection logic lives in Python here: project/layer2/{detection,baselines,
advanced_detection}.c are compiled into a shared library and driven through ctypes.
Every score is the engine's own struct detection_result.

Scope: this runner produces OUR arm only. The nine competitor baselines (POT, DSPOT,
ECOD, COPOD, HBOS, LODA, INNE, IForest, DIF) are PyOD and hand-written Python with no C
implementation, and are produced by run_corrected_benchmark.py as before.

Two protocols are reported because they answer different questions:
  frozen  -- baseline fitted on the benign train split then held fixed; the inductive
             protocol every competitor arm uses, so its AUC is comparable to that table.
  closed  -- baseline tracks while normal, frozen while alarming, with the 30 s
             cool-down and K=3 persistence gate; mirrors layer2.c. NOT comparable to
             the competitor table: on short-warmup corpora it is dominated by the
             attack duty cycle rather than by detector quality.

Writes results/c_engine_ours.json.
"""
import ctypes, datetime as _dt, gc, json, os, subprocess, sys, time
import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, HERE); sys.path.insert(0, ROOT)
from config import RESULTS_DIR, BASE
from run_post2023_benchmark import load_case, tkey

EXTRACTED = os.path.join(BASE, 'datasets', 'extracted')
PROJECT = os.path.abspath(os.path.join(ROOT, '..', 'project'))
SHIM = os.path.join(ROOT, 'c_engine_shim.c')
OUT = os.path.join(RESULTS_DIR, 'c_engine_ours.json')
# Build artifact: kept out of results/ so it never lands in the deposit or the manifest.
SO = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'antiddos_libl2engine.so')
ALPHA, MINSAMP, THETA, AGREE, JSD_T, COOL, K = (0.15, 0.05, 0.01), (10, 20, 40), 4.0, 2, 0.15, 30.0, 3


def build():
    srcs = [SHIM] + [os.path.join(PROJECT, s) for s in
                     ('layer2/detection.c', 'layer2/baselines.c', 'layer2/advanced_detection.c',
                      'layer2/config/layer2_config.c', 'external/cJSON.c')]
    inc = ['-I' + os.path.join(PROJECT, d) for d in
           ('common', 'external', 'layer1', 'layer1/interlayer', 'layer2', 'layer2/config')]
    r = subprocess.run(['gcc', '-O2', '-fPIC', '-shared', '-o', SO] + srcs + inc + ['-lm'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit('engine build failed:\n' + r.stderr[:2000])
    print(f"built engine -> {SO}", flush=True)
    return ctypes.CDLL(SO)


L = build()
L.l2drv_new.restype = ctypes.c_void_p
L.l2drv_new.argtypes = [ctypes.c_double]*3 + [ctypes.c_uint]*3
L.l2drv_free.argtypes = [ctypes.c_void_p]
L.l2drv_n_features.restype = ctypes.c_int
L.l2drv_feature_name.restype = ctypes.c_char_p; L.l2drv_feature_name.argtypes = [ctypes.c_int]
L.l2drv_update.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_ulonglong]
L.l2drv_update_adv.argtypes = L.l2drv_update.argtypes
L.l2drv_set_persistence.argtypes = [ctypes.c_void_p, ctypes.c_uint]
L.l2drv_detect_full.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_ulonglong,
    ctypes.c_double, ctypes.c_int, ctypes.c_double, ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double)]
L.l2drv_cycle_terms.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_ulonglong,
    ctypes.c_double, ctypes.c_int, ctypes.c_double, ctypes.c_double, ctypes.c_int] + \
    [ctypes.POINTER(ctypes.c_int)]*5
NF = L.l2drv_n_features()
FEATURES = [(L.l2drv_feature_name(i) or b'').decode() for i in range(NF)]
IDX = {f: i for i, f in enumerate(FEATURES) if f}


def vec(row):
    b = (ctypes.c_double * NF)()
    for f, i in IDX.items():
        v = row.get(f, 0.0); b[i] = float(v) if v is not None else 0.0
    return b


def ts(row):
    v = row.get('_dt')
    if isinstance(v, (int, float)): return int(float(v) * 1e9)
    if isinstance(v, str):
        try: return int(_dt.datetime.fromisoformat(v).timestamp() * 1e9)
        except Exception: pass
    try: return int(float(row.get('_id_time', 0.0)) * 1e9)
    except Exception: return 0


def episodes(m):
    m = np.asarray(m).astype(int)
    return int(((m[1:] == 1) & (m[:-1] == 0)).sum() + (m[0] == 1)) if len(m) else 0


def score(fit, post, y):
    out = {}
    h = L.l2drv_new(*ALPHA, *MINSAMP)
    z, za, ca, ja, cn, js = (ctypes.c_double(), ctypes.c_int(), ctypes.c_int(),
                             ctypes.c_int(), ctypes.c_double(), ctypes.c_double())
    try:
        for r in fit:
            v, t = vec(r), ts(r)
            L.l2drv_update(ctypes.c_void_p(h), v, t); L.l2drv_update_adv(ctypes.c_void_p(h), v, t)
        mz, ZA, CA, JA = [], [], [], []
        for r in post:
            L.l2drv_detect_full(ctypes.c_void_p(h), vec(r), ts(r), THETA, AGREE, JSD_T,
                ctypes.byref(z), ctypes.byref(za), ctypes.byref(ca), ctypes.byref(ja),
                ctypes.byref(cn), ctypes.byref(js))
            mz.append(z.value); ZA.append(za.value); CA.append(ca.value); JA.append(ja.value)
    finally:
        L.l2drv_free(ctypes.c_void_p(h))
    mz = np.array(mz); ZA, CA, JA = map(np.array, (ZA, CA, JA)); b = (y == 0)
    OR = ((ZA | CA | JA) > 0).astype(int)
    out['frozen'] = {'auc_max_z': float(roc_auc_score(y, mz)),
                     'z_dr': float(ZA[y == 1].mean()), 'z_fpr': float(ZA[b].mean()),
                     'cusum_fpr': float(CA[b].mean()), 'jsd_fpr': float(JA[b].mean()),
                     'or_dr': float(OR[y == 1].mean()), 'or_fpr': float(OR[b].mean())}
    h = L.l2drv_new(*ALPHA, *MINSAMP); L.l2drv_set_persistence(ctypes.c_void_p(h), K)
    P = [ctypes.c_int() for _ in range(5)]
    try:
        for r in fit:
            v, t = vec(r), ts(r)
            L.l2drv_update(ctypes.c_void_p(h), v, t); L.l2drv_update_adv(ctypes.c_void_p(h), v, t)
        D, A = [], []
        for r in post:
            L.l2drv_cycle_terms(ctypes.c_void_p(h), vec(r), ts(r), THETA, AGREE, JSD_T, COOL, 0,
                                *[ctypes.byref(x) for x in P])
            D.append(P[3].value); A.append(P[4].value)
    finally:
        L.l2drv_free(ctypes.c_void_p(h))
    D, A = np.array(D), np.array(A)
    out['closed_loop'] = {'or_dr': float(D[y == 1].mean()), 'or_fpr': float(D[b].mean()),
                          'active_fpr': float(A[b].mean()),
                          'benign_episodes_per_1000': float(1000.0*episodes(A[b])/max(int(b.sum()), 1))}
    return out


def main():
    t0 = time.time(); panel, strict, skipped = {}, {}, []
    inv = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    for e in inv:
        try:
            fit, cal, tb, atk = load_case(e)
        except Exception as ex:
            skipped.append({'row': e['label'], 'reason': str(ex)[:120]}); continue
        if fit is None or len(fit) < 10 or len(atk) < 10: continue
        tg = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        y = np.array([t[1] for t in tg])
        panel[e['label']] = {'victim': e.get('victim') or e['label'], **score(fit, [t[2] for t in tg], y)}
        print(f"  panel  {e['label'][:46]:46s} ({time.time()-t0:.0f}s)", flush=True)
    for corp in sorted(os.listdir(EXTRACTED)):
        ix = os.path.join(EXTRACTED, corp, 'index.json')
        if not os.path.isfile(ix) or corp == 'CESNET-TimeSeries24': continue
        d = json.load(open(ix))
        items = d if isinstance(d, list) else (list(d.values())[0] if len(d) == 1 else list(d.values()))
        if isinstance(items, dict): items = list(items.values())
        for e in items:
            if not isinstance(e, dict) or e.get('verdict') != 'USABLE': continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            p = os.path.join(EXTRACTED, corp, fn)
            if not os.path.exists(p) or os.path.getsize(p) > 120e6: continue
            try:
                dd = json.load(open(p)); pi = dd.get('per_ip_windows', {})
                vic = e.get('victim') if e.get('victim') in pi else next(iter(pi), None)
                rr = sorted(pi.get(vic, []), key=tkey)
                ai = [i for i, r in enumerate(rr) if r.get('_is_attack')]
                if not ai: raise ValueError
                pre = [r for r in rr[:ai[0]] if not r.get('_is_attack')]
                if len(pre) < 30: raise ValueError
                fit = pre[:int(len(pre)*0.6)]; post = rr[ai[0]:]
                y = np.array([1 if r.get('_is_attack') else 0 for r in post])
                if y.sum() < 10 or (y == 0).sum() < 5: raise ValueError
                strict[fn] = {'victim': f"{corp}/{vic}", **score(fit, post, y)}
                print(f"  usable {corp} {fn[:38]:38s} ({time.time()-t0:.0f}s)", flush=True)
            except Exception:
                pass
            finally:
                try: del dd, pi
                except Exception: pass
                gc.collect()

    def agg(store, key):
        if not store: return {}
        return {k: round(float(np.mean([v[key][k] for v in store.values()])), 4)
                for k in next(iter(store.values()))[key]}
    res = {'note': __doc__.strip(), 'arm': 'C engine Layer 2 (shipped rule set)',
           'config': {'alpha': list(ALPHA), 'min_samples': list(MINSAMP), 'theta': THETA,
                      'min_tier_agreement': AGREE, 'jsd_threshold': JSD_T,
                      'cool_down_s': COOL, 'persistence_k': K},
           'engine_sources': ['project/layer2/detection.c', 'project/layer2/baselines.c',
                              'project/layer2/advanced_detection.c'],
           'competitor_arms': 'NOT produced here -- Python only, see run_corrected_benchmark.py',
           'skipped_rows': skipped,
           'PANEL-23': {'n': len(panel), 'frozen': agg(panel, 'frozen'),
                        'closed_loop': agg(panel, 'closed_loop'), 'per_scenario': panel},
           'USABLE-strict': {'n': len(strict), 'frozen': agg(strict, 'frozen'),
                             'closed_loop': agg(strict, 'closed_loop'), 'per_scenario': strict}}
    json.dump(res, open(OUT, 'w'), indent=1)
    for pop in ('PANEL-23', 'USABLE-strict'):
        print(f"\n{pop}: n={res[pop]['n']}")
        print(f"  frozen      {res[pop]['frozen']}")
        print(f"  closed_loop {res[pop]['closed_loop']}")
    print(f"\nwrote {OUT} ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
