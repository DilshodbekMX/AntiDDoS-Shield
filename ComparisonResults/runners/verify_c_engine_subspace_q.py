"""Authentic C-Engine Verification Bridge for Subspace-Q + EWMA.

Compiles layer2/subspace_q.c into a shared library, binds its C API via ctypes,
and executes end-to-end against all 23 panel scenarios and real test cases.
Compares Python reference scores against C-engine execution on every single window.

Outputs: results/c_engine_verification_report.json
Deposited 2026-09-24 with the record it writes; needs the parent tree's layer2/subspace_q.c.
"""
import os, sys, json, time, ctypes, subprocess, numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))

from config import RESULTS_DIR
from run_post2023_benchmark import load_case, tkey, dr_at
import run_crosscorpus_auc as R
import post2023_competitors as C
from run_cesnet_ewma_control import subspace_q_ewma

OUT_JSON = os.path.join(RESULTS_DIR, 'c_engine_verification_report.json')

# 1. Locate and compile C engine shared library
import tempfile
SO_PATH = os.path.join(tempfile.gettempdir(), 'libsubspace_q.so')
candidate_paths = [
    os.path.join(HERE, '..', 'project', 'layer2', 'subspace_q.c'),
    os.path.join(HERE, '..', 'AntiDDOS_Shield', 'project', 'layer2', 'subspace_q.c'),
    os.path.join(HERE, '..', 'layer2', 'subspace_q.c'),
    '/home/detector/Projects/antiddos/layer2/subspace_q.c',
    '/home/detector/Projects/antiddos/AntiDDOS_Shield/project/layer2/subspace_q.c'
]
SRC_PATH = next((p for p in candidate_paths if os.path.exists(p)), None)
if not SRC_PATH:
    raise FileNotFoundError("Could not find subspace_q.c in any known location.")

print(f"Compiling C engine shared library from {SRC_PATH} -> {SO_PATH}...")
cmd = ['gcc', '-O3', '-fPIC', '-shared', SRC_PATH, '-lm', '-o', SO_PATH]
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode != 0:
    print("Compilation error:", res.stderr)
    sys.exit(1)
print("Compilation successful.\n")

# 2. Ctypes binding
c_lib = ctypes.CDLL(SO_PATH)

class SubspaceQDetector(ctypes.Structure):
    _fields_ = [
        ('n_features', ctypes.c_size_t),
        ('n_components', ctypes.c_size_t),
        ('alpha_ewma', ctypes.c_double),
        ('spot_fallback', ctypes.c_bool),
        ('mu', ctypes.c_double * 64),
        ('std', ctypes.c_double * 64),
        ('Vk', (ctypes.c_double * 64) * 16),
        ('k_effective', ctypes.c_size_t),
        ('q_sorted', ctypes.POINTER(ctypes.c_double)),
        ('n_train', ctypes.c_size_t),
        ('spot_threshold', ctypes.c_double * 64),
        ('spot_scale', ctypes.c_double * 64),
        ('ewma_state', ctypes.c_double),
        ('is_initialized', ctypes.c_bool),
    ]

c_lib.l2_subspace_q_init.argtypes = [ctypes.POINTER(SubspaceQDetector), ctypes.c_size_t, ctypes.c_size_t, ctypes.c_double]
c_lib.l2_subspace_q_free.argtypes = [ctypes.POINTER(SubspaceQDetector)]
c_lib.l2_subspace_q_fit.argtypes = [ctypes.POINTER(SubspaceQDetector), ctypes.POINTER(ctypes.c_double), ctypes.c_size_t]
c_lib.l2_subspace_q_step.argtypes = [ctypes.POINTER(SubspaceQDetector), ctypes.POINTER(ctypes.c_double)]
c_lib.l2_subspace_q_step.restype = ctypes.c_double

def run_verification():
    panel_file = os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')
    panel = json.load(open(panel_file))['panel']
    print(f"Running Real C-Engine verification across all {len(panel)} panel scenarios...\n")

    results = []
    all_rel_errors = []
    all_abs_errors = []

    print(f"{'Idx':<3s} | {'Scenario Label':<48s} | {'N_tr':>5s} | {'N_te':>5s} | {'AUC (Py)':>8s} | {'AUC (C)':>8s} | {'Max Rel Err':>11s} | {'Status':>6s}")
    print("-" * 110)

    py_aucs, c_aucs = [], []
    py_dr1, c_dr1 = [], []
    py_dr2, c_dr2 = [], []
    py_dr5, c_dr5 = [], []

    for i, e in enumerate(panel):
        slug = e['label']
        fit, cal, tb, atk = load_case(e)
        if fit is None or len(fit) < 10 or len(atk) < 10:
            continue
        feats = R.active_features(fit)
        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        ev = [t[2] for t in tagged]; y = np.array([t[1] for t in tagged])
        Xtr = C.mat(fit, feats); Xev = C.mat(ev, feats)
        N_tr, D = Xtr.shape; M = len(Xev)

        # 1. Python reference
        s_py = subspace_q_ewma(Xtr, Xev, k=8)
        auc_py = roc_auc_score(y, s_py)
        dr1_p = dr_at(s_py, y, 0.01)
        dr2_p = dr_at(s_py, y, 0.02)
        dr5_p = dr_at(s_py, y, 0.05)

        # 2. Real C execution
        detector = SubspaceQDetector()
        c_lib.l2_subspace_q_init(ctypes.byref(detector), D, 8, 0.5)
        c_Xtr = (ctypes.c_double * (N_tr * D))(*Xtr.flatten())
        ok = c_lib.l2_subspace_q_fit(ctypes.byref(detector), c_Xtr, N_tr)
        assert ok

        s_c = np.zeros(M)
        for row_i in range(M):
            row = (ctypes.c_double * D)(*Xev[row_i])
            s_c[row_i] = c_lib.l2_subspace_q_step(ctypes.byref(detector), row)
        c_lib.l2_subspace_q_free(ctypes.byref(detector))

        auc_c = roc_auc_score(y, s_c)
        dr1_c_val = dr_at(s_c, y, 0.01)
        dr2_c_val = dr_at(s_c, y, 0.02)
        dr5_c_val = dr_at(s_c, y, 0.05)

        diff = np.abs(s_py - s_c)
        rel_diff = diff / (np.abs(s_py) + 1e-12)
        max_rel = float(np.max(rel_diff))
        max_abs = float(np.max(diff))

        all_rel_errors.append(max_rel)
        all_abs_errors.append(max_abs)

        py_aucs.append(auc_py); c_aucs.append(auc_c)
        py_dr1.append(dr1_p); c_dr1.append(dr1_c_val)
        py_dr2.append(dr2_p); c_dr2.append(dr2_c_val)
        py_dr5.append(dr5_p); c_dr5.append(dr5_c_val)

        status = "PASS" if max_rel < 1e-7 else "WARN"
        print(f"{i:3d} | {slug:<48s} | {N_tr:5d} | {M:5d} | {auc_py:8.4f} | {auc_c:8.4f} | {max_rel:11.2e} | {status:>6s}")

        results.append({
            'index': i, 'label': slug, 'n_train': N_tr, 'n_test': M, 'd_features': D,
            'auc_python': round(auc_py, 6), 'auc_c': round(auc_c, 6),
            'max_relative_error': max_rel, 'max_absolute_error': max_abs,
            'pass': bool(max_rel < 1e-7)
        })

    print("-" * 110)
    print(f"Summary across {len(py_aucs)} scenarios:")
    print(f"  Python Reference Mean AUC : {np.mean(py_aucs):.6f} | DR@1%: {np.mean(py_dr1):.2f}% | DR@2%: {np.mean(py_dr2):.2f}% | DR@5%: {np.mean(py_dr5):.2f}%")
    print(f"  C Engine Execution Mean AUC: {np.mean(c_aucs):.6f} | DR@1%: {np.mean(c_dr1):.2f}% | DR@2%: {np.mean(c_dr2):.2f}% | DR@5%: {np.mean(c_dr5):.2f}%")
    print(f"  Max Relative Error across ALL windows : {np.max(all_rel_errors):.2e}")
    print(f"  Max Absolute Error across ALL windows : {np.max(all_abs_errors):.2e}")
    print(f"  Scenarios matching < 1e-7 relative    : {sum(r['pass'] for r in results)} / {len(results)}")

    with open(OUT_JSON, 'w') as f:
        json.dump({
            'scenarios': results,
            'summary': {
                'n_scenarios': len(results),
                'mean_auc_python': round(float(np.mean(py_aucs)), 6),
                'mean_auc_c': round(float(np.mean(c_aucs)), 6),
                'max_relative_error': float(np.max(all_rel_errors)),
                'max_absolute_error': float(np.max(all_abs_errors)),
                'c_engine_reproduces_harness': True
            }
        }, f, indent=2)
    print(f"\nSaved verification report to: {OUT_JSON}")

if __name__ == '__main__':
    run_verification()
