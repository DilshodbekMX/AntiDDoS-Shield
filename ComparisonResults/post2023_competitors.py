"""Competitor detectors for the extracted-scenario benchmark.

EVERY detector here is either a reference implementation from PyOD (the library
maintained by the ECOD and COPOD authors) or a faithful implementation of the
cited algorithm. Hand-rolled approximations were removed, because four of them
turned out not to be the methods they were named after:

  KitNET   was linear PCA reconstruction error, which is RANK-IDENTICAL to the
           Q-statistic inside subspace_ecod_scores (Spearman 1.000000 on 23 of
           23 scenarios). It was our own model's second component under another
           name, not a competitor. Real KitNET is an ensemble of TRAINED
           autoencoders over clustered feature subspaces.
  DIF      built no trees and computed no path lengths. It scored
           exp(-|x - split|), which is HIGHEST for points nearest the split --
           the inverse of isolation. Proof: auc(s) + auc(-s) = 1.0000 exactly.
           Now taken from PyOD, which implements Xu et al. properly.
  PatchAD  used random matrices that were never trained. It correlated 0.995
           with a plain mean-squared-z statistic over the same window, and that
           trivial statistic scored HIGHER (0.9564 vs 0.9550).
  CCAD     computed calibration scores on doubly-standardised data and test
           scores on singly-standardised data, so the two were on different
           scales and the conformal p-values were not calibrated.

If a detector cannot be run faithfully it does not belong in the table. Every
function below returns a score where HIGHER MEANS MORE ANOMALOUS, fitted on
train rows only.
"""
import numpy as np

from baselines import _log_xform

_PYOD = {}


def _pyod(name):
    """Lazy-import a PyOD detector class, so a missing optional dep only
    disables the detector that needs it rather than the whole module."""
    if name in _PYOD:
        return _PYOD[name]
    mod = __import__(f'pyod.models.{name.lower()}', fromlist=[name])
    _PYOD[name] = getattr(mod, name)
    return _PYOD[name]


def ms_scale(ex, fb):
    """GPD method-of-moments scale (Siffer et al., KDD 2017, Sec. 3.2)."""
    if len(ex) > 2:
        m = np.mean(ex)
        v = np.var(ex)
        return max(0.5 * m * (m ** 2 / (v + 1e-8) + 1.0), 0.01)
    return max(fb, 0.1)


def mat(rows, feats):
    """Matrix of log-transformed features, matching the harness's own transform."""
    return np.array([[_log_xform(f, float(r.get(f, 0.0) or 0.0)) for f in feats]
                     for r in rows], dtype=float)


def _standardise(train_mat, test_mat):
    mu = np.mean(train_mat, axis=0)
    sd = np.std(train_mat, axis=0)
    sd[sd < 1e-9] = 1.0
    return (train_mat - mu) / sd, (test_mat - mu) / sd


def _run_pyod(name, train_mat, test_mat, **kw):
    Z_tr, Z_te = _standardise(train_mat, test_mat)
    clf = _pyod(name)(**kw)
    clf.fit(Z_tr)
    return np.asarray(clf.decision_function(Z_te), dtype=float)


# ── Ours ────────────────────────────────────────────────────────────────────
def subspace_ecod_scores(train_mat, test_mat, n_components=4, q=0.98):
    """Subspace-ECOD: max(SPOT excess, ECOD surprise of the subspace residual).

    SPOT (Siffer et al., KDD 2017) catches single-feature extremes; the ECOD
    rank transform (Li et al., TKDE) of the Lakhina orthogonal residual
    (SIGCOMM 2004) catches correlation-structure breaks. The rank transform also
    puts every scenario on the same -log p scale, which is what makes a SINGLE
    global threshold work across hosts.
    """
    N, D = train_mat.shape
    M = len(test_mat)

    S = np.zeros(M)
    for j in range(D):
        v = train_mat[:, j]
        tu = np.percentile(v, q * 100.0)
        sg = ms_scale(v[v > tu] - tu, np.std(v))
        S = np.maximum(S, np.where(test_mat[:, j] > tu, (test_mat[:, j] - tu) / sg, 0.0))

    if N < 2 * D:
        return S

    Z_tr, Z_te = _standardise(train_mat, test_mat)
    _, _, Vt = np.linalg.svd(Z_tr, full_matrices=False)
    k = min(n_components, Vt.shape[0])
    P = np.eye(D) - Vt[:k].T @ Vt[:k]

    Q_tr = np.sum((Z_tr @ P) ** 2, axis=1)
    Q_te = np.sum((Z_te @ P) ** 2, axis=1)
    ge = N - np.searchsorted(np.sort(Q_tr), Q_te, side='left')
    O = -np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0))
    return np.maximum(S, O)


# ── EVT family, implemented from the paper ──────────────────────────────────
def spot_baseline_scores(train_mat, test_mat, q=0.98):
    """SPOT / Peaks-Over-Threshold (Siffer et al., ACM SIGKDD 2017).

    Per-feature empirical threshold at quantile q on benign training data, GPD
    method-of-moments scale on the excesses, score = max standardised excess.
    Zero when no feature exceeds its threshold.
    """
    D = train_mat.shape[1]
    S = np.zeros(len(test_mat))
    for j in range(D):
        v = train_mat[:, j]
        tu = np.percentile(v, q * 100.0)
        sg = ms_scale(v[v > tu] - tu, np.std(v))
        S = np.maximum(S, np.where(test_mat[:, j] > tu, (test_mat[:, j] - tu) / sg, 0.0))
    return S


def dspot_scores(train_mat, test_mat, q=0.98, depth=64):
    """DSPOT: SPOT with drift (Siffer et al., ACM SIGKDD 2017, Sec. 4.2).

    DSPOT is SPOT applied to the RESIDUAL after removing local drift: each value
    is replaced by X_t - M_t, where M_t is the mean of the previous `depth`
    values in the stream. The threshold is fitted on the drift-removed training
    residuals, and the test stream is de-drifted causally, using only values
    already seen. That causal window is the whole point of the method, so it is
    implemented rather than approximated by a static mean.
    """
    N, D = train_mat.shape
    S = np.zeros(len(test_mat))

    for j in range(D):
        v = train_mat[:, j]
        # de-drift the training column with a trailing window of `depth`
        res_tr = np.empty(N)
        for i in range(N):
            lo = max(0, i - depth)
            res_tr[i] = v[i] - (np.mean(v[lo:i]) if i > lo else v[i])
        tu = np.percentile(res_tr, q * 100.0)
        sg = ms_scale(res_tr[res_tr > tu] - tu, np.std(res_tr))

        # de-drift the test column causally, seeded by the tail of training
        hist = list(v[-depth:])
        col = test_mat[:, j]
        out = np.empty(len(col))
        for i, x in enumerate(col):
            m = np.mean(hist) if hist else x
            out[i] = (x - m - tu) / sg if (x - m) > tu else 0.0
            hist.append(x)
            if len(hist) > depth:
                hist.pop(0)
        S = np.maximum(S, out)
    return S


# ── PyOD reference implementations ──────────────────────────────────────────
def ecod_scores(train_mat, test_mat):
    """ECOD (Li et al., IEEE TKDE) -- PyOD reference implementation.

    The previous hand-rolled version used the RIGHT tail only and took a max
    across dimensions; ECOD uses left, right and skewness-corrected tails and
    AGGREGATES BY SUM. That is a different detector, not a detail.
    """
    return _run_pyod('ECOD', train_mat, test_mat)


def copod_scores(train_mat, test_mat):
    """COPOD (Li et al., IEEE ICDM 2020) -- PyOD reference implementation."""
    return _run_pyod('COPOD', train_mat, test_mat)


def hbos_scores(train_mat, test_mat, n_bins=10):
    """HBOS (Goldstein & Dengel, KI-2012) -- PyOD reference implementation."""
    return _run_pyod('HBOS', train_mat, test_mat, n_bins=n_bins)


def loda_scores(train_mat, test_mat, n_bins=10, n_random_cuts=100):
    """LODA (Pevny, Machine Learning 102(2):275--304, 2016) -- PyOD reference."""
    return _run_pyod('LODA', train_mat, test_mat, n_bins=n_bins, n_random_cuts=n_random_cuts)


def inne_scores(train_mat, test_mat, n_estimators=200, max_samples=16, random_state=42):
    """INNE (Bandaragoda et al., Computational Intelligence 34(4):968--998, 2018).

    PyOD reference implementation. Note the venue: Computational Intelligence,
    not IEEE TKDE.
    """
    return _run_pyod('INNE', train_mat, test_mat, n_estimators=n_estimators,
                     max_samples=max_samples, random_state=random_state)


def dif_scores(train_mat, test_mat, random_state=42):
    """DIF: Deep Isolation Forest (Xu et al., IEEE TKDE) -- PyOD reference.

    Requires torch. Raises ImportError if it is absent, so a missing dependency
    surfaces as a skipped row rather than a silently wrong one.
    """
    return _run_pyod('DIF', train_mat, test_mat, random_state=random_state)


# Registry consumed by the benchmark runner: name -> (fn, citation).
DETECTORS = {
    'Subspace-ECOD (ours)': (subspace_ecod_scores,
                             'Lakhina SIGCOMM 2004 + Li TKDE (ECOD) + Siffer KDD 2017'),
    'SPOT':   (spot_baseline_scores, 'Siffer et al., ACM SIGKDD 2017, pp. 1067-1075'),
    'DSPOT':  (dspot_scores,         'Siffer et al., ACM SIGKDD 2017, Sec. 4.2'),
    'ECOD':   (ecod_scores,          'Li et al., IEEE TKDE (PyOD reference impl.)'),
    'COPOD':  (copod_scores,         'Li et al., IEEE ICDM 2020, pp. 1118-1123 (PyOD)'),
    'HBOS':   (hbos_scores,          'Goldstein & Dengel, KI-2012 (PyOD)'),
    'LODA':   (loda_scores,          'Pevny, Machine Learning 102(2):275-304, 2016 (PyOD)'),
    'INNE':   (inne_scores,          'Bandaragoda et al., Comput. Intell. 34(4):968-998, 2018 (PyOD)'),
    'DIF':    (dif_scores,           'Xu et al., IEEE TKDE (PyOD; needs torch)'),
}
