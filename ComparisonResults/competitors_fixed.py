"""Corrected competitor set for the Subspace-Q + EWMA benchmark.

Supersedes post2023_competitors.py, which the 2026-08-27 audit found defective in
four of nine rows. Every defect fixed here was demonstrated by execution, not
argued; see ComparisonResults/README.md for the evidence.

WHAT WAS WRONG AND WHAT CHANGED
  ECOD, COPOD  PyOD's decision_function concatenates X_train onto the scored
               batch and recomputes the ECDF over the union (ecod.py, copod.py).
               On a 67%-attack panel the attacks became their own reference
               distribution. Reimplemented INDUCTIVELY here: the ECDF is built on
               train and merely EVALUATED at test points.
  DIF          PyOD's _deep_representation calls StandardScaler().fit_transform
               on whichever batch it is scoring (dif.py:282), so test rows were
               standardised against each other. Subclassed to fit the scaler once
               per ensemble member on the TRAIN pass and reuse it thereafter.
               (minmax_scaler was already train-fitted and is left alone.)
  LODA         Was the only arm without a random_state, so its row was a single
               unreproducible draw. Seeded.
  DSPOT        Fed flagged anomalies back into the local drift window, which
               Siffer Algorithm 3 line 16 forbids ("W* does not contain abnormal
               values"). During a sustained flood the trailing mean climbed to the
               attack level and the residual collapsed. The window is now frozen
               on an alarm.
  SPOT         Renamed POT. What is implemented is a static per-feature
               peaks-over-threshold detector with a method-of-moments GPD scale.
               Siffer's SPOT is online and univariate and fits the GPD by MLE, so
               the old name overclaimed. MoM is Hosking & Wallis, not Siffer.

NEW: IsolationForest, the shallow reference DIF is the deep version of, so the
two can be read against each other.

Every function returns a score where HIGHER MEANS MORE ANOMALOUS, computed from
train rows only. That claim is now true for all ten arms and is enforced by
verify_inductive.py.
"""
import numpy as np
from scipy.stats import skew

from baselines import _log_xform

_PYOD = {}


def _pyod(name):
    if name not in _PYOD:
        mod = __import__(f'pyod.models.{name.lower()}', fromlist=[name])
        _PYOD[name] = getattr(mod, name)
    return _PYOD[name]


def mat(rows, feats):
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


# ── EVT family ──────────────────────────────────────────────────────────────
def ms_scale(ex, fb):
    """Method-of-moments GPD scale (Hosking & Wallis, Technometrics 29(3), 1987).

    NOT Siffer: KDD 2017 Sec. 3.2 raises method-of-moments only to reject it in
    favour of maximum likelihood via Grimshaw. Attributing MoM to that paper was
    a misattribution and is corrected here.
    """
    if len(ex) > 2:
        m, v = np.mean(ex), np.var(ex)
        return max(0.5 * m * (m ** 2 / (v + 1e-8) + 1.0), 0.01)
    return max(fb, 0.1)


def pot_scores(train_mat, test_mat, q=0.98):
    """Static per-feature peaks-over-threshold, MoM GPD scale, max over features.

    Deliberately NOT called SPOT: Siffer's SPOT is an online univariate algorithm
    with an MLE-fitted GPD and a drifting threshold. This is the static
    multivariate-by-max variant that the archive has always run; the numbers are
    unchanged, only the name and the attribution are now honest.
    """
    S = np.zeros(len(test_mat))
    for j in range(train_mat.shape[1]):
        v = train_mat[:, j]
        tu = np.percentile(v, q * 100.0)
        sg = ms_scale(v[v > tu] - tu, np.std(v))
        S = np.maximum(S, np.where(test_mat[:, j] > tu, (test_mat[:, j] - tu) / sg, 0.0))
    return S


def dspot_scores(train_mat, test_mat, q=0.98, depth=64):
    """DSPOT, faithful to Siffer Algorithm 3: the drift window excludes alarms.

    Algorithm 3 line 16 adds X_i to W only on the normal branch. The previous
    implementation appended unconditionally, so a sustained flood dragged the
    trailing mean up to the attack level and the residual went to zero.
    """
    N, D = train_mat.shape
    S = np.zeros(len(test_mat))

    for j in range(D):
        v = train_mat[:, j]
        res_tr = np.empty(N)
        for i in range(N):
            lo = max(0, i - depth)
            res_tr[i] = v[i] - (np.mean(v[lo:i]) if i > lo else v[i])
        tu = np.percentile(res_tr, q * 100.0)
        sg = ms_scale(res_tr[res_tr > tu] - tu, np.std(res_tr))

        hist = list(v[-depth:])
        col = test_mat[:, j]
        out = np.empty(len(col))
        for i, x in enumerate(col):
            m = np.mean(hist) if hist else x
            resid = x - m
            if resid > tu:
                out[i] = (resid - tu) / sg          # ALARM
            else:
                out[i] = 0.0
                hist.append(x)                       # normal branch only
                if len(hist) > depth:
                    hist.pop(0)
        S = np.maximum(S, out)
    return S


# ── Inductive ECOD / COPOD ──────────────────────────────────────────────────
def _tail_probs(train_col, test_col):
    """Left/right tail probabilities of test values under the TRAIN ECDF."""
    s = np.sort(train_col)
    N = len(s)
    floor = 1.0 / (N + 1)
    left = np.searchsorted(s, test_col, side='right') / N
    right = (N - np.searchsorted(s, test_col, side='left')) / N
    return np.maximum(left, floor), np.maximum(right, floor)


def _ecod_tails(train_mat, test_mat):
    M, D = test_mat.shape
    U_l = np.empty((M, D)); U_r = np.empty((M, D))
    for j in range(D):
        l, r = _tail_probs(train_mat[:, j], test_mat[:, j])
        U_l[:, j] = -np.log(l)
        U_r[:, j] = -np.log(r)
    sk = np.sign(skew(train_mat, axis=0))            # skewness from TRAIN
    U_skew = U_l * -1 * np.sign(sk - 1) + U_r * np.sign(sk + 1)
    return U_l, U_r, U_skew


def ecod_scores(train_mat, test_mat):
    """ECOD (Li et al., IEEE TKDE 35(12):12181-12193, 2023) -- INDUCTIVE.

    Same tail construction and sum aggregation as PyOD, but the ECDF and the
    skewness sign come from the training rows alone, so a row's score does not
    depend on what else is in the batch.
    """
    Z_tr, Z_te = _standardise(train_mat, test_mat)
    U_l, U_r, U_skew = _ecod_tails(Z_tr, Z_te)
    O = np.maximum(np.maximum(U_l, U_r), U_skew)
    return O.sum(axis=1)


def copod_scores(train_mat, test_mat):
    """COPOD (Li et al., IEEE ICDM 2020, pp. 1118-1123) -- INDUCTIVE.

    COPOD's aggregation, max(U_skew, (U_l + U_r)/2), over a train-fitted
    empirical copula.
    """
    Z_tr, Z_te = _standardise(train_mat, test_mat)
    U_l, U_r, U_skew = _ecod_tails(Z_tr, Z_te)
    O = np.maximum(U_skew, (U_l + U_r) / 2.0)
    return O.sum(axis=1)


# ── PyOD arms that were already sound ───────────────────────────────────────
def hbos_scores(train_mat, test_mat, n_bins=10):
    """HBOS (Goldstein & Dengel, KI-2012, pp. 59-63). Verified batch-invariant."""
    return _run_pyod('HBOS', train_mat, test_mat, n_bins=n_bins)


def inne_scores(train_mat, test_mat, n_estimators=200, max_samples=16, random_state=42):
    """INNE (Bandaragoda et al., Comput. Intell. 34(4):968-998, 2018)."""
    return _run_pyod('INNE', train_mat, test_mat, n_estimators=n_estimators,
                     max_samples=max_samples, random_state=random_state)


def loda_scores(train_mat, test_mat, n_bins=10, n_random_cuts=100, random_state=42):
    """LODA (Pevny, Machine Learning 102(2):275-304, 2016). NOW SEEDED.

    PyOD's LODA draws fresh random projections per call and the archive's row was
    a single unreproducible draw (two committed artifacts disagree, 0.5536 vs
    0.5876). np.random.seed is set around construction; PyOD's LODA also accepts
    random_state, and at a common seed the two routes agree.
    """
    np.random.seed(random_state)
    return _run_pyod('LODA', train_mat, test_mat, n_bins=n_bins,
                     n_random_cuts=n_random_cuts)


def iforest_scores(train_mat, test_mat, n_estimators=200, random_state=42):
    """Isolation Forest (Liu, Ting & Zhou, ICDM 2008, pp. 413-422).

    The shallow reference point for DIF: if DIF underperforms and IForest does
    not, that is a DIF result rather than a property of isolation.
    """
    return _run_pyod('IForest', train_mat, test_mat, n_estimators=n_estimators,
                     random_state=random_state)


# ── Inductive DIF ───────────────────────────────────────────────────────────
def _inductive_dif_cls():
    """DIF with the representation scaler frozen after the training pass."""
    import torch
    from torch.utils.data import DataLoader
    from sklearn.preprocessing import StandardScaler
    DIF = _pyod('DIF')

    class InductiveDIF(DIF):
        def _deep_representation(self, net, X):
            if not hasattr(self, '_rep_scalers'):
                self._rep_scalers = {}
            net.eval()
            reduced = []
            with torch.no_grad():
                loader = DataLoader(X, batch_size=self.batch_size,
                                    drop_last=False, pin_memory=True, shuffle=False)
                for bx in loader:
                    reduced.append(net(bx.float().to(self.device)))
            raw = torch.cat(reduced).data.cpu().numpy()
            key = id(net)
            if key not in self._rep_scalers:          # first pass = TRAIN
                self._rep_scalers[key] = StandardScaler().fit(raw)
            return np.tanh(self._rep_scalers[key].transform(raw))

    return InductiveDIF


def dif_scores(train_mat, test_mat, random_state=42):
    """DIF (Xu et al., IEEE TKDE 35(12):12591-12604, 2023) -- INDUCTIVE.

    Note the year: no version of this paper is 2024 (TKDE 2024 is volume 36).
    """
    Z_tr, Z_te = _standardise(train_mat, test_mat)
    clf = _inductive_dif_cls()(random_state=random_state)
    clf.fit(Z_tr)
    return np.asarray(clf.decision_function(Z_te), dtype=float)


# ── Ours ────────────────────────────────────────────────────────────────────
ALPHA, K = 0.5, 8


def ewma(s, alpha=ALPHA):
    out = np.zeros(len(s)); cur = 0.0
    for i, v in enumerate(s):
        cur = alpha * v + (1.0 - alpha) * cur
        out[i] = cur
    return out


def subspace_q_ewma(train_mat, test_mat, k=K):
    """Ours. Unchanged from run_final_evaluation.py:51-64."""
    N, D = train_mat.shape
    if N < 2 * D:
        return pot_scores(train_mat, test_mat)
    mu = train_mat.mean(axis=0); sd = train_mat.std(axis=0); sd[sd < 1e-9] = 1.0
    Ztr, Zte = (train_mat - mu) / sd, (test_mat - mu) / sd
    _, _, Vt = np.linalg.svd(Ztr, full_matrices=False)
    Vk = Vt[:min(k, Vt.shape[0])]
    Qtr = np.sum(Ztr ** 2, axis=1) - np.sum((Ztr @ Vk.T) ** 2, axis=1)
    Qte = np.sum(Zte ** 2, axis=1) - np.sum((Zte @ Vk.T) ** 2, axis=1)
    Qte_adj = Qte - 1e-12 * np.maximum(1.0, Qte)
    ge = N - np.searchsorted(np.sort(Qtr), Qte_adj, side='left')
    return ewma(-np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0)))


DETECTORS = {
    'Subspace-Q + EWMA (ours)': (subspace_q_ewma, 'Lakhina SIGCOMM 2004 + Li TKDE 2023 (ECOD) rank transform'),
    'POT':    (pot_scores,     'Hosking & Wallis, Technometrics 29(3), 1987 (MoM GPD); cf. Siffer KDD 2017'),
    'DSPOT':  (dspot_scores,   'Siffer et al., ACM SIGKDD 2017, Sec. 4.2.2, Algorithm 3'),
    'ECOD':   (ecod_scores,    'Li et al., IEEE TKDE 35(12):12181-12193, 2023'),
    'COPOD':  (copod_scores,   'Li et al., IEEE ICDM 2020, pp. 1118-1123, doi:10.1109/ICDM50108.2020.00135'),
    'HBOS':   (hbos_scores,    'Goldstein & Dengel, KI-2012, pp. 59-63 (PyOD)'),
    'LODA':   (loda_scores,    'Pevny, Machine Learning 102(2):275-304, 2016 (PyOD, seeded)'),
    'INNE':   (inne_scores,    'Bandaragoda et al., Comput. Intell. 34(4):968-998, 2018 (PyOD)'),
    'IForest': (iforest_scores, 'Liu, Ting & Zhou, IEEE ICDM 2008, pp. 413-422 (PyOD)'),
    'DIF':    (dif_scores,     'Xu et al., IEEE TKDE 35(12):12591-12604, 2023 (PyOD, inductive)'),
}
