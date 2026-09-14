"""Feature-set selection, extracted verbatim from the reference harness.

Only active_features() is used by ComparisonResults; it is pure dict/min/max with no
detector logic. NOTE: the C engine scores all 39 features regardless of whether they
are constant on the training split, so a run intended to mirror the engine should pass
the full engine feature list rather than this filtered set.
"""


def active_features(train_rows):
    """Non-underscore keys that are non-constant on benign train (std>0).
    Same set used by both detectors so the comparison is fair."""
    keys = [k for k in train_rows[0].keys() if not k.startswith('_')]
    feats = []
    for f in keys:
        vals = [float(r.get(f, 0.0) or 0.0) for r in train_rows]
        if max(vals) - min(vals) > 0:
            feats.append(f)
    return sorted(feats)
