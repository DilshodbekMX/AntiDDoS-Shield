"""Feature-set selection, extracted verbatim from the reference harness.

Only active_features() is used by ComparisonResults; it is pure dict/min/max with no
detector logic. NOTE: the C engine scores all 39 features regardless of whether they
are constant on the training split, so a run intended to mirror the engine should pass
the full engine feature list rather than this filtered set.
"""

# Placeholders of the offline extractor, see Supplementary S10: the extractor wrote
# burst_factor = packets_per_sec and unique_flows = flows_per_sec, so in the scored
# matrix burst_factor is a bit-identical duplicate column and unique_flows is
# ln(flows_per_sec + 1). Neither is the engine's definition of that name; both are
# dropped from the evaluated schedule.
EXCLUDED_DUPLICATE_FEATURES = frozenset({'burst_factor', 'unique_flows'})


def active_features(train_rows):
    """Non-underscore keys that are non-constant on benign train (std>0).
    Same set used by both detectors so the comparison is fair.
    Names in EXCLUDED_DUPLICATE_FEATURES are skipped (placeholders of the offline
    extractor, see Supplementary S10)."""
    keys = [k for k in train_rows[0].keys()
            if not k.startswith('_') and k not in EXCLUDED_DUPLICATE_FEATURES]
    feats = []
    for f in keys:
        vals = [float(r.get(f, 0.0) or 0.0) for r in train_rows]
        if max(vals) - min(vals) > 0:
            feats.append(f)
    return sorted(feats)
