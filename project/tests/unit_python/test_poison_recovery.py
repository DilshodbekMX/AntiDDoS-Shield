"""Unit test for ThreeTierBaseline poison auto-recovery.

The Python harness used to set self.frozen = True permanently whenever the
poisoning detector tripped. Long-running streams (CESNET, LITNET) lost their
baseline adaptation for the remainder of the test.

The C engine auto-unfreezes after a recovery interval -- see layer2/layer2.c
lines 660-672:

    if (baseline_is_poisoned(...) && !g_layer2.anomaly_state.active) {
        uint64_t elapsed_ns = snapshot.timestamp_ns - poison_ns;
        if (elapsed_ns >= recovery_ns) {
            baseline_poison_tracker_reset(...);
            three_tier_baseline_unfreeze(...);
        }
    }

This test asserts that experiment/baselines.py mirrors that auto-recovery.
"""
import os, sys
from datetime import datetime, timezone, timedelta

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# Locate the experiment package whether we're in the source tree
# (<repo>/experiment, tests at <repo>/tests/unit_python/) or the GitHub-release
# tree (<root>/experiments, tests at <root>/project/tests/unit_python/).
for _candidate in (
    os.path.join(THIS_DIR, "..", "..", "experiment"),
    os.path.join(THIS_DIR, "..", "..", "experiments"),
    os.path.join(THIS_DIR, "..", "..", "..", "experiment"),
    os.path.join(THIS_DIR, "..", "..", "..", "experiments"),
):
    _candidate = os.path.abspath(_candidate)
    if os.path.isdir(_candidate):
        sys.path.insert(0, _candidate)
        break
else:
    raise RuntimeError("could not locate experiment/ or experiments/ package "
                       "from {}".format(THIS_DIR))

from baselines import ThreeTierBaseline  # noqa: E402
from config import BASELINE_POISON_RECOVERY_SEC  # noqa: E402


KEY_FEATS = ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec', 'flows_per_sec']


def _warm_baseline(bl, t0, n=50):
    """Warm a baseline with steady benign traffic before tripping poison."""
    for i in range(n):
        bl.update({f: 10 for f in KEY_FEATS}, t0 + timedelta(seconds=i))


def test_frozen_does_not_recover_before_window():
    """Within the recovery window, the baseline stays frozen."""
    bl = ThreeTierBaseline(KEY_FEATS)
    t0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    _warm_baseline(bl, t0)
    # Simulate poison trip
    bl.frozen = True
    bl.poison_detected = True
    bl.poison_detected_at = t0 + timedelta(seconds=100)
    # Try to update half-way through the recovery window
    half = BASELINE_POISON_RECOVERY_SEC // 2
    bl.update({f: 10 for f in KEY_FEATS}, t0 + timedelta(seconds=100 + half))
    assert bl.frozen, "baseline unfroze BEFORE recovery window elapsed"


def test_frozen_recovers_after_window():
    """At or past the recovery window, the baseline auto-unfreezes."""
    bl = ThreeTierBaseline(KEY_FEATS)
    t0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    _warm_baseline(bl, t0)
    bl.frozen = True
    bl.poison_detected = True
    bl.poison_detected_at = t0 + timedelta(seconds=100)
    # Update at t = 100 + recovery + buffer
    bl.update(
        {f: 10 for f in KEY_FEATS},
        t0 + timedelta(seconds=100 + BASELINE_POISON_RECOVERY_SEC + 10),
    )
    assert not bl.frozen, "baseline still frozen after recovery window"
    assert bl.poison_detected_at is None, "poison_detected_at should reset on recovery"
    assert bl.poison_detected is False


def test_recovery_reseeds_poison_reference():
    """After recovery, poison_last_mean is reseeded from current tier-1 mean
    so the next 300 s window measures change from the post-recovery state,
    not the pre-poison state."""
    bl = ThreeTierBaseline(KEY_FEATS)
    t0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    _warm_baseline(bl, t0)
    # Inject some artificial pre-poison reference
    for f in KEY_FEATS:
        bl.poison_last_mean[f] = 0.1   # value that would trip a >200% jump
    bl.frozen = True
    bl.poison_detected_at = t0 + timedelta(seconds=100)
    bl.update(
        {f: 10 for f in KEY_FEATS},
        t0 + timedelta(seconds=100 + BASELINE_POISON_RECOVERY_SEC + 10),
    )
    # After recovery, poison_last_mean must reflect current tier-1 mean
    for f in KEY_FEATS:
        assert abs(bl.poison_last_mean[f] - bl.t1[f].mean) < 1e-9, (
            f"poison_last_mean[{f}] not reseeded after recovery"
        )


if __name__ == '__main__':
    test_frozen_does_not_recover_before_window()
    test_frozen_recovers_after_window()
    test_recovery_reseeds_poison_reference()
    print("test_poison_recovery.py — all 3 tests passed")
