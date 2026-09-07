"""Unit test for ThreeTierBaseline tier-readiness gate.

The Python harness used to accept tier-2/3 votes if ANY feature in the slot
had a non-None z-score. That let immature tiers contribute partial votes
and over-detect early in long streams (especially CESNET hourly data with
sparse tier-3 weekly slots).

The C engine requires every feature to reach `min_samples_ready` before
the tier is voted-eligible -- see layer2/baselines.c:289-298:

    bool all_ready = true;
    for (int i = 0; i < L2_MAX_FEATURES; i++) {
        if (tier->features[i].sample_count < tier->min_samples_ready) {
            all_ready = false;
            break;
        }
    }
    tier->ready = all_ready;

This test asserts that experiment/baselines.py mirrors that gate.

Each test exercises one scenario; failures here mean some C-engine claim
in the paper's per-second numbers is over-detecting compared to production.
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
from config import TIER2_MIN_SAMPLES, TIER1_MIN_SAMPLES  # noqa: E402


def test_partial_tier2_readiness_yields_none():
    """If only one of three features has reached tier-2 min_samples_ready,
    z_scores()['t2'] must be None (not a partial dict)."""
    feats = ['a', 'b', 'c']
    bl = ThreeTierBaseline(feats)
    dt = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    # Update ONLY feature 'a' on tier-2's hour-12 slot
    for i in range(TIER2_MIN_SAMPLES + 5):
        bl.t2[12]['a'].update(float(i))
    # 'b' and 'c' on tier-2 still have sample_count == 0
    assert bl.t2[12]['a'].ready() is True
    assert bl.t2[12]['b'].ready() is False
    assert bl.t2[12]['c'].ready() is False

    z = bl.z_scores({'a': 100, 'b': 0, 'c': 0}, dt)
    assert z['t2'] is None, (
        "tier-2 voted with partial-readiness slot. "
        f"got: {z['t2']!r}"
    )


def test_full_tier2_readiness_yields_dict():
    """When all features reach tier-2 min_samples_ready, z_scores()['t2'] is
    a populated dict."""
    feats = ['a', 'b', 'c']
    bl = ThreeTierBaseline(feats)
    dt = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    # All three features warm to ready on tier-2 hour-12 slot
    for i in range(TIER2_MIN_SAMPLES + 5):
        bl.t2[12]['a'].update(float(i))
        bl.t2[12]['b'].update(float(i * 2))
        bl.t2[12]['c'].update(float(i * 0.5))
    z = bl.z_scores({'a': 100, 'b': 200, 'c': 50}, dt)
    assert isinstance(z['t2'], dict), f"tier-2 should vote when all ready, got {z['t2']!r}"
    assert set(z['t2'].keys()) == set(feats)


def test_tier1_votes_when_all_ready():
    """Tier-1 votes as soon as every feature has reached its min_samples."""
    feats = ['a']
    bl = ThreeTierBaseline(feats)
    dt = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    for i in range(TIER1_MIN_SAMPLES + 1):
        bl.update({'a': float(i)}, dt + timedelta(seconds=i))
    z = bl.z_scores({'a': 99999}, dt)
    assert z['t1'] is not None
    assert 'a' in z['t1']


def test_partial_tier1_readiness_yields_none():
    """tier-1 with partial readiness must also yield None.
    The C engine's `tier->ready` gate applies to every tier including the
    immediate one -- `tier_baseline_z_scores` short-circuits when
    `!tier->ready` regardless of which tier it is (baselines.c:289-298)."""
    feats = ['a', 'b', 'c']
    bl = ThreeTierBaseline(feats)
    dt = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    # Warm only one of three features on tier-1
    for i in range(TIER1_MIN_SAMPLES + 1):
        bl.t1['a'].update(float(i))
    assert bl.t1['a'].ready() is True
    assert bl.t1['b'].ready() is False
    z = bl.z_scores({'a': 100, 'b': 0, 'c': 0}, dt)
    assert z['t1'] is None, (
        "tier-1 voted with partial-readiness slot. "
        f"got: {z['t1']!r}"
    )


if __name__ == '__main__':
    test_partial_tier2_readiness_yields_none()
    test_full_tier2_readiness_yields_dict()
    test_tier1_votes_when_all_ready()
    test_partial_tier1_readiness_yields_none()
    print("test_tier_readiness.py — all 4 tests passed")
