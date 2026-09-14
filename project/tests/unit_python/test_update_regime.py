"""Unit test for pipeline.should_update_baseline + UpdateRegime.

Previously, each runner inlined its own (not det) / (not is_attack) gate.
There were three distinct gating patterns across the codebase plus a
fourth pattern used by the production C engine. A single helper lets each
call-site declare its regime explicitly by name.

This test verifies the truth table for all four regimes plus the global
`frozen` short-circuit.
"""
import os, sys

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# Locate the experiment package whether we're in the source tree
# (<repo>/experiment, tests at <repo>/tests/unit_python/) or the GitHub-release
# tree (<root>/experiments, tests at <root>/project/tests/unit_python/).
for _candidate in (
    os.path.join(THIS_DIR, "..", "..", "ComparisonResults"),
    os.path.join(THIS_DIR, "..", "..", "..", "ComparisonResults"),
    os.path.join(THIS_DIR, "..", "..", "experiment"),
    os.path.join(THIS_DIR, "..", "..", "experiments"),
    os.path.join(THIS_DIR, "..", "..", "..", "experiment"),
    os.path.join(THIS_DIR, "..", "..", "..", "experiments"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "ComparisonResults"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "experiment"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "experiments"),
):
    _candidate = os.path.abspath(_candidate)
    if os.path.isdir(_candidate):
        sys.path.insert(0, _candidate)
        break
else:
    raise RuntimeError("could not locate ComparisonResults or experiment package "
                       "from {}".format(THIS_DIR))

from pipeline import should_update_baseline, UpdateRegime  # noqa: E402


def test_frozen_short_circuit():
    """frozen=True overrides every regime."""
    for r in (UpdateRegime.FROZEN_AUDIT, UpdateRegime.CONJUNCTION_BENIGN,
              UpdateRegime.PRODUCTION_EPISODE, UpdateRegime.ATTACK_SKIP):
        assert should_update_baseline(False, False, frozen=True, regime=r) is False


def test_frozen_audit_never_updates():
    """FROZEN_AUDIT regime never updates regardless of det / is_attack."""
    for det in (False, True):
        for atk in (False, True):
            assert should_update_baseline(det, atk, regime=UpdateRegime.FROZEN_AUDIT) is False


def test_conjunction_benign():
    """CONJUNCTION_BENIGN updates only when (not det) AND (not is_attack)."""
    assert should_update_baseline(False, False, regime=UpdateRegime.CONJUNCTION_BENIGN) is True
    assert should_update_baseline(True,  False, regime=UpdateRegime.CONJUNCTION_BENIGN) is False
    assert should_update_baseline(False, True,  regime=UpdateRegime.CONJUNCTION_BENIGN) is False
    assert should_update_baseline(True,  True,  regime=UpdateRegime.CONJUNCTION_BENIGN) is False


def test_production_episode_ignores_attack_label():
    """PRODUCTION_EPISODE updates when (not det) -- mirrors C per-IP gate
    (layer2.c:1700-1704) which updates unless this IP is per-IP anomalous,
    even if the ground-truth label says attack."""
    assert should_update_baseline(False, False, regime=UpdateRegime.PRODUCTION_EPISODE) is True
    assert should_update_baseline(False, True,  regime=UpdateRegime.PRODUCTION_EPISODE) is True
    assert should_update_baseline(True,  False, regime=UpdateRegime.PRODUCTION_EPISODE) is False
    assert should_update_baseline(True,  True,  regime=UpdateRegime.PRODUCTION_EPISODE) is False


def test_attack_skip_ignores_detection():
    """ATTACK_SKIP updates whenever is_attack is False, regardless of det."""
    assert should_update_baseline(False, False, regime=UpdateRegime.ATTACK_SKIP) is True
    assert should_update_baseline(True,  False, regime=UpdateRegime.ATTACK_SKIP) is True
    assert should_update_baseline(False, True,  regime=UpdateRegime.ATTACK_SKIP) is False
    assert should_update_baseline(True,  True,  regime=UpdateRegime.ATTACK_SKIP) is False


def test_unknown_regime_raises():
    """Unknown regime strings raise ValueError so typos don't silently misroute."""
    try:
        should_update_baseline(False, False, regime='not-a-real-regime')
    except ValueError:
        pass
    else:
        raise AssertionError("unknown regime should raise ValueError")


if __name__ == '__main__':
    test_frozen_short_circuit()
    test_frozen_audit_never_updates()
    test_conjunction_benign()
    test_production_episode_ignores_attack_label()
    test_attack_skip_ignores_detection()
    test_unknown_regime_raises()
    print("test_update_regime.py — all 6 tests passed")
