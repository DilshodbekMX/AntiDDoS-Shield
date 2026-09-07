"""Unit test: AdaptiveThreshold uses wall-clock seconds.

Pre-fix the controller used the caller's `cycle` integer as both an index AND
seconds-since-start, which broke when callers advanced cycle one-per-row on
non-1-Hz streams (CESNET hourly: 1 cycle = 3600 s).

The C engine uses clock_gettime(CLOCK_MONOTONIC) so duration tracking and
the ADAPTIVE_EVAL_INTERVAL gate operate on real wall-clock seconds. This
test asserts the Python harness now does the same when callers pass
datetime objects.
"""
import os, sys
from datetime import datetime, timezone, timedelta

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
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
    raise RuntimeError("could not locate experiment/ or experiments/ package")

from detectors import AdaptiveThreshold, _epoch_seconds  # noqa: E402
from config import ADAPTIVE_EVAL_INTERVAL  # noqa: E402


def test_epoch_seconds_datetime():
    """datetime -> its .timestamp() value."""
    t = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)
    assert abs(_epoch_seconds(t) - t.timestamp()) < 1e-9


def test_epoch_seconds_float_passthrough():
    """Plain float/int -> as-is (backward compat for PCAP runners on 1Hz)."""
    assert _epoch_seconds(300) == 300.0
    assert _epoch_seconds(300.5) == 300.5


def test_event_duration_uses_seconds_not_indices():
    """Open at t=0, close at t=42s -> duration 42 s regardless of how many
    cycles passed between them."""
    a = AdaptiveThreshold()
    t0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)
    a.on_detect(t0)
    a.on_clear(t0 + timedelta(seconds=42))
    assert len(a.events) == 1
    assert abs(a.events[0] - 42.0) < 1e-9


def test_maybe_adjust_gates_on_wall_clock():
    """Two calls 50 s apart -> no re-evaluation. Two calls
    ADAPTIVE_EVAL_INTERVAL+1 s apart -> re-evaluation fires
    (returns theta even with no events; the test asserts the gate clears)."""
    a = AdaptiveThreshold()
    t0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)
    a.maybe_adjust(t0)                         # primes last_eval
    assert a.last_eval == t0.timestamp()
    a.maybe_adjust(t0 + timedelta(seconds=50)) # within interval -- no change
    assert a.last_eval == t0.timestamp()
    a.maybe_adjust(t0 + timedelta(seconds=ADAPTIVE_EVAL_INTERVAL + 1))
    assert a.last_eval > t0.timestamp(), \
        "AdaptiveThreshold did not advance last_eval after interval elapsed"


def test_cesnet_hourly_interval_was_broken_pre_fix():
    """Pre-fix the controller treated `cycle` as seconds. On CESNET 1 cycle =
    3600 s; the controller saw ADAPTIVE_EVAL_INTERVAL=60 cycles as 60 s of
    wall-clock when it was really 60x3600 s = 60 hours.

    This regression test passes datetime objects spaced an hour apart and
    verifies that re-evaluation fires after the second hour-step
    (60 s ADAPTIVE_EVAL_INTERVAL is well under 1 hour).
    """
    a = AdaptiveThreshold()
    t0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)
    a.maybe_adjust(t0)
    a.maybe_adjust(t0 + timedelta(hours=1))   # 3600 s gap >> ADAPTIVE_EVAL_INTERVAL
    assert a.last_eval == (t0 + timedelta(hours=1)).timestamp(), \
        "CESNET hourly callers should trigger re-evaluation after 1 wall-clock hour"


if __name__ == '__main__':
    test_epoch_seconds_datetime()
    test_epoch_seconds_float_passthrough()
    test_event_duration_uses_seconds_not_indices()
    test_maybe_adjust_gates_on_wall_clock()
    test_cesnet_hourly_interval_was_broken_pre_fix()
    print("test_adaptive_timebase.py — all 5 tests passed")
