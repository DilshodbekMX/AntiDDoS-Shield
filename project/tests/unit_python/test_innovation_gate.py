"""Unit tests for Innovation (Forecast-Error Surprise) Path."""
import pytest
import numpy as np
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (
    os.path.join(HERE, "..", "..", "ComparisonResults"),
    os.path.join(HERE, "..", "..", "..", "ComparisonResults"),
    os.path.join(HERE, "..", "..", "experiment"),
    os.path.join(HERE, "..", "..", "experiments"),
    os.path.join(HERE, "..", "..", "..", "experiment"),
    os.path.join(HERE, "..", "..", "..", "experiments"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "ComparisonResults"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "experiment"),
    os.path.join(os.environ.get("ANTIDDOS_BASE", ""), "experiments"),
):
    _candidate = os.path.abspath(_candidate)
    if os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, _candidate)

from negatives.innovation_path import InnovationPath

def test_innovation_path_initialization():
    """Verify InnovationPath initializes with features and default lambda=0.01."""
    features = ["packets_per_sec", "bytes_per_sec", "syn_per_sec"]
    inno = InnovationPath(features, lam=0.01)
    assert inno.feats == features
    assert inno.lam == 0.01
    assert inno.Z == {}

def test_innovation_path_seed_and_surprise():
    """Verify steady traffic produces low surprise while sudden jumps produce high surprise."""
    features = ["packets_per_sec", "bytes_per_sec"]
    inno = InnovationPath(features, lam=0.01)

    # 1. Warmup with steady benign traffic (packets=1000, bytes=500000)
    warmup_rows = [
        {"packets_per_sec": 1000.0, "bytes_per_sec": 500000.0}
        for _ in range(50)
    ]
    calib_scores = inno.fit(warmup_rows)
    assert len(calib_scores) == 50
    # After initial convergence, steady traffic should have near-zero residual surprise
    assert calib_scores[-1] < 1.0

    # 2. Steady test row -> low surprise
    steady_row = {"packets_per_sec": 1005.0, "bytes_per_sec": 501000.0}
    steady_score = inno.score(steady_row)
    assert steady_score < 2.0

    # 3. Sudden massive attack jump (10x traffic shock) -> massive surprise
    jump_row = {"packets_per_sec": 50000.0, "bytes_per_sec": 40000000.0}
    jump_score = inno.score(jump_row)
    assert jump_score > 10.0
