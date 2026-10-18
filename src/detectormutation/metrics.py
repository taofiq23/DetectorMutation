"""Bootstrap confidence interval for an evasion rate (same percentile-bootstrap pattern used in
the SentinelShield project's metrics.py)."""

from typing import Tuple

import numpy as np


def rate_bootstrap_ci(flags: np.ndarray, n_resamples: int = 2000, seed: int = 0, confidence: float = 0.95):
    """`flags` is a boolean array, True = event of interest (e.g. "evaded"). Returns
    (point_estimate, lower, upper), or (None, None, None) if there is nothing to measure (e.g.
    the detector never caught any of the originals this operator's mutants came from)."""
    flags = np.asarray(flags, dtype=bool)
    rng = np.random.default_rng(seed)
    n = len(flags)
    if n == 0:
        return None, None, None
    values = np.empty(n_resamples)
    for i in range(n_resamples):
        sample = flags[rng.integers(0, n, n)]
        values[i] = sample.mean()
    lo, hi = np.percentile(values, [(1 - confidence) / 2 * 100, (1 + confidence) / 2 * 100])
    return float(flags.mean()), float(lo), float(hi)
