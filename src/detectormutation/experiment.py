"""Run the mutation battery: build the seed corpus from CSIC's real attacks, generate mutants
per operator (keeping only mutants the SQLite oracle confirms are still working injections),
run three detectors against both the originals and the mutants, and report each detector's
evasion rate per operator with a bootstrap confidence interval.

    python -m detectormutation.experiment
"""

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import numpy as np

from .corpus import extract_seed_payloads, normal_values
from .detectors import all_detectors
from .metrics import rate_bootstrap_ci
from .mutate import MUTATIONS, mutate_corpus

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "study_results"


def run(n_normal_for_training: int = 20_000) -> dict:
    t0 = time.time()
    seeds = extract_seed_payloads()
    normal = normal_values(limit=n_normal_for_training)
    detectors = all_detectors(normal)

    baseline: Dict[str, float] = {}
    for d in detectors:
        caught = sum(d.flags(s.value) for s in seeds)
        baseline[d.name] = caught / len(seeds)

    mutants = mutate_corpus(seeds, operators=list(MUTATIONS), seed=0)

    by_operator: Dict[str, List[tuple]] = defaultdict(list)
    for param, orig, op, mutant in mutants:
        by_operator[op].append((orig, mutant))

    # Evasion only makes sense relative to payloads the detector actually caught before
    # mutation: if a detector never flagged the original, "still not flagged after mutation"
    # is not evasion, it is just a miss that mutation had nothing to do with. Each detector's
    # evasion rate is therefore computed only over the subset of mutants built from payloads
    # that detector originally caught.
    evasion: Dict[str, Dict[str, dict]] = {}
    for d in detectors:
        evasion[d.name] = {}
        for op, pairs in by_operator.items():
            detectable = [(orig, mutant) for orig, mutant in pairs if d.flags(orig)]
            evaded = np.array([not d.flags(mutant) for _, mutant in detectable])
            point, lo, hi = rate_bootstrap_ci(evaded)
            evasion[d.name][op] = {
                "n_mutants_from_detected_originals": len(detectable),
                "n_mutants_total": len(pairs),
                "evasion_rate": point,
                "ci_lo": lo,
                "ci_hi": hi,
            }

    result = {
        "n_seed_payloads": len(seeds),
        "n_normal_requests_used": len(normal),
        "baseline_detection_rate": baseline,
        "mutants_generated_per_operator": {op: len(pairs) for op, pairs in by_operator.items()},
        "evasion_rate_by_detector_and_operator": evasion,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "mutation_results.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    out = run()
    print(json.dumps(out, indent=2))
