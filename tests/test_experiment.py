from detectormutation.corpus import extract_seed_payloads, normal_values
from detectormutation.detectors import all_detectors
from detectormutation.experiment import run


def test_corpus_has_real_seed_payloads_and_normal_values():
    seeds = extract_seed_payloads()
    normal = normal_values(limit=500)
    assert len(seeds) > 50
    assert all(s.value for s in seeds)
    assert len(normal) == 500


def test_detectors_catch_an_unmutated_tautology():
    normal = normal_values(limit=2000)
    detectors = all_detectors(normal)
    assert all(d.flags("' OR '1'='1") for d in detectors)


def test_full_run_produces_consistent_counts():
    result = run(n_normal_for_training=2000)
    assert result["n_seed_payloads"] > 50
    total_mutants = sum(result["mutants_generated_per_operator"].values())
    for detector_name, per_op in result["evasion_rate_by_detector_and_operator"].items():
        for op, cell in per_op.items():
            assert cell["n_mutants_from_detected_originals"] <= cell["n_mutants_total"]
            if cell["n_mutants_from_detected_originals"] == 0:
                assert cell["evasion_rate"] is None
            else:
                assert 0.0 <= cell["evasion_rate"] <= 1.0
    assert total_mutants > 0
