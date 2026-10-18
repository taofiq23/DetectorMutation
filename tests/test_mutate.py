import random

from detectormutation.mutate import (
    MUTATIONS,
    case_random,
    classify,
    comment_whitespace,
    preserves_semantics,
    split_keyword,
)


def test_case_random_only_changes_case():
    rng = random.Random(1)
    original = "' OR 1=1--"
    mutated = case_random(original, rng)
    assert mutated.lower() == original.lower()


def test_comment_whitespace_removes_literal_spaces_between_keywords():
    rng = random.Random(1)
    mutated = comment_whitespace("' OR 1=1--", rng)
    assert " " not in mutated.split("'", 1)[1].split("1=1")[0] or "/**/" in mutated


def test_classify_distinguishes_bypass_from_benign():
    benign = classify("nothing-malicious", "SELECT * FROM users WHERE username = 'admin' AND password = '{p}'")
    bypass = classify("' OR '1'='1", "SELECT * FROM users WHERE username = 'admin' AND password = '{p}'")
    assert benign.outcome == "no_rows"
    assert bypass.outcome == "bypass"


def test_oracle_confirms_classic_tautology_bypass_survives_case_mutation():
    rng = random.Random(1)
    original = "' OR '1'='1"
    mutated = case_random(original, rng)
    assert preserves_semantics(original, mutated)


def test_split_keyword_breaks_a_literal_substring_match():
    rng = random.Random(2)
    original = "' union select null--"
    mutated = split_keyword(original, rng)
    assert mutated != original
    assert "/**/" in mutated


def test_all_registered_mutations_are_callable():
    rng = random.Random(0)
    for name, fn in MUTATIONS.items():
        out = fn("' OR 1=1--", rng)
        assert isinstance(out, str), name
