from detectormutation.detectors import KeywordRegexDetector, LibinjectionDetector, NgramDetector


def test_libinjection_flags_classic_tautology():
    assert LibinjectionDetector().flags("' OR '1'='1")


def test_libinjection_does_not_flag_plain_text():
    assert not LibinjectionDetector().flags("blue widget size 10")


def test_keyword_regex_flags_waitfor_delay():
    assert KeywordRegexDetector().flags("183','0','0');waitfor delay '0:0:15';--")


def test_keyword_regex_misses_a_tautology_with_no_other_signal():
    # The rule's '\bor\s+\d+=\d+' alternative needs a literal space after "or"; replacing the
    # space with an inline comment, with no other matching alternative (no trailing "--", no
    # "union", no "waitfor"), is exactly the evasion split_keyword-style mutations exploit.
    assert not KeywordRegexDetector().flags("admin' OR/**/1=1")


def test_ngram_detector_requires_fit_before_flags():
    d = NgramDetector()
    try:
        d.flags("anything")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass


def test_ngram_detector_flags_rare_text_after_fitting_on_uniform_normal_text():
    d = NgramDetector(order=3, target_fpr=0.05).fit(["item123", "item124", "item125"] * 50)
    assert d.flags("' UNION SELECT password FROM users--")
