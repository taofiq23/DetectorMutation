"""Three detectors under test, each exposing the same `flags(text) -> bool` interface.

- LibinjectionDetector: libinjection, the parser-based C library used in several real WAFs
  (wraps the `libinjection` PyPI binding).
- KeywordRegexDetector: the kind of hand-written keyword/pattern rule a lightweight WAF ships
  with; uses the same keyword family as the corpus seed filter, so its "before mutation"
  detection rate is close to 100% by construction — the question this project asks is how much
  of that survives real-looking evasion, not whether the rule works on unmutated attacks.
- NgramDetector: SentinelShield's character n-gram anomaly model, trained on CSIC normal traffic
  only and calibrated to a fixed false-alarm budget, exactly as in that project.
"""

import re
from typing import List

import libinjection
import numpy as np

from .ngram import CharNgramLM

_KEYWORD_RULE = re.compile(
    r"(?i)(union\s+select|\bor\s+\d+\s*=\s*\d+|'\s*or\s|;\s*drop\b|;\s*select\b|"
    r"select\s.+\sfrom|insert\s+into|waitfor\s+delay|\bsleep\s*\(|\bhaving\b|"
    r"\band\s+\d+\s*=\s*\d+|--\s*$|\bexec\b)"
)


class LibinjectionDetector:
    name = "libinjection"

    def flags(self, text: str) -> bool:
        return bool(libinjection.is_sql_injection(text)["is_sqli"])


class KeywordRegexDetector:
    name = "keyword_regex"

    def flags(self, text: str) -> bool:
        return bool(_KEYWORD_RULE.search(text))


class NgramDetector:
    name = "char_ngram"

    def __init__(self, order: int = 5, target_fpr: float = 0.01, seed: int = 0):
        self.order = order
        self.target_fpr = target_fpr
        self._model: CharNgramLM = None
        self._threshold: float = None
        self._rng = np.random.default_rng(seed)

    def fit(self, normal_texts: List[str]) -> "NgramDetector":
        split = int(len(normal_texts) * 0.8)
        idx = self._rng.permutation(len(normal_texts))
        train = [normal_texts[i] for i in idx[:split]]
        calib = [normal_texts[i] for i in idx[split:]]
        self._model = CharNgramLM(order=self.order).fit(train)
        calib_scores = self._model.score_many(calib)
        self._threshold = float(np.percentile(calib_scores, (1 - self.target_fpr) * 100))
        return self

    def flags(self, text: str) -> bool:
        if self._model is None:
            raise RuntimeError("NgramDetector.fit() must be called before flags()")
        return bool(self._model.score(text) > self._threshold)


def all_detectors(normal_texts: List[str]):
    """The three detectors, fitted where fitting is needed."""
    return [
        LibinjectionDetector(),
        KeywordRegexDetector(),
        NgramDetector().fit(normal_texts),
    ]
