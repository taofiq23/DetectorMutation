"""Character n-gram anomaly detector, vendored from the SentinelShield project (same author)
so this project has no path dependency on a sibling repo. Unchanged from the original.
"""

import math
from typing import Dict, Iterable, List, Sequence

import numpy as np

START, END = "\x02", "\x03"


class CharNgramLM:
    def __init__(self, order: int = 5):
        if order < 2:
            raise ValueError("order must be at least 2")
        self.order = order
        self._counts: List[Dict[str, Dict[str, int]]] = [dict() for _ in range(order)]
        self._totals: List[Dict[str, int]] = [dict() for _ in range(order)]
        self._vocab: set = set()
        self._fitted = False

    def fit(self, texts: Iterable[str]) -> "CharNgramLM":
        n = self.order
        counts = self._counts
        for text in texts:
            padded = START * (n - 1) + text + END
            self._vocab.update(text)
            for i in range(n - 1, len(padded)):
                c = padded[i]
                for k in range(n):
                    context = padded[i - k : i]
                    bucket = counts[k].get(context)
                    if bucket is None:
                        bucket = counts[k][context] = {}
                    bucket[c] = bucket.get(c, 0) + 1
        for k in range(n):
            self._totals[k] = {context: sum(bucket.values()) for context, bucket in counts[k].items()}
        self._vocab.add(END)
        self._fitted = True
        return self

    def _probability(self, history: str, char: str) -> float:
        p = 1.0 / (len(self._vocab) + 1)
        for k in range(self.order):
            context = history[len(history) - k :] if k else ""
            bucket = self._counts[k].get(context)
            if bucket is None:
                break
            distinct = len(bucket)
            p = (bucket.get(char, 0) + distinct * p) / (self._totals[k][context] + distinct)
        return p

    def score(self, text: str) -> float:
        if not self._fitted:
            raise RuntimeError("model is not fitted")
        n = self.order
        padded = START * (n - 1) + text + END
        total = 0.0
        for i in range(n - 1, len(padded)):
            total -= math.log2(self._probability(padded[max(0, i - (n - 1)) : i], padded[i]))
        return total / (len(padded) - (n - 1))

    def score_many(self, texts: Sequence[str]) -> np.ndarray:
        return np.array([self.score(t) for t in texts])
