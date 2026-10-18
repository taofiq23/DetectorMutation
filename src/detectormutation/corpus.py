"""Build the seed corpus of real SQL-injection values from CSIC 2010's own attack traffic.

Every mutation this project runs starts from a payload a real attacker actually sent, not from
a payload list sourced elsewhere. A value is kept if a SQL-keyword regex matches it; the regex is
deliberately loose (it is only a *seed filter*, not the thing being evaluated) so it pulls in the
dataset's real injection families: boolean tautologies, stacked DROP/INSERT, time-delay blind
SQLi (waitfor delay), and UNION-style probes.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qsl

from .csic import HttpRequest, load_csic

_SQLI_KEYWORDS = re.compile(
    r"(?i)(union\s+select|\bor\s+\d+\s*=\s*\d+|'\s*or\s|;\s*drop\b|;\s*select\b|"
    r"select\s.+\sfrom|insert\s+into|waitfor\s+delay|\bsleep\s*\(|\bhaving\b|"
    r"\band\s+\d+\s*=\s*\d+|--\s*$|\bexec\b)"
)


@dataclass
class SeedPayload:
    param: str
    value: str
    template: str  # digits and the literal prefix collapsed, for de-duplication


def _decoded_params(r: HttpRequest):
    q = r.query if r.method == "GET" else r.body
    return parse_qsl(q, keep_blank_values=True, encoding="latin-1")


def _template(value: str) -> str:
    collapsed = re.sub(r"\d+", "0", value)
    collapsed = re.sub(r"^[A-Za-z0-9_\-\. ]*(?=')", "X", collapsed)
    return collapsed


def extract_seed_payloads(data_dir: Path = None) -> List[SeedPayload]:
    """One SeedPayload per distinct (param, template) pair found in the real attack traffic,
    keeping the first real value seen for each so every mutation test starts from text a real
    attacker sent, not a synthetic rewrite."""
    requests = load_csic(data_dir) if data_dir else load_csic()
    attacks = [r for r in requests if r.label == 1]
    seen: Dict[tuple, SeedPayload] = {}
    for r in attacks:
        for k, v in _decoded_params(r):
            if not _SQLI_KEYWORDS.search(v):
                continue
            key = (k, _template(v))
            if key not in seen:
                seen[key] = SeedPayload(param=k, value=v, template=key[1])
    return list(seen.values())


def normal_values(data_dir: Path = None, limit: int = None) -> List[str]:
    """Parameter values from real *normal* traffic, used to measure false alarms."""
    requests = load_csic(data_dir) if data_dir else load_csic()
    normal = [r for r in requests if r.label == 0]
    values = [v for r in normal for _, v in _decoded_params(r) if v]
    return values[:limit] if limit else values
