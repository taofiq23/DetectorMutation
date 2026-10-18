"""Mutation operators for SQL-injection payloads, plus a SQLite oracle that checks a mutation
kept the payload a *working* injection (not just different-looking text).

Each operator is a generic, reversible text transform — letter case, whitespace style, or an
equivalent boolean literal — not a new attack. The payload being transformed always comes from
`corpus.py`, i.e. from CSIC 2010's own recorded attack traffic.

The oracle executes the payload against a throwaway in-memory SQLite database with one seeded
row, classifies the outcome (bypass / no_rows / error), and keeps only mutants whose outcome
class matches the original payload's. This is the standard check used in adversarial-SQLi
research (e.g. WAF-A-MoLE): a mutation that silently breaks the exploit is not a valid test of
whether a detector can be evaded.
"""

import random
import re
import sqlite3
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

_KEYWORD = re.compile(
    r"(?i)\b(union|select|from|where|or|and|drop|table|insert|into|values|"
    r"waitfor|delay|sleep|having|exec|like|null)\b"
)


def case_random(payload: str, rng: random.Random) -> str:
    """Randomize the case of letters inside SQL keywords. SQL keywords are case-insensitive, so
    this never changes what the payload does; it only changes what a literal-keyword matcher sees."""

    def swap(match: re.Match) -> str:
        return "".join(rng.choice((c.upper(), c.lower())) for c in match.group(0))

    return _KEYWORD.sub(swap, payload)


def comment_whitespace(payload: str, rng: random.Random) -> str:
    """Replace each run of spaces with an inline SQL comment, which most dialects treat as
    whitespace. A classic tokenizer-confusing evasion: 'OR 1=1' becomes 'OR/**/1=1'."""
    return re.sub(r" +", "/**/", payload)


def split_keyword(payload: str, rng: random.Random) -> str:
    """Insert an inline comment inside one keyword, splitting it without changing how the SQL
    engine tokenizes it once the comment is stripped (e.g. 'union' -> 'un/**/ion')."""

    def split(match: re.Match) -> str:
        word = match.group(0)
        if len(word) < 4:
            return word
        cut = rng.randint(1, len(word) - 1)
        return word[:cut] + "/**/" + word[cut:]

    return _KEYWORD.sub(split, payload, count=1)


def equivalent_tautology(payload: str, rng: random.Random) -> str:
    """Rewrite a numeric tautology (N=N) to a different true numeric tautology. Only fires when
    the pattern is present; otherwise the payload is returned unchanged."""

    def repl(match: re.Match) -> str:
        n = rng.randint(2, 99)
        return f"{n}={n}"

    return re.sub(r"\b(\d+)\s*=\s*\1\b", repl, payload)


def extra_whitespace(payload: str, rng: random.Random) -> str:
    """Pad existing spaces with extra tabs/spaces, which SQL tokenizers collapse."""
    return re.sub(r" +", lambda m: m.group(0) + rng.choice(("\t", "  ", " \t ")), payload)


MUTATIONS: Dict[str, Callable[[str, random.Random], str]] = {
    "case_random": case_random,
    "comment_whitespace": comment_whitespace,
    "split_keyword": split_keyword,
    "equivalent_tautology": equivalent_tautology,
    "extra_whitespace": extra_whitespace,
}


@dataclass
class OracleResult:
    outcome: str  # "bypass" | "no_rows" | "error"


_TEMPLATES = [
    "SELECT * FROM users WHERE username = 'admin' AND password = '{p}'",
    "SELECT * FROM products WHERE id = '{p}'",
]


def _fresh_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'correct-horse-battery-staple')")
    conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO products VALUES (1, 'widget')")
    return conn


def classify(payload: str, template: str) -> OracleResult:
    """Run `payload` through a deliberately vulnerable string-concatenated query against a
    throwaway in-memory database, and classify what happened."""
    conn = _fresh_db()
    try:
        sql = template.format(p=payload)
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error:
            return OracleResult(outcome="error")
        return OracleResult(outcome="bypass" if rows else "no_rows")
    finally:
        conn.close()


def preserves_semantics(original: str, mutated: str, template: str = _TEMPLATES[0]) -> bool:
    """A mutation is valid only if it produces the same outcome class as the original payload
    under the same vulnerable query template."""
    return classify(original, template).outcome == classify(mutated, template).outcome


def mutate_corpus(seeds, operators: Optional[List[str]] = None, seed: int = 0, template: str = _TEMPLATES[0]):
    """For each seed payload and each requested operator, produce one mutant and keep it only if
    the oracle confirms it is still semantically the same kind of injection. Returns a list of
    (seed_param, seed_value, operator_name, mutant_value) tuples."""
    rng = random.Random(seed)
    ops = operators or list(MUTATIONS)
    out = []
    for s in seeds:
        for name in ops:
            mutant = MUTATIONS[name](s.value, rng)
            if mutant == s.value:
                continue  # operator did not apply (e.g. no tautology present)
            if preserves_semantics(s.value, mutant, template):
                out.append((s.param, s.value, name, mutant))
    return out
