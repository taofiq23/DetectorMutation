# DetectorMutation

Mutation testing for SQL-injection detectors: does a detector that catches an attack still catch
it after a small, meaning-preserving rewrite? A detector's catch rate on unmutated attacks says
nothing about this; mutation testing does, the same way it is used to grade a test suite instead
of trusting it.

Every mutation here starts from a real attack value in the [CSIC 2010](http://www.isi.csic.es/dataset/)
dataset (the same dataset used by [SentinelShield](https://github.com/taofiq23/SentinelShield)),
not from an external payload list. A mutation operator is a generic text transform — letter case,
whitespace style, or an equivalent numeric tautology — applied to that real value. Before a mutant
is used, a SQLite oracle executes both the original and the mutated payload against a throwaway
in-memory database and keeps the mutant only if it produces the same outcome (bypass / no-rows /
error) as the original. A mutation that silently breaks the exploit is not a valid test.

## The result

288 distinct real SQL-injection payloads (one per distinct parameter-name-and-template pair) were
extracted from CSIC's attack traffic. Five mutation operators were applied; 1,142 of the resulting
mutants passed the SQLite equivalence oracle. Three detectors were evaluated: `libinjection` (the
parser-based C library several real WAFs use), a keyword/pattern regex (the kind a lightweight WAF
ships with), and SentinelShield's character n-gram anomaly model, trained on CSIC normal traffic
and calibrated to a 1% false-alarm budget.

**Baseline detection, on the unmutated payloads:**

| Detector | Detects |
|---|---|
| libinjection | 54.5% (157/288) |
| keyword regex | 100% (288/288, by construction — the regex and the corpus seed filter share their keyword list) |
| char n-gram | 98.6% (284/288) |

**Evasion rate per mutation, counted only over mutants built from a payload the detector actually
caught beforehand** (a detector that never caught the original can't be said to be "evaded" by the
mutant — see Methodology):

| Mutation | libinjection | keyword regex | char n-gram |
|---|---|---|---|
| random letter case | 0% (0/274) | 0% (0/278) | 0% (0/274) |
| space → inline comment | 0% (0/157) | 14.9% (43/288, 95% CI 10.8–19.1%) | 0% (0/284) |
| split a keyword with `/**/` | **100% (157/157)** | 42.5% (116/273, 95% CI 36.6–48.4%) | 0% (0/269) |
| extra whitespace padding | 0% (0/157) | 0% (0/288) | 0% (0/284) |
| equivalent tautology (`1=1`→`7=7`) | n/a — 0 of these 15 originals were ever caught by libinjection | 0% (0/15) | 0% (0/15) |

Full results with confidence intervals: [`study_results/mutation_results.json`](study_results/mutation_results.json).

**What this shows:**

- **Splitting a keyword with an inline comment (`union` → `un/**/ion`) defeats libinjection
  completely on every payload it would otherwise have caught.** This was unexpected going in — a
  parser-based detector should, in principle, be the hardest to fool with surface rewrites. Spot
  checking the actual mutant/verdict pairs (`'; DR/**/OP TABLE usuarios; ...` → not flagged)
  confirms this is real, not a harness bug: libinjection's tokenizer treats `/**/` as a hard
  separator rather than reassembling the split keyword the way some SQL dialects' own lexers do.
- **The keyword regex is harder to evade than libinjection on this specific mutation, but not
  immune.** It survives letter-case changes (it is case-insensitive by design) and tolerates one
  broken keyword about half the time, because several of its alternative patterns overlap on the
  same payload (a payload ending in `--` is still caught by the `--\s*$` alternative even if its
  `union select` is split). 14.9–42.5% of attacks it originally caught still get through.
- **The character n-gram model was the most robust of the three** against every operator tested
  here, because it scores the whole string's character statistics rather than matching specific
  substrings — a few altered characters barely move the aggregate anomaly score. This is the same
  property SentinelShield's write-up attributes to it for a different reason (shape-preserving
  privacy transforms).

## Methodology, stated plainly

- **Mutations are built from real captured attacks, not a curated payload list.** 288 is the
  number of distinct (parameter name, payload shape) pairs CSIC's attack traffic actually
  contains; it is not a target chosen in advance.
- **A mutant is only used if the SQLite oracle confirms it is still a working exploit.** Not every
  mutation attempt passes: `equivalent_tautology` only fires on the 15 payloads containing a
  literal `N=N` tautology, and `case_random`/`split_keyword` occasionally produce a mutant the
  oracle rejects (278 and 273 out of 288 attempts respectively).
- **Evasion rate is conditioned on prior detection, per detector.** An earlier version of this
  experiment computed evasion as "not flagged after mutation" over *all* mutants regardless of
  whether the detector had ever flagged the original — which inflated libinjection's apparent
  evasion rate by counting payloads it never caught in the first place. The number now reported
  only counts mutants built from payloads that detector did catch.
- **The oracle uses one query shape** (`SELECT ... WHERE col = '{payload}'`), executed against
  SQLite. CSIC's attacks were largely written against a different backend (the `waitfor delay`
  syntax is Microsoft SQL Server's, not SQLite's), so most of those specific payloads are
  classified `error` under both the original and the mutated form — the oracle still correctly
  confirms the mutation didn't change the outcome class, but it does not confirm the payload would
  succeed against the SQL Server backend CSIC's attacker actually targeted.
- **Three detectors, one dataset, five operators.** This is a pilot, not a benchmark survey. The
  ordering (n-gram > regex > libinjection, for these specific operators) should not be read as a
  general ranking of detection strategies.

## Quickstart

```bash
git clone https://github.com/taofiq23/DetectorMutation
cd DetectorMutation
pip install -r requirements.txt
# copy the three CSIC 2010 traffic files into data/raw/csic2010/
# (normalTrafficTraining.txt, normalTrafficTest.txt, anomalousTrafficTest.txt)
PYTHONPATH=src python -m detectormutation.experiment
PYTHONPATH=src pytest -q
```

## What it does

- **Corpus** (`corpus.py`): extracts real SQLi-bearing parameter values from CSIC's attack
  traffic, de-duplicated by (parameter name, value template).
- **Mutations** (`mutate.py`): `case_random`, `comment_whitespace`, `split_keyword`,
  `equivalent_tautology`, `extra_whitespace`, each a generic text transform; a SQLite oracle
  (`classify`, `preserves_semantics`) that confirms a mutant is still a working exploit.
- **Detectors** (`detectors.py`): `libinjection`, a keyword regex, and a character n-gram model
  vendored from SentinelShield (`ngram.py`), each behind one `flags(text) -> bool` interface.
- **Experiment** (`experiment.py`): runs the full battery, computes per-operator, per-detector
  evasion rate with a bootstrap confidence interval, and writes `study_results/mutation_results.json`.

## Limitations

- Attack family is SQL injection only; the same method applies to XSS or command injection, but
  neither is implemented here.
- The keyword regex and char n-gram model are illustrative baselines, not production WAF rules —
  `libinjection` is the only detector here that real systems actually ship.
- No claim is made about evasion rates against a production WAF, which typically layers several
  of these signals together with others this project does not model.
