# Contributing

Read [`CHARTER.md`](CHARTER.md) first. It is the design contract, and a change
that conflicts with it either loses or amends it — in the same pull request,
deliberately, never silently.

## The most useful contribution

**Challenge a conformance case.** [`corpus.py`](src/marklens/audit/corpus.py)
states an expected output and a Unicode-semantics rationale for every input, and
it is scored against tools including this one. I wrote both the corpus and one of
the tools in it, which is a real conflict of interest.

So: if a case looks wrong, say so. That is worth more than a feature.

A case is wrong if the expected output would corrupt legitimate content, or if
the rationale does not hold up against the Unicode standard. If tools could
reasonably disagree, it belongs in the `POLICY` tier, which is reported but never
scored — scoring taste would just encode one project's preferences as another's
bugs.

Adding a case means committing to a claim about correctness. Cite the reason.

## Setup

```bash
git clone https://github.com/syahra712/marklens && cd marklens
pip install -e ".[dev]"
pytest -q
```

The core has **no dependencies**, and that is load-bearing rather than
aesthetic: the product is trustworthy reports, so a user has to be able to read
the whole trust-relevant codebase in an afternoon and run it air-gapped. New
dependencies go in an extra (`[c2pa]`, `[research]`), never in `marklens.core`.
A test enforces this.

## Before opening a pull request

```bash
ruff check src tests
mypy
pytest -q
python -m marklens.audit          # conformance must stay at full marks
```

Then, from the charter's checklist:

- [ ] No banned claim phrases in user-facing strings (rule 1 — `test_contract.py`
      greps for them)
- [ ] New empirical claims in docs carry a citation, labelled verified / inferred
      / claimed
- [ ] New removal behaviour has an idempotence test and a protected-region test
- [ ] Regenerate `RESULTS.md` if you changed cleaning behaviour

## Testing standards

Two habits have caught almost every real bug in this project, and both are
expected of new work.

**Fuzz anything position-dependent.** The idempotence guarantee passed a
hand-written test suite for days while being broken in 0.5% of cases; a
9,000-case fuzz found it in seconds, and a later one caught that
`U+180B..U+180E` sit inside the Mongolian block so one variation selector
vouched for the next. Curated cases prove you thought of something. Fuzzing
finds what you did not.

**Prove a regression test fails without the fix.** A test that passes both ways
documents nothing. The cp1252 crash regressions were verified by reverting the
fix and watching them go red.

## Scope

Things deliberately not built, with reasons, are listed under
[Deliberately out of scope](CHARTER.md#deliberately-out-of-scope). The short
version: no statistical-watermark evasion, no keyless "is this AI?" verdict, no
provenance destruction. These are refusals rather than unclaimed tickets, so a
pull request adding one will be declined regardless of how well it is written.

If you want to do watermark-robustness research, [MarkLLM](https://github.com/THU-BPM/MarkLLM)
is Apache-2.0 and is the right home for it.

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md). Silent corruption counts as a security bug
here, not a correctness bug.
