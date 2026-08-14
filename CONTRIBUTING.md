# Contributing

Read [`CHARTER.md`](CHARTER.md) first. It is the design contract, and a change
that conflicts with it either loses or amends it — in the same pull request,
deliberately, never silently.

## The most useful contribution

**Challenge a conformance case.** [`corpus.py`](src/hiddenink/audit/corpus.py)
states an expected output and a Unicode-semantics rationale for every input. It
is a project-authored regression suite, not an independent benchmark. The author
writes both the corpus and hiddenink, which is a real conflict of interest.

So: if a case looks wrong, say so. That is worth more than a feature.

A case is wrong if the expected output would corrupt legitimate content, or if
the rationale does not hold up against the Unicode standard. If tools could
reasonably disagree, it belongs in the `POLICY` tier, which is reported but never
scored — scoring taste would just encode one project's preferences as another's
bugs.

Adding a case means committing to a claim about correctness. Cite the reason.

## Setup

```bash
git clone https://github.com/syahra712/hiddenink && cd hiddenink
pip install -e ".[dev]"
pytest -q
```

The core has **no dependencies**, and that is load-bearing rather than
aesthetic: the product is trustworthy reports, so the trust-relevant code must
remain reviewable and usable air-gapped. An
optional dependency may go in an extra only when implemented, documented, and
tested functionality calls it. Dependencies never go in `hiddenink.core`; a
test enforces this.

## Before opening a pull request

```bash
ruff check src tests
mypy
pytest -q
python -m hiddenink.audit          # review project-authored expectations
python -m build
python -m twine check dist/*
```

Then, from the charter's checklist:

- [ ] No banned claim phrases in user-facing strings (rule 1 — `test_contract.py`
      greps for them)
- [ ] New empirical claims use primary sources and label inference explicitly
- [ ] Parser changes update status, coverage, warning, and refusal reporting
- [ ] External comparisons record repository URL, exact revision, command and
      flags, run date, and runtime environment
- [ ] New removal behaviour has an idempotence test and a protected-region test
- [ ] Regenerate `RESULTS.md` if you changed cleaning behaviour

## Testing standards

Two testing habits are expected of new work.

**Fuzz anything position-dependent.** Curated cases document known boundaries;
deterministic fuzz/property tests exercise interactions between positions,
regions, and repeated cleaning that examples can miss.

**Prove a regression test fails without the fix.** A test that passes both ways
does not demonstrate the defect it is intended to prevent.

## Scope

Things deliberately not built, with reasons, are listed under
[Deliberately out of scope](CHARTER.md#deliberately-out-of-scope). The short
version: no statistical-watermark evasion, no "is this AI?" verdict, no
provenance destruction. These are refusals rather than unclaimed tickets, so a
pull request adding one will be declined regardless of how well it is written.

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md). Silent corruption counts as a security bug
here, not a correctness bug.
