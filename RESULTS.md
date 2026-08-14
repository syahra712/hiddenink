# Project-authored conformance run

Generated with `python -m hiddenink.audit` on 2026-08-14. This is a regression
run against expectations authored in this repository, not an independent
benchmark and not evidence of universal correctness or market leadership.

## Summary

| tool | expected-output matches | load-bearing mismatches | contraband mismatches |
|---|---|---|---|
| hiddenink | 40/40 | 0 | 0 |

A mismatch means only that output differed from this corpus's stated
expectation. The author controls both hiddenink and the expected outputs. A
passing self-run does not establish that every classification is normatively
correct or that unseen inputs will be preserved.

## Run metadata

| tool | repository | revision | command | date | runtime |
|---|---|---|---|---|---|
| hiddenink | https://github.com/syahra712/hiddenink | release 0.2.0 (working tree) | in-process hiddenink_adapter(profile=prose) | 2026-08-14 | CPython 3.12.10; macOS-13.7.8-x86_64-i386-64bit |

No external competitor result is published in this release. Earlier tables
compared multiple flag combinations of one repository and described that as a
market comparison. They did not record the exact commit, run date, or runtime,
and they did not include a second independent competitor, so they have been
removed rather than presented as reproducible evidence.

## Interpretation limits

- The corpus is useful for regressions the project already knows about.
- Policy cases are displayed but not scored.
- A project-authored expectation can itself be wrong. Normative Unicode data
  and independent review take precedence over the score.
- “Load-bearing” and “contraband” are corpus groups, not universal properties
  of a codepoint. Context can change the result.
- This run covers text transformation only. It does not benchmark file parser
  security, image fidelity, C2PA validation, or statistical watermarking.

To reproduce the detailed case table locally:

```bash
python -m hiddenink.audit
```

Before publishing an external comparison, record for every tool:

- repository URL;
- exact release or commit SHA;
- command and flags;
- run date;
- Python/runtime and operating system; and
- any adapter code used.

The audit renderer includes these metadata fields and labels missing metadata
as unsuitable for a published comparison.
