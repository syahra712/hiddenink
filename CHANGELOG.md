# Changelog

Notable changes per release. Dates use ISO 8601.

## [0.2.1] — 2026-08-14

- Kept codepoints from newer Unicode script blocks inside mixed-script token
  analysis on Python 3.10 and 3.11, whose bundled Unicode databases predate
  those assignments.

## [0.2.0] — 2026-08-14

Release-hardening update. This version deliberately narrows earlier product
claims rather than treating marketing language as compatibility.

### Security

- In-place changes now use synced same-directory temporary files and atomic
  replacement where supported, with regular-file identity checks.
- Symbolic links and non-regular targets are refused. Recursive traversal is
  explicit, deterministic, de-duplicated, and skips named cache/build trees.
- Multi-file cleaning preflights predictable errors before mutation.
- Existing backups are refused unless `--overwrite-backup` is explicitly used.
- Human reports escape terminal and bidirectional controls from untrusted data.
- Container work now enforces cumulative byte/item/decompression limits and
  refuses malformed structures rather than partially rewriting them.
- Text, finding-output, recursive-file, stdin, and aggregate-operation limits
  bound hostile-input memory use and return explicit resource-limit outcomes.
- Unicode sequence handling now uses registered variation bases and derived
  joining-type constraints; cleaning remains a fixed point even when removing
  an invisible character exposes a CRLF pair.

### Reporting

- Reports expose parse status, coverage, warnings, and refusal reasons.
- Removal, folding, and normalisation counts are separate; the legacy
  `removed` key remains for actual deletions.
- Binary reports no longer receive an irrelevant statistical-text notice.
- Human output says “findings,” not “flagged codepoints,” because mixed-script
  findings may describe a span.
- Office coverage is documented as properties-only and PDF coverage as a
  shallow lexical metadata scan.
- C2PA-looking bytes, manifest-store structure, retained bytes, parsed claims,
  and cryptographic validity are no longer conflated.

### Packaging and documentation

- Removed unused `c2pa` and `research` extras. No code exercised the declared
  dependencies.
- Replaced unsupported Claude rollout/detector claims with the current official
  Anthropic Transparency Hub boundary.
- Replaced third-party AI Act summaries with the official EUR-Lex text and
  corrected the 2 August 2026 application wording.
- Removed universal remover, zero-corruption, market-leadership, and
  fingerprint-detection claims.
- Recast the self-authored corpus as a regression suite. External comparison
  results require repository, revision, command, date, and runtime metadata.
- CI builds, checks, and smoke-tests installed artifacts before release.

### Compatibility

- Directory traversal now requires `--recursive`.
- Existing backup replacement requires `--overwrite-backup`.
- JSON gains additive status and transformation fields.
- Version advanced to 0.2.0 because reporting and safety contracts changed.

## [0.1.2] — 2026-08-14

- Revised the README presentation.
- Added explicit UTF-8 handling to release-integrity tests.

## [0.1.1] — 2026-08-14

- Corrected stale README content in the distribution metadata.
- Added release-integrity checks for version, README, and wheel metadata.

## [0.1.0] — 2026-08-14

- Initial beta with text inspection/cleaning, limited container metadata
  inspection, PNG/JPEG cleaning, a CLI, and a project-authored corpus.

The 0.1.x documentation made claims about Claude watermark rollout, provenance
preservation, universal correctness, and comparative leadership that the
implementation and cited sources did not establish. Those claims are not part
of the 0.2.0 contract.
