# Changelog

Notable changes per release. Dates are ISO-8601.

## [Unreleased]

### Added

- **Load-bearing invisible detection**, decided per occurrence rather than per
  codepoint. A U+200D between Latin letters is a hidden mark; the same
  codepoint between two emoji fuses a family into one glyph, and between two
  Devanagari letters it is spelling. Covers emoji ZWJ sequences, subdivision
  flag tag sequences, keycaps, Arabic/Indic/Persian orthography, Hangul
  fillers, Khmer inherent vowels, and Mongolian free variation selectors.
- **Confusable and mixed-script detection.** NFKC folding handles compatibility
  variants (fullwidth, mathematical, circled) with no table; word-level
  script-mixing analysis catches homographs no lookalike table lists. Folding
  of cross-script letters is scoped to mixed-script runs, so legitimate
  Cyrillic, Greek, and CJK text is never rewritten.
- **Container metadata cleaning** for PNG and JPEG, under an explicit rule:
  remove metadata that identifies the user, keep metadata that discloses AI
  involvement. EXIF, text chunks, XMP, and comments go; C2PA manifests stay.
- **Conformance corpus and audit harness** (`python -m hiddenink.audit`). States
  an expected output and a rationale per input, in scored `CORRECTNESS` and
  unscored `POLICY` tiers. Any tool reading stdin and writing stdout can be
  measured. Results in [`RESULTS.md`](RESULTS.md).
- `clean --check`, for gating CI on whether anything would change.
- Codepoint coverage for `U+034F`, `U+115F`, `U+1160`, `U+17B4`, `U+17B5`, and
  `U+180B`–`U+180E`, which are `Mn`/`Lo` rather than `Cf` and so were invisible
  to the format-character fallback.
- `SECURITY.md`, `CONTRIBUTING.md`, `py.typed`.

### Fixed

- **Idempotence**, which was documented and untrue: a fuzz found 45 violations
  in 9,000 cases. Two independent causes — regions computed before invisible
  removal, and folding emitting characters the region patterns key on. Cleaning
  is now two-phase and folds to a fixed point.
- **Text corruption of Indic, Arabic, and Persian documents**, and of emoji ZWJ
  sequences and subdivision flags, all from stripping by codepoint identity.
- **CLI crash on any non-UTF-8 console.** `inspect` died with a cp1252
  `UnicodeEncodeError` on the default Windows console.
- **Line-ending fidelity.** `clean` translated `\n` to `\r\n` on Windows when
  writing to stdout, and a CRLF input came out as `\r\r\n`.
- **Surrogate round-trip.** Reads used `surrogatepass` and writes used strict,
  so `--in-place` crashed on files it could successfully inspect.
- **`clean --json` discarded the cleaned text**, writing only a report.
- **Multi-file `clean` concatenated to stdout** unrecoverably; now refused.
- SVG was scanned for metadata but not for codepoints, despite being text.
- Truncated containers lost their trailing partial data during cleaning.

### Security

- XML entity expansion (billion laughs) and XXE: entity declarations in the
  prolog are refused.
- Decompression bombs in PNG `zTXt`/`iTXt` and in zip-based documents: output
  is capped at 8 MB and oversized zip members are skipped on their declared
  size without being read.

### Performance

- 4.8 MB clean: 38.37s → 0.217s, peak memory 85 MB → 10 MB.
- 20,000 inline code spans: 15.35s → 0.066s (region resolution was quadratic).
