# hiddenink

Inspect hidden Unicode and supported file metadata without overstating what was
examined. Cleaning is conservative, local, and reported as separate removal,
folding, and normalisation counts.

[![PyPI](https://img.shields.io/pypi/v/hiddenink)](https://pypi.org/project/hiddenink/)
[![Python](https://img.shields.io/pypi/pyversions/hiddenink)](https://pypi.org/project/hiddenink/)
[![License](https://img.shields.io/pypi/l/hiddenink)](LICENSE)

Apache-2.0 · Python 3.10+ · dependency-free core · offline operation

## Install

```bash
pip install hiddenink
```

The default package has no runtime dependencies. The former `c2pa` and
`research` extras were removed because this release did not call their
dependencies; declaring unused functionality made the package boundary
misleading.

## Use

Inspect files:

```bash
hiddenink inspect notes.md
hiddenink inspect image.png --json
hiddenink inspect --recursive src/ --fail-on invisible
```

Clean text to standard output, preview changes, or replace a file:

```bash
hiddenink clean notes.md
hiddenink clean --check --recursive src/
hiddenink clean --dry-run image.png
hiddenink clean --in-place --backup notes.md
```

Directory traversal is opt-in with `--recursive`. Traversal is lexical and
deterministic; duplicate files are processed once. `.git`, `.hg`, `.svn`,
common cache/virtual-environment directories, `node_modules`, `build`, and
`dist` are ignored. Symbolic links and non-regular files are refused rather
than followed. Bytes that are neither a recognised container nor decodable by
the UTF-8 text reader are reported as an input error. One operation accepts at
most 10,000 files and 256 MiB in aggregate; text APIs accept at most 1,000,000
codepoints and reports retain at most 10,000 findings.

In-place cleaning reads and preflights every target before changing the first
one. Each changed file is written to a same-directory temporary file, synced,
given the original file's mode and timestamps, and atomically replaced where
the platform supports `os.replace`. A pre-existing `.bak` is never overwritten
unless `--overwrite-backup` is also supplied. Cross-file atomicity is not
possible: a later, unexpected filesystem failure can still leave an earlier
replacement complete, but never partially written.

Exit codes:

- `0`: operation completed and no requested threshold was exceeded.
- `1`: `--check` found a change or `--fail-on` found a matching severity.
- `2`: usage, I/O, unsupported-input, malformed-input, or refusal condition.

## What inspection means

Every report includes a parse status, a coverage statement, warnings, and
refusal reasons. “No findings” means only that no finding was observed inside
that stated coverage.

| Input | Coverage |
|---|---|
| UTF-8 text | Flagged Unicode codepoints plus heuristic mixed-script detection |
| PNG/JPEG | Validated container structure and supported metadata chunks/segments |
| SVG | Parsed XML metadata plus a Unicode scan of decoded markup/text |
| DOCX/XLSX/PPTX/ODF | Document properties only |
| PDF | Shallow lexical metadata scan |

Office body text, Word comments/revisions, spreadsheet cells, presentation
slides, and embedded media are not inspected. PDF compressed object streams,
incremental-update semantics, encryption, and unsupported encodings are not a
full-parser claim. These formats therefore report partial coverage rather than
equating parser omission with absence.

The human report escapes C0/C1, ANSI/OSC, and bidirectional terminal controls
from filenames and metadata. JSON remains machine-readable and preserves the
original values through JSON escaping.

## Cleaning policy

`hiddenink` distinguishes detection from rewriting. The profiles are:

- `prose`: remove policy-defined hidden controls and fold exotic spaces while
  preserving normal typography.
- `code`: additionally fold selected typography. Mixed-script/confusable text
  is reported; it is not automatically rewritten merely because it appears in
  a source file, since strings and comments are not parsed by language syntax.
- `data`: apply the code policy, drop a leading BOM, and normalise CRLF to LF.

Context-dependent Unicode is preserved only when a supported sequence rule
applies. Registered variation sequences, emoji sequences, and orthographic
joiners are content, not generic “invisible junk.” URL and Markdown handling is
heuristic; it is not a claim of complete URI or CommonMark parsing. Review a
`--dry-run` report before applying policy-driven changes to valuable text.

Binary cleaning is narrower than metadata inspection. A cleaner may refuse a
malformed file, a structure it cannot validate, or a file whose provenance
could be invalidated. It does not treat EXIF, XMP, ICC profiles, rights data,
or arbitrary text chunks as interchangeable. Preserve the original and use an
independent decoder when fidelity matters.

## C2PA boundary

The core can identify some container structures that may carry JUMBF/C2PA
bytes. That is not the same as parsing a manifest or validating a credential.
Reports distinguish:

- C2PA-looking container bytes;
- a structurally recognised manifest store;
- retained manifest bytes;
- parsed manifest claims; and
- cryptographic validation of the credential and hard binding.

The dependency-free core does not parse manifest claims or perform the final
cryptographic credential/hard-binding validation. It never calls
retained bytes “valid provenance.” C2PA defines hard bindings as cryptographic
bindings between a manifest and an asset, and defines soft bindings separately;
see the official [C2PA Content Credentials specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html).
Because rewriting unrelated asset bytes can invalidate a hard binding, the safe
outcome may be refusal.

## Statistical watermark boundary

`hiddenink` has no vendor detector and no model-specific statistical watermark
scheme. Text reports therefore say that this layer was not evaluated; binary
metadata reports do not repeat an irrelevant text-watermark notice.

This project does not assert that Claude inserts zero-width characters, that
EXIF/XMP proves Claude authorship, or that C2PA proves AI generation. Anthropic's
current official [Transparency Hub](https://www.anthropic.com/transparency/voluntary-commitments)
describes watermarking as an area it continues to explore; that source does not
support the rollout story previously published here.

## Law and policy

Article 50(2) of the EU AI Act places machine-readable marking obligations on
providers of covered AI systems, subject to feasibility and stated exceptions.
Article 50(4) separately addresses disclosure by deployers for deepfakes and
certain public-interest text. The Regulation applies from 2 August 2026, with
the staged exceptions in Article 113. Read the official
[EUR-Lex text of Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj?locale=en).
Nothing in this README is legal advice, and the project does not infer a user's
obligations from a file alone.

## Conformance corpus

`python -m hiddenink.audit` runs a project-authored Unicode regression corpus.
It is useful for repeatable development tests, not proof of universal
correctness or market leadership. Policy cases are unscored. A comparison is
publishable only with the competitor repository, exact revision, command and
flags, run date, runtime environment, and independently reviewable cases.

See [RESULTS.md](RESULTS.md) for the current self-run and its limitations. The
author writes both hiddenink and the corpus; that conflict of interest is not
eliminated by a passing score.

## Security and responsible use

Read [SECURITY.md](SECURITY.md) for resource limits, hostile-file assumptions,
and vulnerability reporting. If a document has been used in an authorship or
academic-integrity dispute, preserve the original before inspecting it and see
[docs/FALSE-FLAG.md](docs/FALSE-FLAG.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Anthropic, C2PA, or the European Union.
