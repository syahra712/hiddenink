# hiddenink

### Find the ink you can't see.

**A context-aware, zero-dependency inspector for hidden Unicode and supported
file metadata, with conservative text cleaning. It shows what it found, what it
changed, what it refused, and what the bytes cannot prove.**

[![PyPI](https://img.shields.io/pypi/v/hiddenink)](https://pypi.org/project/hiddenink/)
[![Python](https://img.shields.io/pypi/pyversions/hiddenink)](https://pypi.org/project/hiddenink/)
[![CI](https://github.com/syahra712/hiddenink/actions/workflows/ci.yml/badge.svg)](https://github.com/syahra712/hiddenink/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/hiddenink)](LICENSE)

Apache-2.0 · Python 3.10+ · zero runtime dependencies · local and offline

<p align="center">
  <img src="https://raw.githubusercontent.com/syahra712/hiddenink/main/.github/demo.gif"
       alt="hiddenink inspecting an ordinary-looking invoice and reporting a Cyrillic homograph, a zero-width space, a bidirectional override, its inspection coverage, and an unevaluated statistical-watermark boundary."
       width="760">
</p>

<p align="center"><strong>Find what is there. Say what isn't knowable.</strong></p>

## The problem hides in plain sight

These strings can render almost identically while containing different bytes:

```text
paypal.com      ← Latin a
pаypal.com      ← Cyrillic а (U+0430)

hello           ← five visible letters
hel​lo           ← a zero-width space between l and l
```

That difference can break identifiers, disguise links, alter source code, leak
through copied text, or trigger a false accusation when an invisible character
was actually legitimate content.

The tempting solution is a blocklist: find every invisible codepoint and delete
it. That is also how text gets damaged. A zero-width joiner can be hidden noise
between Latin letters, part of an emoji such as `👨‍👩‍👧`, or required by an
orthographic sequence. The codepoint is the same; its job is not.

`hiddenink` evaluates each occurrence in context. Detection and rewriting are
separate decisions, so a suspicious character can be reported without being
silently destroyed.

## Why hiddenink is the safer choice

| Question | A simple blocklist | hiddenink |
|---|---|---|
| “This character is invisible—delete it?” | Decides by codepoint | Examines the surrounding sequence and selected profile |
| “No findings—am I clean?” | Often implies yes | States exactly what was parsed and what remained outside coverage |
| “Can this metadata be removed?” | Treats metadata as interchangeable | Does not assume removability: it validates structure and refuses unsupported mutation |
| “Are these C2PA bytes valid provenance?” | May conflate presence with validity | Separates structural recognition from cryptographic validation |
| “Can I safely rewrite many files?” | Writes as it goes | Preflights targets, refuses symlinks, and replaces each file atomically where supported |
| “Where does my content go?” | Depends on a hosted service | Nowhere: the dependency-free core runs locally and offline |

The advantage is not maximum deletion. It is **accountable behavior**:

- findings include category, codepoint or span, line, column, and context;
- reports include parse status, coverage, warnings, and refusal reasons;
- removals, compatibility folds, and normalisations are counted separately;
- cleaning is designed to be idempotent: `clean(clean(x)) == clean(x)`;
- ambiguous or provenance-sensitive files are refused instead of partially
  rewritten; and
- human output escapes terminal controls from hostile filenames and metadata.

## Quick start

Install from PyPI:

```bash
pip install hiddenink
```

Inspect a file without changing it:

```bash
hiddenink inspect notes.md
hiddenink inspect image.png --json
hiddenink inspect --recursive src/ --fail-on invisible
```

Cleaning one text file writes the result to standard output. The profile is
inferred from its extension (`prose` for `.md`, `.markdown`, `.txt`, and `.rst`;
`data` for `.csv`, `.tsv`, `.json`, and `.jsonl`; otherwise `code`) unless
`--profile` is supplied:

```bash
hiddenink clean notes.md > notes.cleaned.md
hiddenink clean --profile prose notes.md
hiddenink clean --check --recursive src/
hiddenink clean --dry-run image.png
hiddenink clean --in-place --backup notes.md
```

Use `inspect` first on valuable material. Use `--dry-run` before a binary or
in-place change. Standard-output cleaning accepts one file at a time; use
`--check` or `--in-place` for recursive and multi-file work. Binary cleaning
requires `--dry-run`, `--check`, or `--in-place`.

## What it can inspect

Every format reports its own coverage. “No findings” means no finding was
observed **inside that coverage**—not that every possible layer was examined.

| Input | What is reported | Cleaning boundary |
|---|---|---|
| UTF-8 text | Policy-defined Unicode findings and heuristic mixed-script runs | Profile-driven text transformation |
| PNG | Validated chunks; selected text, ICC/color profile, EXIF, time, and C2PA structures | Validates first; ambiguous or provenance-sensitive metadata is retained/refused |
| JPEG | Validated marker framing; selected EXIF, XMP, ICC, comment, and APP11/JUMBF structures | Validates first; ambiguous or provenance-sensitive metadata is retained/refused |
| SVG | Parsed `title`, `desc`, and `metadata`, plus a Unicode scan of decoded markup/text | Inspection only; generic text cleaning could alter rendering or URLs |
| DOCX/XLSX/PPTX/ODF | Package document properties | Inspection only |
| PDF | Bounded lexical Info fields and XMP packets | Inspection only |

Office body text, comments, revisions, spreadsheet cells, presentation slides,
embedded media, PDF compressed object streams, encryption, and incremental
update semantics are not covered by the current parsers. Those formats report
partial coverage rather than turning parser omission into a claim of absence.

## Unicode cleaning without the wreckage

The built-in profiles make policy explicit:

- **`prose`** removes policy-defined hidden controls and folds exotic spaces
  while preserving normal typography.
- **`code`** additionally folds selected typography. Mixed-script text is
  reported, not automatically rewritten, because strings and comments are not
  parsed with language-specific semantics.
- **`data`** applies the code policy, removes a leading BOM, and normalises CRLF
  to LF.

Registered variation sequences, emoji sequences, and supported orthographic
joiners are treated as content. URL and Markdown protection is deliberately
heuristic and documented as such. Compatibility normalisation and cross-script
folding remain explicit policy choices because they can lose information.

## File cleaning that knows when to stop

Binary cleaning is narrower than inspection. EXIF, XMP, ICC profiles,
orientation, accessibility, rights data, generic text chunks, and provenance
are not interchangeable “metadata.” A cleaner may refuse a malformed file, an
unsupported structure, or a rewrite whose integrity it cannot re-establish.
In `0.2.1`, the PNG/JPEG clean paths validate and then either make no change or
refuse; they do not strip ambiguous metadata.

<details>
<summary><strong>Operational safeguards for in-place and recursive work</strong></summary>

For in-place work, hiddenink:

1. preflights path, file-type, size, and backup-collision errors before mutation;
2. refuses symbolic links and non-regular files;
3. writes a same-directory temporary file and syncs it;
4. copies the original mode and timestamps;
5. atomically replaces the target where `os.replace` provides that guarantee;
   and
6. never overwrites an existing backup without `--overwrite-backup`.

Recursive traversal is explicit with `--recursive`, deterministic, de-duplicated,
and bounded. Named VCS, cache, virtual-environment, dependency, build, and
distribution directories are skipped. One operation accepts at most 10,000
files and 256 MiB in aggregate; text APIs accept at most 1,000,000 codepoints
and reports retain at most 10,000 findings.

</details>

## What hiddenink will not pretend to know

### Statistical text watermarks

hiddenink has no vendor detector and no model-specific statistical-watermark
scheme. Text reports therefore state that this layer was **not evaluated**. The
project does not claim an AI-authorship verdict or verified removal of a secret
model-level signal.

### C2PA and content provenance

The dependency-free core can recognise some container structures that may carry
JUMBF/C2PA bytes. It does not parse manifest claims or perform final
cryptographic credential and hard-binding validation. Detecting C2PA-looking
bytes or a structurally recognised store is not proof of valid provenance. If
hiddenink cannot preserve a recognised provenance structure, it refuses the
rewrite.

<details>
<summary><strong>The provenance distinctions retained in reports</strong></summary>

Reports distinguish C2PA-looking container bytes, a structurally recognised
manifest store, retained manifest bytes, parsed manifest claims, and
cryptographic validation. The first two do not establish the last three.

See the official
[C2PA Content Credentials specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html)
for the validation model.

</details>

## Evidence, not vibes

<details>
<summary><strong>Release and regression evidence</strong></summary>

The release pipeline tests Python 3.10–3.13 on Linux, macOS, and Windows, plus:

- Ruff and strict mypy;
- source and installed-wheel test suites;
- wheel/sdist metadata and README integrity;
- a zero-third-party-dependency core installation;
- resource-limit, malformed-input, symlink, terminal-injection, idempotence,
  and container-fidelity regressions; and
- a project-authored 40-case Unicode conformance corpus.

That corpus currently matches its expected outputs 40/40, but it is regression
evidence—not an independent benchmark or proof of universal correctness. The
same project authors the tool and expectations. [RESULTS.md](RESULTS.md) records
the run, limitations, command, revision, date, and runtime so the evidence can
be challenged and reproduced.

</details>

## Exit codes and automation

- `0`: completed and no requested threshold was exceeded.
- `1`: `--check` found a change or `--fail-on` found a matching severity.
- `2`: usage, I/O, unsupported-input, malformed-input, resource-limit, or
  refusal condition.

JSON output carries the same coverage and refusal model as the human report,
without terminal presentation escaping.

## Responsible use and contribution

If a document may be evidence in an authorship, academic-integrity, legal, or
security dispute, preserve the original before inspecting or cleaning it. Read
[docs/FALSE-FLAG.md](docs/FALSE-FLAG.md) before drawing conclusions from a
finding and [SECURITY.md](SECURITY.md) for hostile-file assumptions, limits, and
vulnerability reporting.

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[development charter](CHARTER.md). New public claims need evidence; new rewrite
rules need positive, negative, and idempotence tests.

## License

Apache-2.0. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Anthropic, C2PA, or the European Union.
