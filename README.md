# marklens

**Inspect and clean AI provenance marks in text and files — and say precisely what was and wasn't done.**

Apache-2.0 · Python ≥3.10 · **zero dependencies** in the core · works offline

---

## The short version

On 2026-08-11 Anthropic began marking Claude output for EU AI Act compliance. Within a day, a dozen "Claude watermark removers" appeared. Nearly all of them do the same two things: strip invisible Unicode, then ask another LLM to paraphrase your text.

The first half is real and useful. The second half **cannot be verified by anyone** — Anthropic has published no detector, so no tool on earth can demonstrate that a statistical watermark was removed. The honest vendors admit this outright. One of them, [gpt-watermark-remover.com](https://gpt-watermark-remover.com/remove-claude-watermarks), puts it plainly:

> "There is no character to strip, which means no character-removal tool can remove it. **Ours included.**"

Others charge **$5.99–$39.99/month** for that same unverifiable claim, and store your drafts on their servers.

`marklens` does the part that is real, does it better than anything else available, and refuses to bill you — in money or in false confidence — for the part that isn't.

## The two layers

Claude marks output in two structurally different ways:

| | What it is | Can it be removed? | Can removal be **verified**? |
|---|---|---|---|
| **Character & metadata** | Invisible codepoints; C2PA/EXIF/XMP in files | **Yes** | **Yes** — the bytes are there or they aren't |
| **Statistical** | Token-logit biasing under a secret key, applied below the model | Unknown | **No** — no public detector exists |

`marklens` owns the first row completely. For the second row it emits a `not_determinable` section and moves on.

Every single report carries both:

```
── essay.md
VERIFIABLE  (decidable from the bytes)
  16 flagged codepoints: 5 invisible, 2 whitespace, 9 typographic
    · smart_quote          6
    · zero_width           1
    · bidi_control         1
    · tag_character        1
NOT DETERMINABLE  (no tool can decide these)
  · Model-level statistical text watermark: NOT EVALUATED. Anthropic has
    published no detector or scheme specification, so its presence, absence,
    and removal are all undecidable by any third-party tool at this time.
```

## Install

```bash
pip install marklens
```

The core has **no dependencies at all** — not a design accident, a requirement. A tool whose entire value is that its reports mean what they say has to be auditable end to end and installable in an air-gapped environment.

## Use

```bash
marklens inspect essay.md              # what am I actually carrying?
marklens inspect diagram.png           # C2PA / EXIF / XMP in a container
marklens clean notes.md                # write cleaned text to stdout
marklens clean -i src/*.py             # rewrite in place
marklens clean -i screenshot.png       # strip EXIF/text chunks, keep provenance
marklens clean --check src/            # exit 1 if anything needs cleaning (CI)
marklens inspect . --json | jq         # machine-readable, for CI
```

Gate a repo in pre-commit or CI:

```bash
marklens inspect src/ --fail-on invisible
```

## What makes it different

**Three severities, not one bucket.** Invisible characters are never legitimate. Exotic spaces usually aren't. Em dashes and curly quotes usually *are*. Tools that lump these together are why the press called the category ["a text formatter wearing a trench coat"](https://currently.att.yahoo.com/att/claude-watermark-removal-tools-promise-143507892.html) — they mangle your typography and call it watermark removal.

**Region-aware cleaning.** The same character gets different treatment depending on where it sits:

| Input | `--profile prose` | `--profile code` |
|---|---|---|
| `clear—truly` (prose) | `—` kept | `-` folded |
| `` `x = "y"` `` (code span) | `"` **folded** | `"` folded |
| `example.com/a—b` (URL) | `—` **kept** | `—` **kept** |

A curly quote inside a Markdown code fence is a bug even in a prose document. A dash inside a URL is load-bearing even in a source file. Both distinctions are in the audit's policy tier, so you can see for yourself which tools make them — as of the last run, no other one does.

**Load-bearing invisibles are decided per occurrence.** This is the one that matters most, and it is measured below rather than asserted.

The same codepoint can be contraband or essential depending only on what surrounds it:

| | U+200D between… | verdict |
|---|---|---|
| `he‍llo` | two Latin letters | **hidden mark** — Latin has no joining behaviour |
| `👨‍👩‍👧` | two emoji | **content** — it is what makes the family one glyph |
| `ا‍ب` | two Arabic letters | **orthography** — it forces cursive joining |

U+200C is the same story: in `क्‌ष` and `می‌رود` it is *spelling*. A cleaner that strips by codepoint identity silently corrupts every Urdu, Hindi, Persian, and Arabic document it touches. One that preserves by codepoint identity leaves every hidden joiner in place.

`marklens` decides from context, so both are handled correctly in the same document — including emoji ZWJ sequences, subdivision flags (`🏴󠁧󠁢󠁳󠁣󠁴󠁿`, whose tag characters spell the region code), keycaps, Hangul fillers, Khmer inherent vowels, and Mongolian variation selectors.

**No `exiftool` dependency.** PNG chunks, JPEG APPn segments, OOXML/ODF zip parts, SVG nodes, and PDF Info dictionaries are parsed with the standard library. A tool that reports "no metadata found" because an optional binary is missing is worse than one that can't read the format at all.

**Honest about C2PA soft binding.** When no manifest is found in a C2PA-capable file, `marklens` says so *and* warns that soft bindings ride in the pixels and survive metadata stripping. Stripping metadata does not make an image untraceable, and implying otherwise is the false confidence this whole product category sells.

## Non-goals

These are refusals, not roadmap items.

- **No statistical-watermark evasion.** No bundled "paraphrase until it stops registering" mode. It can't be verified, it's the one use [Anthropic's policy](https://www.anthropic.com/legal/aup) actually names ("presenting results as human-generated"), and the same machinery enables *spoofing* — [94.17% of adversarially edited texts stay above detection threshold](https://openreview.net/forum?id=rIOl7KbSkv), which lets someone inject fabricated claims into text that still reads as "Claude wrote this."
- **No "is this AI?" verdict.** Keyless detection of a single document is [computationally intractable if the scheme meets cryptographic undetectability](https://arxiv.org/abs/2306.09194), and uncalibrated accusations are a documented harm, not a feature.
- **No provenance destruction.** `clean` rewrites container metadata under one rule: **remove metadata that identifies you, keep metadata that discloses AI involvement.** A PNG loses its text chunks and EXIF (GPS, camera serial, usernames, paths); it keeps its C2PA manifest. If you need the manifest gone, this is the wrong tool — and removing it would not make the file unmarked anyway, since C2PA soft bindings ride in the pixels.

## If you've been falsely accused

Anthropic's own documentation concedes that using Claude to **proofread or translate your own writing** leaves the mark on work you genuinely wrote. If that's happened to you, read **[docs/FALSE-FLAG.md](docs/FALSE-FLAG.md)** before you touch a removal tool.

The short version: **erasing the mark makes your position worse, not better.** It destroys the only evidence anyone could examine, and removal leaves its own detectable signature. What actually wins an academic-integrity hearing is draft history, the sub-50-token no-signal floor, Anthropic's own "not fully conclusive" language, and the [61.3% false-positive rate AI detectors show against non-native English writers](https://arxiv.org/abs/2304.02819).

## Measured, not asserted

This project's own charter forbids claiming superiority without evidence, so the comparison is a runnable conformance suite rather than a paragraph. [`src/marklens/audit/corpus.py`](src/marklens/audit/corpus.py) states an expected output **and a reason** for every input; any tool that reads stdin and writes stdout can be scored:

```bash
python -m marklens.audit "other-tool=path/to/their-cleaner"
```

Current results ([full table with per-case rationale](RESULTS.md)):

| tool | correctness | content corrupted | contraband left in place |
|---|---|---|---|
| **marklens** | **40/40** | **0** | **0** |
| watermarks-remover | 35/40 | 3 | 2 |
| watermarks-remover `--strip-emoji-glue` | 28/40 | 11 | 1 |
| watermarks-remover `--aggressive-homoglyphs` | 33/40 | 3 | 2 |

Those are all the same tool, and together they are the argument for deciding **per occurrence** rather than per flag. Its protections are global switches, so each one trades one failure for another:

- default — leaves hidden marks in place
- `--strip-emoji-glue` — destroys emoji sequences and Indic orthography
- `--aggressive-homoglyphs` — corrupts legitimate non-Latin text: `привет мир` comes out as **`пpивeт миp`**, which is not only no longer Russian but *more* confusable than the input, since it now genuinely mixes scripts

No combination of those flags gets one document right. Its five default-mode failures: a surviving private-use codepoint, an unterminated tag sequence kept as if it were a flag, and three destroyed load-bearing characters (Mongolian variation selector, Khmer inherent vowel, Hangul filler).

**Read this critically.** I wrote both the corpus and one of the tools in it, which is a real conflict of interest. Two mitigations: every case carries a Unicode-semantics rationale you can check independently, and the suite is scored in CI against a deliberately destructive tool and a deliberately inert one, so it cannot silently degrade into a pass-everything harness. The **policy** tier exists for the same reason — differences that are legitimately matters of taste (whether an em dash in prose becomes a hyphen) are reported but never scored. If a case looks wrong, open an issue; the corpus is the contribution, not the scoreboard.

## Prior art, credited

- [`guillaumemeyer/watermarks-remover`](https://github.com/guillaumemeyer/watermarks-remover) (MIT) — the incumbent, and unusually honest in its README about what its statistical layer can't do. Differential testing against it found three genuine corruption bugs in `marklens`, including the Indic/Arabic one above; the comparison above is only meaningful because their tool is good enough to learn from.
- [MarkLLM](https://github.com/THU-BPM/MarkLLM) (Apache-2.0) — the serious watermarking research toolkit. If you want real attack/robustness evaluation, use it, not a remover.
- [`sanitext`](https://github.com/panispani/sanitext) (MIT), [`confusable-homoglyphs`](https://github.com/vhf/confusable_homoglyphs) (MIT) — Unicode hygiene prior art.
- [c2pa-python](https://github.com/contentauth/c2pa-python) (Apache-2.0/MIT) — the real C2PA implementation, used by the optional `[c2pa]` extra.

## License

Apache-2.0. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Anthropic.
