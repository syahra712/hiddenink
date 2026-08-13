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

A curly quote inside a Markdown code fence is a bug even in a prose document. A dash inside a URL is load-bearing even in a source file. No other tool in this space makes either distinction.

**Emoji survive.** `❤️` and `1️⃣` are base + U+FE0F. Tools that blanket-strip `U+FE00..U+FE0F` corrupt them. `marklens` recognises emoji presentation sequences and keycaps and leaves them alone.

**No `exiftool` dependency.** PNG chunks, JPEG APPn segments, OOXML/ODF zip parts, SVG nodes, and PDF Info dictionaries are parsed with the standard library. A tool that reports "no metadata found" because an optional binary is missing is worse than one that can't read the format at all.

**Honest about C2PA soft binding.** When no manifest is found in a C2PA-capable file, `marklens` says so *and* warns that soft bindings ride in the pixels and survive metadata stripping. Stripping metadata does not make an image untraceable, and implying otherwise is the false confidence this whole product category sells.

## Non-goals

These are refusals, not roadmap items.

- **No statistical-watermark evasion.** No bundled "paraphrase until it stops registering" mode. It can't be verified, it's the one use [Anthropic's policy](https://www.anthropic.com/legal/aup) actually names ("presenting results as human-generated"), and the same machinery enables *spoofing* — [94.17% of adversarially edited texts stay above detection threshold](https://openreview.net/forum?id=rIOl7KbSkv), which lets someone inject fabricated claims into text that still reads as "Claude wrote this."
- **No "is this AI?" verdict.** Keyless detection of a single document is [computationally intractable if the scheme meets cryptographic undetectability](https://arxiv.org/abs/2306.09194), and uncalibrated accusations are a documented harm, not a feature.
- **No C2PA stripping.** `marklens` reads and verifies provenance. It does not destroy it.

## If you've been falsely accused

Anthropic's own documentation concedes that using Claude to **proofread or translate your own writing** leaves the mark on work you genuinely wrote. If that's happened to you, read **[docs/FALSE-FLAG.md](docs/FALSE-FLAG.md)** before you touch a removal tool.

The short version: **erasing the mark makes your position worse, not better.** It destroys the only evidence anyone could examine, and removal leaves its own detectable signature. What actually wins an academic-integrity hearing is draft history, the sub-50-token no-signal floor, Anthropic's own "not fully conclusive" language, and the [61.3% false-positive rate AI detectors show against non-native English writers](https://arxiv.org/abs/2304.02819).

## Prior art, credited

- [`guillaumemeyer/watermarks-remover`](https://github.com/guillaumemeyer/watermarks-remover) (MIT) — the incumbent, and unusually honest in its README about what its statistical layer can't do.
- [MarkLLM](https://github.com/THU-BPM/MarkLLM) (Apache-2.0) — the serious watermarking research toolkit. If you want real attack/robustness evaluation, use it, not a remover.
- [`sanitext`](https://github.com/panispani/sanitext) (MIT), [`confusable-homoglyphs`](https://github.com/vhf/confusable_homoglyphs) (MIT) — Unicode hygiene prior art.
- [c2pa-python](https://github.com/contentauth/c2pa-python) (Apache-2.0/MIT) — the real C2PA implementation, used by the optional `[c2pa]` extra.

## License

Apache-2.0. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Anthropic.
