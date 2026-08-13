# Development charter

The design contract for `marklens`. Read this before writing code or accepting a contribution. If a change conflicts with a rule here, the rule wins or the rule gets amended in the same pull request — not silently overridden.

---

## The one-sentence brief

> Build the best available tool for removing what is **provably** removable from AI-marked text and files, report exactly what was done, and never claim — in code, output, docs, or marketing — to have done something that cannot be verified.

Everything below follows from that sentence.

---

## The problem this project exists to solve

Anthropic began marking Claude output on 2026-08-11 (EU AI Act Transparency Code, in force 2026-08-02). The marks come in two layers:

- **Character & metadata layer** — invisible codepoints in text; C2PA/EXIF/XMP in files. Removal is deterministic and byte-verifiable.
- **Statistical layer** — token-logit biasing under a secret key, applied in the sampling pipeline *below* the model. Anthropic has published no scheme and no detector.

A dozen removal tools shipped within 48 hours. All of them handle layer one (about 50 lines of `unicodedata`) and then hand layer two to another LLM to paraphrase. **Layer two removal cannot be verified by anyone**, which means every claim about it — positive or negative — is currently unfalsifiable.

The gap in the market is not a better paraphraser. It is a tool whose output you can trust.

---

## Non-negotiable rules

### 1. Never claim the undecidable

Every report carries a `not_determinable` section. It is not decoration and it is not removable by a flag. If a code path could cause a user to believe the statistical watermark was evaluated or removed, that path is a bug.

Banned from all user-facing strings: "watermark removed", "now undetectable", "AI-proof", "bypasses detection", "100% clean".

### 2. Verifiable and unverifiable claims never share a section

The `verifiable` / `not_determinable` split is the product. Keep it machine-readable so downstream tools can rely on it, and keep it structural so it cannot be argued away.

### 3. No evasion features

No bundled paraphrase-to-defeat-detection mode. No "rewrite until it stops registering" loop. No integration that ships one by proxy.

This is not squeamishness. Three concrete reasons:

- It cannot be verified, so it is a promise we cannot keep.
- It is the one use [Anthropic's AUP](https://www.anthropic.com/legal/aup) names explicitly ("presenting results as human-generated").
- The same machinery enables **spoofing**: [94.17% of adversarially edited texts still register as watermarked](https://openreview.net/forum?id=rIOl7KbSkv), so an attacker can inject fabricated claims into text that still reads as "Claude wrote this." Shipping a good implementation of this hurts people who never used the tool.

If a contributor wants to do watermark-robustness research, point them at [MarkLLM](https://github.com/THU-BPM/MarkLLM) — it is Apache-2.0, it is the serious toolkit, and it is the right home for that work.

### 4. The core stays dependency-free

`marklens.core` imports nothing outside the standard library, enforced by a test. Optional extras (`[c2pa]`, `[research]`) may add dependencies; the core may not.

Rationale: the product is trustworthy reports. A user must be able to read the entire trust-relevant codebase in an afternoon and run it air-gapped. Every dependency is a thing they'd have to audit too.

### 5. Removal semantics are content-aware, always

Never blanket-strip a Unicode range. The taxonomy exists because these genuinely differ:

- **Invisible** — never legitimate. Remove everywhere, under every profile.
- **Whitespace** — invisible bugs. Fold to U+0020 everywhere.
- **Typographic** — legitimate writing. Fold only where it's a defect (source code), never in prose or URLs.

Known correctness traps, all currently handled — do not regress them:

| Trap | Correct behaviour |
|---|---|
| `U+FE0F` after an emoji base | **Preserve** — it's an emoji presentation sequence |
| Keycap `1` + `U+FE0F` + `U+20E3` | **Preserve** |
| Dash or quote inside a URL | **Never fold** — it breaks the link |
| Curly quote inside a code fence | **Fold**, even under `--profile prose` |
| `U+FEFF` mid-document | Remove (it's ZWNBSP, not a BOM) |
| Truncated / malformed container | Report what was parsed; never raise |

### 6. Absence of a finding is not absence of a mark

When no C2PA manifest is found in a C2PA-capable container, say so **and** note that soft bindings live in the pixels and survive metadata stripping. Users reach for these tools *specifically* to feel untraceable. Do not sell them that feeling.

### 7. Cite, don't assert

Every empirical claim in docs carries a link. Distinguish rigorously between:

- **Verified** — Anthropic's own documentation, or a paper's stated result
- **Inferred** — e.g. "Claude's scheme is probably KGW-family." Third parties inferred this from the literature. Anthropic has **not** confirmed it. Label it as inference wherever it appears.
- **Claimed** — vendor marketing. Never repeat as fact.

---

## Design principles

**Reports are the product; cleaning is a feature.** When the two conflict, protect the report.

**`line:column`, not just counts.** A finding a user can't locate in their editor is trivia.

**Idempotence is a tested property.** `clean(clean(x)) == clean(x)` for every profile. Folding `U+2026` → `...` changes length, so this is a real property, not an obvious one.

**Fail loud on ambiguity, quiet on absence.** A malformed PNG reports what was parsed. An unknown format says "unrecognised", never "clean".

**Optimise for the falsely accused, not the evader.** The evader is served by a dozen tools and escapes with one paraphrase pass regardless. The person wrongly flagged for using Claude to proofread their own essay has nobody. Design for them — see [docs/FALSE-FLAG.md](docs/FALSE-FLAG.md).

---

## Contribution checklist

- [ ] `python -m pytest` passes
- [ ] `python -m ruff check src tests` clean
- [ ] Core still imports nothing third-party (`test_no_third_party_imports`)
- [ ] New user-facing strings contain no banned claims (rule 1)
- [ ] New empirical claims in docs carry citations, labelled verified/inferred/claimed
- [ ] New removal behaviour has an idempotence test and a protected-region test
- [ ] Any new dependency lands in an extra, never the core

---

## Deliberately out of scope

| Not building | Why |
|---|---|
| Statistical watermark detector | Keyless single-document detection is [intractable under cryptographic undetectability](https://arxiv.org/abs/2306.09194) |
| Statistical watermark remover | Unverifiable; see rule 3 |
| "Is this AI?" classifier | Uncalibrated accusations are the documented harm |
| C2PA stripping | We read provenance, we don't destroy it |
| C2PA soft-binding removal | Pixel-domain; out of scope and out of principle |
| Hosted web service | Every hosted competitor uploads user drafts. Local-only is a feature |

---

## Glossary

**C2PA** — Coalition for Content Provenance and Authenticity. Signed metadata standard; Anthropic uses it for `.png`/`.jpg`/`.svg`.

**Soft binding** — a provenance mark carried in the content itself (pixels), able to re-link a remote manifest after metadata is stripped.

**KGW** — Kirchenbauer/Geiping/Wen green-list watermarking ([ICML 2023](https://arxiv.org/abs/2301.10226)). A secret-keyed function partitions the vocabulary; "green" tokens get a logit bias; detection is a z-test on green-token frequency. *Widely inferred* to be the family Claude's scheme belongs to. **Not confirmed by Anthropic.**

**Spoofing** — making text falsely register as watermarked, e.g. to attribute fabricated statements to a model.

**TPR@FPR=1%** — true-positive rate at a 1% false-positive rate. The community's standard reporting metric; prefer it to bare accuracy or AUROC.
