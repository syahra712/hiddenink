# If your writing has been flagged

*Practical guidance for students, writers, and anyone accused of submitting AI-generated work.*

This document is not legal advice. It is a summary of what the published research and the vendors' own documentation actually say, with citations you can hand to a committee.

---

## Read this first: do not "clean" the document

The instinct is to run a watermark remover and resubmit. **This makes your position worse in three separate ways.**

1. **It destroys your evidence.** If you genuinely wrote the work, the document is the artifact that supports you. Modifying it after an accusation looks like — and is functionally indistinguishable from — tampering.
2. **Removal has its own signature.** Independent review of the current tools notes that a forensic classifier recognises the removal's fingerprint with near-perfect accuracy. You trade an explicit mark for an implicit one, and the implicit one is harder to explain.
3. **It probably didn't work anyway.** No public detector exists, so no tool can demonstrate the statistical mark was removed. You would be taking a real risk in exchange for an unverifiable benefit.

Use `hiddenink inspect` to *understand* what's in your document. Do not clean it until the matter is resolved.

---

## The single most important fact

**Anthropic's own documentation says a detected mark does not mean AI wrote the text.**

From [How Claude marks AI-generated content](https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content):

> Because people also use Claude to proofread, translate, summarize, or otherwise edit their own writing, text that originated somewhere else could still carry a Claude watermark.

And:

> A detected mark … is not fully conclusive.

If you wrote your essay and used Claude to fix your grammar, **the mark is supposed to be there.** The detector is working correctly. The inference "mark present, therefore AI wrote it" is the error — and it is the accuser's error, not yours.

This is worth stating precisely, because it is not a false positive in the statistical sense. It is a **true positive attached to a false conclusion**. No amount of detector tuning fixes it, which means the burden is on whoever is drawing the inference.

---

## The arguments, with citations

### 1. Short passages carry no reliable signal

Statistical watermarks need length. The published floors:

| Source | Finding |
|---|---|
| [Kirchenbauer et al., ICML 2023](https://arxiv.org/abs/2301.10226) | ~25 tokens minimum under *ideal, unedited* conditions |
| [MarkMyWords](https://arxiv.org/abs/2312.00273) | <100 tokens in practice for KGW-family schemes |
| [SynthID theoretical analysis](https://arxiv.org/html/2603.03410v2) | 50-token passages: max TPR ≈ **0.3** at 1% FPR |
| [Kirchenbauer et al., ICLR 2024](https://arxiv.org/abs/2306.04634) | after *human* paraphrasing: **~800 tokens** needed at a 10⁻⁵ false-positive threshold |

**If the flagged passage is short, the result is not evidence.** Ask what length threshold the tool used and what its false-positive rate is at that length. A tool that reports a verdict on two sentences is reporting noise.

### 2. Detectors are biased against non-native English writers

[Liang et al., *Patterns* 2023](https://arxiv.org/abs/2304.02819) found AI detectors falsely flagged **61.3%** of TOEFL essays by non-native English speakers, versus near-0% for native speakers. The mechanism is low lexical diversity producing low perplexity.

That study covers post-hoc classifiers rather than keyed watermarks. But the mechanism carries over more than you'd hope: [Three Bricks (Fernandez et al.)](https://arxiv.org/abs/2308.00113) shows that watermark z-tests assume scored tokens are independent, and **repeated n-grams break that assumption and inflate the statistic**. Repetitive, formulaic, or limited-vocabulary prose — exactly what a second-language writer or a technical-template document produces — is systematically over-flagged relative to the theoretical false-positive rate.

If your institution uses a detector, it is fair to ask whether its false-positive rate was measured on writers with your language background.

### 3. Empirical false-positive rates exceed the advertised ones

Also from [Three Bricks](https://arxiv.org/abs/2308.00113): the standard z-test's theoretical tails **do not hold** on natural text. A tool reporting "p < 0.0001" is quoting a number derived under an independence assumption that real prose violates. Ask whether the detector applies n-gram deduplication or rank-based scoring corrections. Most don't.

### 4. Nobody outside Anthropic can currently verify anything

As of 2026-08-13, Anthropic has published neither the watermarking scheme nor a detector; the detection API is announced but not shipped. Any third-party tool claiming to detect *Claude's* watermark specifically is not doing what it says.

If you were flagged by a third-party "AI detector," that is a **post-hoc statistical classifier** — the technology the 61.3% study covers — not Claude's watermark. These are completely different mechanisms, and conflating them is common.

### 5. The mark does not indicate proportion

A detected mark cannot tell you whether Claude wrote 100% of the text or fixed five commas. [No Free Lunch (NeurIPS 2024)](https://openreview.net/forum?id=rIOl7KbSkv) demonstrates the converse too: an attacker can edit watermarked text substantially — injecting content the model never produced — with **94.17%** of results still registering as watermarked. Presence of a mark is not evidence of authorship *by* the model, and it is certainly not evidence of the extent.

---

## What actually helps

**Draft history is the strongest evidence available to you**, and it is the one thing a watermark cannot manufacture:

- Google Docs / Word version history (`File → Version history`) showing incremental composition
- Git history, if you wrote in a repo
- Handwritten notes, outlines, whiteboard photos, dated file backups
- Library or database access logs matching your citations
- Search history from your research period

Then:

- **Preserve the original document unmodified.** Take a hash of it (`shasum -a 256 essay.docx`) and record it somewhere dated.
- **Run `hiddenink inspect essay.docx`** to see what's verifiably present. Bring the report.
- **Ask what tool was used, at what threshold, with what published false-positive rate, on a passage of what length.** Ask whether that rate was validated on writers with your language background. These questions are frequently unanswerable, and that is itself informative.
- **State plainly what you actually used Claude for**, if anything. "I wrote this and used Claude to check grammar" is a complete, honest, and — per Anthropic's own documentation — fully consistent explanation of a detected mark.

---

## What the law actually requires (EU)

Worth knowing if someone claims you broke a regulation by editing your own document:

The EU AI Act's [Article 50](https://artificialintelligenceact.eu/article/50/) marking duty binds **providers** (50(2)) and **deployers** (50(4)). [Article 99](https://artificialintelligenceact.eu/article/99/) penalties apply to them. **Article 50 imposes no obligation on end users**, and neither it nor [Recital 133](https://artificialintelligenceact.eu/recital/133/) prohibits removing a mark from your own document.

Separate obligations may still apply to you — your institution's academic-integrity policy, contractual terms, and disclosure duties if you publish AI-generated material on a matter of public interest. Those are the real constraints. The AI Act is not one of them for an individual student.

---

## Contributing

If you have been through an integrity process involving a watermark or AI-detection claim, an anonymised account of what arguments worked would materially improve this document. Open an issue.
