# If your writing has been flagged

Practical evidence-preservation guidance for an authorship or academic-integrity
dispute. This is not legal advice, and `hiddenink` cannot determine who wrote a
document or whether an AI system was used.

## Preserve the original

Do not clean, re-save, or convert the disputed file. Keep the exact bytes and
work from a copy. A hash can help identify that preserved copy:

```bash
shasum -a 256 essay.docx
```

Keep the hash with a date and a note describing where the original is stored.
A hash does not prove authorship; it only helps show that the file later
examined is the same file.

Useful contemporaneous evidence may include:

- document version history and autosaved drafts;
- Git history or dated backups;
- outlines, notes, and source annotations;
- research/library access records; and
- the institution's policy and the exact notice or score you received.

Preserve exports and screenshots without deleting the original service-side
history.

## Ask for the actual claim

“AI detected,” “watermark detected,” and “suspicious metadata found” describe
different mechanisms. Ask the reviewer for:

- the product and version used;
- the exact passage or file examined;
- whether the result came from a classifier, a vendor-specific keyed detector,
  metadata/provenance validation, or a human review;
- the threshold and documented error rate for that use; and
- the policy provision under which the result is being considered.

Do not substitute statistics from an unrelated detector. Research about
post-hoc AI-text classifiers does not by itself establish the behaviour of a
secret-key watermark detector, and vice versa.

## What hiddenink can contribute

Run inspection on a copy:

```bash
hiddenink inspect essay.txt --json
hiddenink inspect essay.docx --json
```

For UTF-8 text, hiddenink inventories supported Unicode findings. For DOCX,
XLSX, PPTX, and ODF files, it currently inspects document properties only. It
does **not** inspect Word body text, comments, tracked revisions, spreadsheet
cells, presentation slides, or embedded images. Export body text separately if
you want a Unicode scan, and keep the original container unchanged.

PDF inspection is a shallow metadata scan, not a full PDF parse. A partial,
unsupported, malformed, or refused report must not be described as “clean.”

The package has no Claude-specific or other vendor-specific statistical
watermark detector. Its text report explicitly marks that question as not
evaluated.

## Product and provenance claims

Do not infer that an invisible character, EXIF field, XMP packet, or generic
C2PA structure proves AI authorship. C2PA validation can establish signed
provenance assertions and their binding to an asset; the meaning of a validated
assertion still depends on its contents. The dependency-free hiddenink core
does not cryptographically validate C2PA credentials.

Anthropic's current official
[Transparency Hub](https://www.anthropic.com/transparency/voluntary-commitments)
describes watermarking as an area under continued exploration. It does not
support the previous version of this guide's claims about a Claude watermark
rollout, detector API, proofreading behaviour, or token thresholds, so those
claims have been removed.

## EU AI Act context

The official [EUR-Lex text of Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj?locale=en)
sets different Article 50 obligations for providers and deployers and includes
exceptions and feasibility language. It entered into force in 2024 and applies
generally from 2 August 2026 under Article 113's staged timetable.

Whether a particular person, institution, publication, or workflow has a legal
or contractual duty depends on facts outside a file inspection. Consult the
institution's written policy or qualified counsel rather than relying on this
project for a legal conclusion.
