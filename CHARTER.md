# Development charter

This is the design contract for `hiddenink`. A change that conflicts with it
must amend the charter explicitly, with tests and rationale.

## Brief

> Inspect hidden Unicode and supported file metadata, apply only documented
> conservative transformations, and report exactly what was examined, changed,
> refused, or left undetermined.

The project is a general text-hygiene and metadata-inspection tool. It is not a
Claude watermark remover, an AI detector, or proof of content authorship.

## Non-negotiable rules

### 1. Never claim an unevaluated result

Text reports always state that model-level statistical watermarking was not
evaluated. The project has no vendor detector or model-specific scheme. No
user-facing string may imply an AI-authorship verdict or successful evasion.

### 2. Coverage and uncertainty stay structural

Reports keep findings separate from `not_determinable`. Container reports also
carry `parse_status`, `coverage`, `warnings`, and `refusal_reasons`. Empty parser
output is not evidence of absence. `complete`, `partial`, `unsupported`,
`malformed`, `refused`, and `resource_limit` are distinct outcomes.

### 3. No evasion feature

Do not add paraphrase-to-defeat-detection loops, detector gaming, or authorship
spoofing. This project inspects bytes and applies explicit hygiene policies.

### 4. The core stays dependency-free

`hiddenink.core` imports only the Python standard library, enforced by tests.
An optional extra may be introduced only with an implemented, documented, and
tested feature. Dead extras are removed.

### 5. Detection and rewriting are separate decisions

A suspicious character can be reported without being safe to rewrite. Unicode
format characters and variation selectors are context-dependent; private-use
characters and compatibility normalisation are policy questions. New rewrite
rules need normative rationale, positive and negative cases, and idempotence
coverage.

Normative sources include the [Unicode Standard](https://www.unicode.org/versions/latest/),
[UAX #15](https://www.unicode.org/reports/tr15/),
[UTS #39](https://www.unicode.org/reports/tr39/), and
[UTS #51](https://www.unicode.org/reports/tr51/).

### 6. Provenance bytes are not validated provenance

Detecting a `caBX`, APP11/JUMBF, filename, XMP reference, or `c2pa` substring
does not establish a parsed manifest, a valid signature, a valid hard binding,
or AI generation. The official
[C2PA specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html)
defines those validation concepts. If a rewrite could invalidate provenance and
the project cannot validate the result, refuse the rewrite.

### 7. Preserve content and rendering by default

Default cleaning must not knowingly change image pixels, orientation, colour,
accessibility, rights/licensing data, or provenance. ICC profiles, Adobe colour
transforms, EXIF orientation, IPTC rights data, XMP, and generic text chunks are
not interchangeable “privacy metadata.” A path that cannot be selective and
validated should be inspection-only.

### 8. Hostile input is normal input

Apply cumulative size/member/chunk/decompression limits. XML entity declarations
are refused before parsing. Malformed containers are never partially rewritten.
Expected parser, ZIP, encoding, and resource-limit failures become structured
reports. Human terminal output escapes untrusted controls.

### 9. In-place writes are transactional per file

Preflight all predictable multi-file errors before mutation. Refuse symlinks and
non-regular targets. Write a synced same-directory temporary file, preserve
appropriate metadata, and atomically replace the target where supported. Never
overwrite a backup without an explicit option. Cross-file atomicity is not
promised.

### 10. Cite public factual claims

Use primary sources for standards, product behaviour, law, and rollout claims.
Label inference as inference. A project-authored corpus is regression evidence,
not independent proof of market leadership. Comparisons require reproducible
tool revisions, commands, dates, and environments.

## Reporting principles

- Findings identify actionable characters or spans, with line and column.
- “No findings” is always scoped to declared parser coverage.
- Removal, folding, and normalisation counts are separate.
- JSON preserves machine-readable values; human output neutralises terminal
  controls.
- Cleaning is idempotent: `clean(clean(x)) == clean(x)`.
- Safe refusal is preferable to silent corruption.

## Contribution checklist

- [ ] Full `pytest` suite passes.
- [ ] Ruff and strict mypy pass.
- [ ] The built wheel and sdist pass `twine check`.
- [ ] Tests exercise the installed wheel, not only the source tree.
- [ ] Core still imports no third-party package.
- [ ] New parser limitations appear in coverage/status output.
- [ ] New transformations have normative rationale and regressions.
- [ ] New public empirical claims have primary citations.
- [ ] `git diff --check` passes.

## Deliberately out of scope

| Not building | Reason |
|---|---|
| Statistical watermark detector/remover | No integrated vendor scheme or detector |
| “Is this AI?” verdict | A file inspection cannot establish authorship |
| Provenance destruction | Conflicts with preservation and validation rules |
| Hosted upload service | Local/offline operation is part of the trust boundary |
| Full Office/PDF parser | Current implementation declares narrower coverage |
