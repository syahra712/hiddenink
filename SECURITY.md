# Security policy

`hiddenink` parses files it did not create. Treat every input, filename, and
metadata value as attacker-controlled.

## Reporting

Open a [private security advisory](https://github.com/syahra712/hiddenink/security/advisories/new).
Do not publish an unfixed vulnerability first. The project aims to acknowledge
reports within seven days and credit reporters unless they request otherwise.

## Threat model

In scope:

- resource exhaustion through size, count, compression, nesting, or algorithmic
  complexity;
- path traversal, symlink following, backup clobbering, or writes outside the
  selected target;
- parser-triggered code execution, entity expansion, or external resolution;
- unexpected network access;
- terminal injection through filenames or metadata; and
- silent corruption or a report that states more certainty than the parser has.

## Current controls

- A CLI operation is capped at 10,000 files and 256 MiB of aggregate input.
- Recognised container files are capped at 256 MiB. Text APIs are capped at
  1,000,000 codepoints; the CLI applies a 4 MiB encoded-text preflight ceiling
  before decoding, and stdin is read through the same bounded path.
- A text report retains at most 10,000 findings. Crossing the text or finding
  ceiling produces a structured `resource_limit` result rather than a partial
  success claim.
- Container chunk/member counts are capped at 10,000.
- A decompressed member is capped at 8 MiB; aggregate metadata and aggregate
  decompressed metadata are each capped at 16 MiB.
- XML input is capped at 2 MiB with depth/element limits. Expat performs the
  grammar-aware gate and refuses entity declarations; ElementTree builds a tree
  only after that gate succeeds. The external-entity handler refuses resolution;
  no resolver or network access is provided.
- Malformed/resource-limited containers are reported distinctly and are not
  partially rewritten.
- Expected ZIP, compression, XML, and encoding failures become structured
  warnings/refusals rather than tracebacks.
- Human output escapes C0/C1, ANSI/OSC, and bidirectional terminal controls.
  JSON uses JSON escaping and retains machine-readable values.
- Recursive traversal is opt-in, sorted, de-duplicated, and does not follow
  symlinks. Common repository cache/build directories are ignored.
- In-place changes use a synced same-directory temporary file and `os.replace`;
  regular-file identity is rechecked before replacement. Existing backups are
  refused unless explicit overwrite authority is supplied.

Limits are safety ceilings, not a proof that every accepted input is cheap.
Reports that demonstrate excessive CPU or memory below these limits remain in
scope.

## Provenance and fidelity

C2PA-looking bytes are not a validated credential. A hard binding may be
invalidated by changing bytes outside its exclusion ranges, so a cleaning path
must either validate the post-write result or refuse the mutation. The project
does not delete provenance by design.

Default image cleaning must preserve rendering, orientation, colour profiles,
rights/licensing information, and accessibility data. A case where a successful
default clean changes those semantics is a security issue.

## Supported versions

Before 1.0, only the latest release receives fixes. No optional `c2pa` or
`research` dependency is shipped in 0.2.0; vulnerabilities in user-installed
third-party tools are outside this package's boundary.
