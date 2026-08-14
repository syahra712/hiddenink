# Security policy

`hiddenink` parses files it did not create — that is its entire purpose. Report
anything that looks like a way to turn that against a user.

## Reporting

Open a [private security advisory](https://github.com/syahra712/hiddenink/security/advisories/new).
Please do not open a public issue for an unfixed vulnerability.

Expect an acknowledgement within 7 days. If a fix is warranted it will land with
a regression test and the advisory will credit you unless you ask otherwise.

## In scope

The threat model is **a user runs `hiddenink` on a hostile file**. Anything that
escapes that boundary is in scope:

- Denial of service through resource exhaustion — decompression bombs, quadratic
  parsing, unbounded memory
- Path traversal or writes outside the target file
- Code execution, including through deserialisation or entity resolution
- Network access from a tool that is documented as working offline
- **Silent corruption**: producing altered output while reporting success. This
  is treated as a security bug, not a correctness bug, because the whole value
  of the tool is that its reports can be trusted.

## Already defended, with tests

Reports of these are still welcome if you find a bypass. See
[`_safety.py`](src/hiddenink/core/formats/_safety.py) and
[`test_hardening.py`](tests/test_hardening.py).

| Class | Defence |
|---|---|
| XML entity expansion (billion laughs) | Entity declarations in the prolog are refused outright |
| XXE / external entities | Same refusal; no external entity handler is installed |
| zlib decompression bombs (PNG `zTXt`/`iTXt`) | `decompressobj` with an 8 MB output cap; never materialised |
| Zip bombs (`.docx`/`.odt`) | Declared member size checked *before* reading; oversized members skipped |
| Truncated / malformed containers | Parsers report what they read; cleaners return input unchanged rather than truncating |
| Lone surrogates | Read and written with `surrogatepass`, so inspection cannot crash on them |
| Non-UTF-8 consoles | Streams reconfigured; a legacy codepage cannot crash a report |

## Out of scope

- **Defeating a statistical text watermark.** Not a vulnerability; not a feature
  request either. See [Non-goals](README.md#non-goals).
- **Preserved C2PA manifests.** `hiddenink` removes metadata that identifies the
  user and keeps metadata that discloses AI involvement. That is deliberate,
  documented, and enforced by tests. If you need provenance stripped, this is
  the wrong tool.
- Findings that require the attacker to already control the machine running
  `hiddenink`.
- Vulnerabilities in optional extras (`[c2pa]`, `[research]`) that live in the
  upstream dependency — report those upstream, though a note here is welcome so
  the pin can be raised.

## Supported versions

Pre-1.0: only the latest release is supported. Once 1.0 lands, the two most
recent minor versions will be.
