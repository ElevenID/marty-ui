# Canvas URL-template reference

Reference-only evidence for `_badgr_assertion_url`, `_badgr_validation_url`, and
`_badgr_revoke_url` from Credentials commit
`578e86ef43166be79add2d812e92ef650535edaa`. The adapter blob is
`c86671e2b2ab5bb8a72de78a9bdadb0f340a5ec8`; the artifact records the exact selected
AST/dependency closure. Existing pinned-source loader and regular-file output
ownership utilities are reused without modification. No application module,
operator settings, provider network, Rust code, or runtime dependency is changed.

The corpus contains 123 actual helper observations: 43 assertion, 43 validation,
and 37 revoke. It preserves exact result strings or exception type/message,
including 54 errors. Python 3.12.10 produced the initial capture. Defaults,
missing/empty IDs, quoting of reserved/Unicode characters, whitespace stripping,
escaped braces, named/index/deterministic attribute fields, conversions,
format specifications, nested width, malformed templates, and surrogate behavior
are represented. Assertions and validation intentionally retain their distinct
missing-badge error messages. Validation's unused delivery-record argument is an
inert value, not a fake implementation.

This is not a restricted replacement grammar. Address-bearing bound-method repr
and other nondeterministic introspection are not normalized or claimed as exact
deterministic parity. No provider request, lifecycle recovery, public route,
database persistence, native formatter, or deployment is qualified here. The
publication owner consumes this evidence before adopting a Rust formatting fix.

The observation child has a closed environment and file/network/process audit
fence after pinned definition loading. Any caught infrastructure violation fails
the whole capture, never becoming an expected helper error. Source reads precede
the separate 15-second observation bound. Both output streams are capped at
4 MiB, independently drained via regular files, and the child is reaped within a
separate five-second bound. Nonzero exit, stderr, malformed/duplicate/nonfinite
JSON, incomplete outcomes, or changed source/case identity fail closed.

Replay (read-only; explicit local Credentials Git checkout):

```text
python scripts/capture_canvas_url_template_reference.py <credentials-checkout> --check
python -m pytest tests/test_canvas_url_template_reference.py
```

Frozen JSON guards normalize CRLF to LF only. Git source identities retain exact
blob bytes; surrogate results remain escaped JSON rather than lossy replacement
characters. No feature deletion or full migration-completion claim follows from
this reference slice.

## Adoption status

The reference has now been consumed by the shared production Rust owner in
`canvas_credentials_urls`. Assertion publication, managed validation and
revocation status all call that owner; no consumer retains a separate template
replacement implementation. The wrapper passes all 123 observations, including
the 28 default/optional-identifier cases and seven eager-quoting failures that
were intentionally outside the generic formatter-only gate. Consumer suites,
the full 418-test issuance library suite and strict Clippy pass on the selected
implementation. Provider transport, persistence and deployment evidence remain
separate gates; this adoption closes the URL-helper parity gap only.
