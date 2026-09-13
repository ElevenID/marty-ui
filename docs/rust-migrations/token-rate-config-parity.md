# Token rate configuration and sliding-window parity

This slice preserves `TOKEN_RATE_LIMIT` and `TOKEN_RATE_WINDOW` behavior before
retiring their Python owner. It does not change Core/MMF revisions, KMS, routes,
deployment selection, or production configuration.

## Frozen reference and scope

`contracts/token-rate-python-reference.json` contains 40 independently replayed
cases from protected Credentials commit
`ddd6b4e4383fe1000e3255f3e4237dc5b6020a2a`. Its source table records exact Git blob
and SHA-256 identities for the issuance API routes and main middleware. The capture
executes unchanged AST-selected configuration, limiter, enforcer and request-ID
middleware; synthetic environment and clock replace external inputs. No operator
environment files, key material, database, socket or live deployment are accessed.

Run the explicit reference gate with CPython 3.12 and its capture-only dependencies:

```text
python scripts/capture_token_rate_reference.py <credentials-checkout> --check
```

The qualified local reference runtime is CPython 3.12.10, FastAPI 0.135.3,
Starlette 1.0.0 and HTTPX 0.28.1, with the default 4,300-digit integer policy.
Ordinary repository guards import only the standard library and pytest; they do
not reinstall the retired application runtime. The capture reads immutable Git
objects, not the checkout's dirty or current source. It writes nothing.

The reference HTTP cases exercise the real default FastAPI error stack around a
named stand-in successful endpoint, not token business logic or a deployed service.
The native replay uses the actual limiter and transport middleware at the same
boundary, comparing status, body, selected headers, and downstream-call count.
Independent existing token/proof-nonce business-route tests retain their fixtures;
the shared-budget test additionally runs through the exact-integer constructor.

## Preserved behavior

- Shared `mmf_config::numeric_config::PythonConfigInteger` owns integer grammar:
  signs, underscores, Unicode decimal digits/whitespace, and the digit limit.
  No duplicated parser or bounded-integer clamp is introduced.
- Zero and negative limits start successfully and reject requests. Zero and
  negative windows retain the original strict timestamp comparison. Large values
  remain exact, including the decimal `Retry-After` header.
- Windows too large for Python float conversion fail on each request before the
  limit check, not at startup. This preserves the plain-text 500 without CORS or
  request-ID decoration, including when the request supplies an ID. Normal 429s
  retain ordinary transport decoration.
- The absolute monotonic float, integer-to-float rounding, subtraction order and
  strict `timestamp > cutoff` comparison match the reference. Rejected requests
  do not persist a newly pruned list; every direct reference step checks stored
  client count and exact timestamp bits as well as acceptance/error outcomes.
- Configuration errors remain closed and do not echo raw values. Explicit clock
  failures likewise cannot consume budget or invoke the business endpoint.

The unpublished in-workspace limiter retains its `new(usize, Duration)` and bool
`check` APIs, including subsecond durations. The retry accessor now borrows the
canonical integer instead of misleadingly returning a bounded `u64`; the HTTP
owner uses `retry_after_header()` and the fallible `check_request()`. This does not
claim arbitrary-epoch nanosecond precision from the previous `Instant` approach.

## Reusable platform clock

`marty-platform-clock` has a safe public API, checked integer scaling and explicit
errors, with narrow documented platform FFI. The issuance service retains its
`unsafe_code = "forbid"` policy. The selected clocks and integer-seconds conversion
follow [CPython 3.12.10's authoritative implementation](https://raw.githubusercontent.com/python/cpython/v3.12.10/Python/pytime.c):
`GetTickCount64` on Windows, `mach_absolute_time` on Apple platforms, and
`clock_gettime(CLOCK_MONOTONIC)` on the enumerated Linux/Android/BSD targets. There
is no process-relative epoch or silent wall-clock/suspension-policy fallback.
Unreviewed platforms return an explicit unsupported-platform error.

Fifteen frozen conversion vectors come from the actual pinned interpreter's
`_PyTime_AsSecondsDouble` C function, including integer-second and large-integer
rounding boundaries. Native tests compare all result bits and check scaling
failures plus actual platform identity/monotonicity. Windows execution is locally
qualified; Apple and BSD/Android implementations are source-reviewed, not claimed
runtime-qualified. Linux runtime qualification is required from hosted CI.

The existing workspace test/build inventory, workspace Clippy and shared image's
whole-`rust` copy include the new library automatically. It adds no executable or
service/image count. A source guard checks these registration boundaries. The
lockfile adds only the local crate and its edges to already locked platform
dependencies; no existing dependency versions or external source pins change.
