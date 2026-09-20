# Named-string formatter and Canvas URL adoption

`python_format` is now a private production module shared by the native Canvas
assertion-publication, managed-validation and revocation-status URL owners. The
consumer wrapper in `canvas_credentials_urls` owns defaults, identifier rules,
eager quoting, whitespace stripping and public error projection; the generic
formatter remains DRY and unaware of Canvas policy.

The shared API takes lossless `PythonText` and named, already-prepared string
values. Caller-owned URL quoting, default templates, optional identifier rules,
and whitespace stripping remain outside the formatter. Parsing, field lookup,
conversions and string specifications follow the independently observed Python
3.12 behavior, informed by the exact CPython 3.12.10
[field parser](https://github.com/python/cpython/blob/v3.12.10/Objects/stringlib/unicode_format.h)
and [string formatter](https://github.com/python/cpython/blob/v3.12.10/Python/formatter_unicode.c).
Existing lossless text/repr and MMF Unicode integer owners are reused; there is
no runtime Python interpreter or frozen result lookup.

The helper reference contains 123 cases. The formatter-only gate explicitly
separates 88 formatting cases from 28 caller-default cases and seven eager
quoting errors. The production wrapper now replays all 123 cases without an
exclusion list, while the formatter test retains the narrower 88-case ownership
boundary. This is not the entire Python formatting space.

The builtin existence inventory is captured using CPython 3.12.10's exact
`str`/`type` instance, class, and metaclass MRO dictionaries. `dir(str)` alone is
insufficient because it omits metaclass attributes such as `__name__`. The
inventory records types or descriptor errors, never arbitrary values, invoked
methods, or address-bearing repr strings. It permits genuine absent-attribute
errors to be distinguished from known existing capabilities that remain
unmodeled. Eighteen independent absence observations retain Unicode, surrogates,
NUL, quotes and long names.

The follow-on metadata reference contains 463 exact CPython 3.12.10 templates:
356 deterministic outcomes, 97 address-bearing identity shapes, and 10
platform/build-state observations. Identity addresses are removed completely
while retaining a closed owner classification; both uppercase and lowercase
hexadecimal spellings are covered. Platform/build-state rows intentionally keep
only their case identity and qualification, never a captured host value or a
false Rust parity claim. These rows qualify possible formatter expansion; they
are outside the selected Canvas URL surface.

Remaining formatter-expansion gates, not blockers for the three selected Canvas
URL consumers:

- Model remaining deterministic builtin metadata/object paths, not merely the
  known `__class__`, name, qualname and module fields.
- Define governed observations for nondeterministic bound-method/object repr;
  never normalize addresses into a false exact-parity claim.
- Extend specification/parser differential coverage beyond the existing corpus.

An additional frozen 777-case string-only differential inventory exhausts pairs
of eight fixed format axes, selected three-way combinations, numeric-prefix and
Unicode-decimal names/indexes, nested-spec error ordering, and NUL/non-ASCII
conversions. It has 125 successes and 652 exact exceptions; every case must be
compared without skipping internal capability errors. Small widths and numeric
overflow before allocation bound this independently captured workload. It is
still not a complete builtin-object grammar proof.

Unknown existing object capabilities return an explicit internal
`UnmodeledCapability`, never a fake Python `AttributeError`. Allocation failures
are separately classified as `ResourceFailure`; the implementation uses checked
growth and does not clamp valid widths into fabricated successes. This is not a
claim of identical allocation thresholds across Python and Rust, nor recovery
from every allocator-level failure: input collection, repr expansion, cloning,
and codepoint helper allocations remain ordinary infallible Rust allocations.
Only checked append and final formatted-output reservations currently expose
the explicit recoverable resource error. Debug/Display expose only error kinds; exact
lossless diagnostics require the explicit message accessor and caller policy.

Reproduce the independent metadata inventory using exact CPython 3.12.10:

```text
python -I scripts/capture_python_string_attributes.py --check
python -I scripts/capture_python_format_metadata.py --check
```
