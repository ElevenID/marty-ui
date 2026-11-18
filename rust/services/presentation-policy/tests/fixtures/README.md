# Open Badge verification fixtures

The positive fixtures include an achievement criteria object before signing.
They exercise the same governed issuer and foreign issuer scenarios as the
historical fixtures, with freshly generated signatures and deliberately
disposable unit-test keys. They never use an issuer service key, production
registry, or local fallback for a deployment signer.

| Fixture | Purpose |
| --- | --- |
| `governed_ob3_with_criteria.json` | Positive governed issuer verification, registry wrapper selection, and refusal of token-supplied keys. Uses Ed25519 with the existing `JsonWebSignature2020` proof suite. |
| `foreign_ob3_with_criteria_jwt.json` | Positive ES256 issuer authentication kept separate from policy trust. Retains the foreign issuer, subject, credential ID, and 2026–2100 validity window. |
| `governed_ob3.json` | Unchanged historical JWS2020 credential without criteria. Its authentic proof must not make the incomplete OB3 profile valid. |
| `foreign_ob3_jwt.json` | Unchanged historical ES256 credential without criteria. Generic signature/VCDM verification succeeds; dedicated OB3 verification rejects the missing criteria. |

The new governed credential retains the original issuer identifier, method,
subject, and credential ID. It represents the issuer as a `Profile`, supplies
`validFrom: 2026-01-01T00:00:00Z`, and has a new proof created one second later.
The signed JWT freshness helper in `native_kernel.rs` similarly supplies a
Profile and validity dates aligned with its existing `nbf` and `exp` values,
along with criteria, before its existing real test signatures are produced.
The ordinary VC branch and every trust, tamper, and clock assertion remain.

Both new static credential bodies were checked against the pinned official
OB3 AchievementCredential schema with Draft 7 and format checking: zero errors.
The schema SHA-256 is
`b7358e895f492e74055dc6bfc7ffc420d0e497f90c4579fb83d9519b86d393ea`.
This checks those credential bodies; it does not claim full product
certification or compatibility of the existing nested JWT envelope with every
VC JOSE/COSE profile.

## Reproduce the public positives

`generate_ob3_positive_fixtures.py` is optional development tooling. Its
development dependencies are PyLD 3.3.0 and cryptography 50.0.0; they are not
application or CI dependencies. Supply a Core checkout containing the exact
public JSON-LD contexts pinned in the script, unchanged from Core
`ab91a6fd97b2483965e8cb966c3b2e3ddeedf1ca`:

```sh
python generate_ob3_positive_fixtures.py --core-root /path/to/marty-core
```

The default invocation checks byte-for-byte reproduction of the two positive
files. `--write` writes only those derived positive files. Before either mode,
the script checks the historical fixture hashes and independently verifies
both historical signatures. Context loading uses only the five pinned local
context files and refuses every other URI; it cannot fetch network contexts.

For JWS2020, URDNA2015 canonicalization combines the credential contexts with
the proof's JWS2020 context for the proof configuration, then signs the detached
JWS over the proof hash followed by the unsigned credential hash. This recipe
first reproduced verification of the unchanged historical proof. The new
Ed25519 fixture uses public test seed byte `71` repeated 32 times. The ES256
fixture uses public test scalar byte `72` repeated 32 times, deterministic
ECDSA, and the low-S form. These values have no deployment authority.

| Public evidence | SHA-256 |
| --- | --- |
| Historical governed fixture | `3b65cb9fb09ee9bf324def612388d687c96019b9076dd98bb7125f2b8d848af9` |
| Historical foreign fixture | `9d88b796b081aee3507654ca719c058b633c689ace6b6a54cb1597ce4822a0c0` |
| New governed fixture | `76484cb242b091141f818796a79ee9b5ee63bf1dffdd7ecd6bdabe75d93df7cb` |
| New foreign fixture | `6dc97566aa3f9f5b8e68196c08ba84b39949c1ce332f260a9fdf06d9731174db` |
| Historical canonical proof options | `0d9e9a26415b468f7976bf23c4326a5619a4b0e3a83befb79c484bdd3a5f496a` |
| Historical canonical unsigned credential | `4a25f8017dae429e690f3708fdf5b7268a15620dc2c91869cd6eab636028bc98` |
| New canonical proof options | `fb7782c709a22ba395265a00107930e7bf72a291426e1aae99f78a0428eed744` |
| New canonical unsigned credential | `473e423da673544b947b56d6f9f285d996918cb958d69904ce38409713426fe4` |

The native `marty-presentation-policy` library, `native_kernel_behavior`, and
`scoped_registry_verification` suites remain the execution gate for these
fixtures. Independent fixture generation and schema checks do not replace
those actual verifier and policy tests.
