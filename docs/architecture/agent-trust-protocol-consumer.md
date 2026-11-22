# Optional Agent Trust source consumer

Status: source integrity and schema-shape checks only. Runtime qualification is
`NOT_ASSESSED`; public discovery is `false`.

Marty has an independently reviewed source pin for the optional contracts added
by [Marty Protocol PR #38](https://github.com/ElevenID/marty-protocol/pull/38).
This prepares a shared implementation target for agent identity, delegated
commands, OAuth/account links, AuthZEN, security events and evidence portability.
The [consumer lock](../../contracts/agent-trust-protocol-consumer.json) selects
six profiles at source revision
`6126da7619e057be2ff58dd38a5d50f49891d1b3`, whose Protocol package version is the
unreleased `0.6.0` target.

The existing public Gateway remains on MIP `0.5.0` and its separate source pin
`76c37dc229b328afe002b911a26624543f814a64`. This source-consumer check does not
change public version negotiation, routes, OpenAPI, the public support catalog,
authentication or product activation. Protocol source availability is not an
implemented Marty feature or an interoperability result.

## Trust and coverage

The trusted input is this repository's reviewed consumer lock. Obtain the
Protocol checkout through an independently trusted distribution path. The
checker never accepts a replacement lock, expected digest or runtime trust claim
from the Protocol source tree, a submitted record or a manifest.

The lock binds the source commit and SHA-256 of
`conformance/agent-trust/v1/manifest.json`:

```text
3d9fc9475050d80ea2e0a835a3c8cf801a642303a063fa4d3014485ceb6b8d37
```

The [checker](../../scripts/check_agent_trust_protocol_consumer.py) performs a
fixed local Git revision query and verifies the manifest bytes against that
independent digest. It then checks the complete inventory against fixed,
consumer-owned source roots and verifies every listed file's bytes. It rejects
omissions, extra source files, substitutions, duplicate/ambiguous JSON,
noncanonical paths, traversal, symlinks and unreadable directories. Only ordinary
`__pycache__` directories are excluded, matching the pinned source-pack policy;
cache contents are never imported. The manifest excludes itself to avoid a
self-referential hash.

This pin covers 355 source files, including specifications, dependency schemas,
fixtures, reference code, test sources and the upstream test-dependency lock.
Code is hashed as data. The checker does not run or import upstream generators,
reference validators, test modules, package hooks or workflow definitions. Its
only child process is the fixed Git revision query, with inherited Git overrides
removed and hooks disabled; it never fetches a remote. No schema reference or
fixture reference may initiate network access.

After integrity checks, schema and fixture processing uses the verified in-memory
bytes. Fourteen selected schemas and their transitive schema dependencies are
checked against Draft 2020-12, including references in branches that a fixture
does not exercise. Unknown references fail before fixture evaluation. Other
bundled core schema/enum files are integrity checked, but their structural
conformance is outside this optional gate. The existing public-protocol suites
remain responsible for the public Gateway contract.

Checksums detect content changes. They do not authenticate a distribution if an
attacker can also replace the consumer lock or checker. Keep the source revision,
lock and checker within the normal reviewed source and release trust boundary.
Source archives without Git metadata need a separately reviewed import path;
they are not accepted by this checkout verifier.

## What fixture results mean

The pinned corpus produces the following structural results:

| Result | Meaning |
| --- | --- |
| 26 positive schema fixtures | Their selected record shapes satisfy the pinned schemas. |
| 26 negative schema fixtures | Their deliberately forbidden shapes are rejected. |
| 27 principal semantic-negative fixtures, shapes only | Their shapes are valid, but the pinned sidecars identify separate binding/consistency failures. Those semantic checks are **not executed** here. |

For example, an OAuth context containing a raw `access_token` field must be
rejected, as must a decision that simultaneously permits an operation and
requires further verification. A structurally valid session for the wrong
customer needs a separate authenticated binding check; this checker does not
pretend that JSON Schema establishes that relationship.

The output therefore reports `semantic_conformance: NOT_EXECUTED`. It does not
prove authentication, consent, current authority, signature verification,
canonical key conversion, receipt binding, replay protection, final-use
concurrency, domain idempotency or successful business execution. The upstream
reference suites and actual Marty consumer integration suites must exercise
those behaviors separately against independently established trust inputs.

## Local verification

Use Python 3.12 with the repository's contract-check dependencies. The initial
source-consumer verification used `jsonschema==4.26.0`, `referencing==0.37.0`
and `pytest==9.0.2`. These are checker dependencies; the Protocol checkout is
never installed as a package. No private repository source needs to be copied
into this repository.

With the independently obtained Protocol checkout at the pinned revision:

```sh
python scripts/check_agent_trust_protocol_consumer.py \
  --protocol-root /absolute/path/to/marty-protocol

MARTY_AGENT_TRUST_PROTOCOL_ROOT=/absolute/path/to/marty-protocol \
  python -m pytest tests/test_agent_trust_protocol_consumer.py -q
```

The unit tests use small synthetic packs to test source substitution, coverage,
path handling, unknown references, rejection reporting and the absence of
network/upstream execution. Setting `MARTY_AGENT_TRUST_PROTOCOL_ROOT` additionally
requires the actual pinned checkout and verifies its reported counts. Without
that variable, only the external-checkout case is explicitly skipped; synthetic
unit tests do not stand in for verification of the pinned source.

This is a local development check. It neither runs Actions nor changes the
existing CI pin. An eventual CI adoption must preserve the current public
protocol lane and its separate exact-version checks.

## Runtime handoff and future pin changes

The active Delegated Authority implementation owns lifecycle persistence,
authenticated approval/authority sources, challenge and original-result state,
managed receipt signing and final-use integration. Gateway integration must
establish the authenticated principal and represented subject, resource/tenant
ownership, current permissions, bounded evidence and required enforcement before
using these normalized records. Existing machine access is documented in
[machine API authentication](../API_MACHINE_AUTHENTICATION.md); a normalized
OAuth context does not add OAuth authentication to that Gateway.

Keep the [external connector boundary](external-connector-boundary.md): connectors
own provider credentials and jobs; Marty owns identity and representation
evidence and its own authority state; the consuming domain owns business facts,
cumulative reservations, operation identity, execution and reconciliation.
The five core primitives, single-hop v1 delegation and unsupported
`transaction_data` behavior remain in force.

For a future optional-source update, review the upstream diff, fixture changes,
manifest coverage, selected profile versions and dependencies. Update the
consumer lock and any affected consumer policy/tests together. Never regenerate
the expected digest automatically from the checkout under examination. A public
MIP version migration, hosted API, trusted deployment qualification record and
capability advertisement each require their own implementation and evidence;
passing this source check grants none of them.
