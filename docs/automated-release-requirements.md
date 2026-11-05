# Unattended release requirements

## Product requirement

After one release request, CI/CD either publishes the selected artifacts using
the required evidence or stops with a specific failure. It does not wait for a
person to decrypt screenshots, review each test run, merge an approval record,
copy child workflow IDs, or launch a tag operator during a short time window.

Source changes still use normal protected pull requests and the merge queue.
Exploratory testing, visual design review, diagnosis and certification preparation
happen during development. A discovered repeatable defect becomes an automated
regression assertion before the fix is integrated.

## Revised requirements

| Previous implementation requirement | Replacement |
| --- | --- |
| Inspect every upstream positive `REVIEW` screenshot | Assert the exact test flow completed successfully through both the API and the actual rendered UI |
| Encrypt a combined evidence packet and obtain its private identity | Keep unfiltered diagnostics private and upload only bounded machine evidence; optional diagnostic delivery stays outside the release path |
| Merge a per-run disposition within 60 minutes | Qualify the frozen evidence immediately under a versioned, reviewed assertion policy |
| Advance main only to add the disposition | Keep candidate and protected-main source equal throughout the existing publication checks |
| Manually launch the tag operator during the publication wait | Have the publisher dispatch the same independent operator once and authenticate the returned run ID |
| Copy CI, claim and producer IDs between workflow forms | Pass the exact IDs between dependent jobs in the release coordinator |

These changes remove operating steps. They do not turn a failed or incomplete
test into a success.

## Automated interoperability decision

The seven existing official lanes still run against the exact built candidate
and pinned, unmodified upstream implementations. Existing negative protocol
tests, explicit optional-skip limits, complete plan coverage, process exit,
source/manifest/image bindings and JUnit requirements remain enforced.

For the pinned OIDF verifier, the supported positive review obligation is to
establish that successful presentation receipt led to completed verification.
The accepted harness and independent product validator enforce all of:

- The exact allowed positive module and lane variant, using the reviewed runner
  revision and its known successful-verification review condition.
- Complete original module logs with no additional review reason, warning or
  failure hidden underneath the aggregate `REVIEW` result.
- An exact module, plan and flow association; one flow cannot stand in for
  multiple cases.
- A correlated real API result of `completed`, `passed` and `allow`.
- The real result dialog's matching instance and decision, its successful API
  response, a visible verified outcome and absence of an error.
- The existing real screenshot and upstream persisted-image hash bindings.
- Exact equality between the upstream pending set and the automatically
  assessed cases. Missing, duplicated, stale or foreign evidence is rejected.

The release receipt explicitly records automated qualification. The original
upstream `REVIEW` stays `REVIEW`; the policy does not claim an upstream `PASSED`
or paid certification. Unknown obligations fail promptly and require local
investigation and a tested source change. A person cannot approve them during
the release to bypass the missing assertion.

Screenshots remain useful diagnostic material, but the assertions decide
release eligibility. Visual polish and subjective presentation choices are
reviewed locally when those parts of the product change.

## One release request

The `Release pipeline` workflow coordinates the existing producers. Its
protected-main source is fixed when the request starts. The selected channel
is nightly, stable, or both; stable version identity comes from the eligible
stack lock. Exact external infrastructure image digests come from the reviewed
`release/external-images.json` by default, so a routine request requires no JSON
copying. An explicit override must pass the same exact-service/digest checks.
The customer application profile remains explicit.

The coordinator runs full CI, then the applicable no-write claim and producer
workflows. Nightly and stable retain their different artifact contracts. The
stable producer qualifies automatically and starts its independent tag operator
without a person. The coordinator observes the already automatic v2 stable
publisher, requiring both intake and publication to complete successfully.

Optional production web packaging follows successful stable publication. The
existing combined application and independent website producers feed the signed
composition using their exact original run IDs. Customer packages continue to
exclude production marketing pages; the separate production web package owns
that surface.

Each dispatch uses the repository's ephemeral job token and GitHub API
`2026-03-10`, which returns the new workflow's exact ID and URLs. A stage records
its intent before dispatch. Read polling may continue within its timeout, but
an uncertain write is never blindly repeated. Failed jobs, foreign sources,
later attempts, missing outputs and skipped required publication jobs stop the
coordinator. Existing immutable version, create-only tag and signing rules
continue to apply.

The initial release request chooses what to publish. It is not a series of
runtime approvals. Routine code review remains upstream of CI/CD execution.

## Local development and verification

Develop the rule and its regression tests locally. Meaningful controls include
hidden upstream warnings, an unknown review condition, a negative review case,
a failed or incomplete plan, mismatched API/UI results, a reused flow, stale
source/image evidence, and a lost dispatch response. A successful control must
reject the faulty case without publishing or issuing a second write.

The shared Rust validator and Python gate must agree on the same closed
assessment schema. Old manual receipts are historical evidence and cannot be
substituted for a new automatic receipt. Source and workflow validation runs
locally before the normal protected integration of the paired harness/product
changes. The product pins the accepted integration merge commit before a real
candidate run is eligible.

Unit tests establish the policy's behavior; a fresh real candidate execution
must establish the deployed behavior. Do not rewrite historical failed runs or
describe a local mocked test as a successful release.

## Scope of completion

This contract covers unattended CI, claims, candidate qualification, tag
reservation, release publication and selected production web packaging. It does
not create a certification claim or silently assert that unfinished installer
journey checks have passed. Installed-system acceptance, channel admission and
deployment have their own existing requirements. If a required installer check
has no implementation, add that check locally or explicitly revise the product
scope; do not label an incomplete checkpoint `Ready`.

Private subscription/commerce rollout and discretionary paid infrastructure
remain separate product actions. The release coordinator does not create AWS
hosts or change account permissions.

## Implementation references

- `scripts/official_review_gate.py`: frozen evidence and immediate qualification.
- `rust/crates/release-evidence/src/official_automation.rs`: deterministic review
  obligations and the explicit automatic release receipt.
- `scripts/release_review_main.py`: production receipt admission and exact source.
- `scripts/release_tag_handoff.py`: one automatic operator dispatch and admission.
- `scripts/release_pipeline.py`: exact child workflow orchestration.
- `.github/workflows/release-pipeline.yml`: one-request release graph.
- The pinned integration harness's `scripts/oidf_marty_automated_assessment.py`:
  upstream reason validation and bounded API/UI observations.

API behavior is documented in GitHub's
[workflow dispatch endpoint](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)
and [GITHUB_TOKEN event rules](https://docs.github.com/en/actions/concepts/security/github_token).
