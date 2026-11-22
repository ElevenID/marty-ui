# Inspect a website composition on a managed Windows deployment

`scripts/selfhost_windows_website.py --check-only` authenticates a website
composition and compares it with the existing Windows generation owner's
selected application, backend and integrated OpenBao configuration. It is a
read-only diagnostic. It does not deploy a website, qualify production, renew
credentials, repair the selected model or change a scheduled task.

The ordinary `deploy_website.py` owner supports a separate OpenBao project. It
must not recreate the edge or add slots to a managed project's retained model.
The managed owner records the complete configuration, installed identities and
credential-generation history. A website mutation needs its own coordinated
transition and recovery support under that owner before it can be enabled.

## Use the existing selection configuration

Use a trusted checkout of the helper, Python 3.12 and the pinned dependencies in
`scripts/selfhost-preview-tools.requirements.txt`. Supply reviewed Windows gh and
cosign executables and an original signed composition's six files. The full
application requires a compatible full website; a public website composition is
not a substitute for the installed full application/backend.

`--selection-file` is an existing private **generation configuration**, such as
the configuration already retained by the selected owner's scheduled recovery
or renewal entrypoint. It is not `owner.json`, a selection record, a Compose
file, or the wrapper's `marty.windows-managed-recovery/v1` JSON. A retained
historical configuration can resolve through completed recovery and continuation
links using the existing owner. Do not choose a generation by directory name or
edit an earlier record to make it current.

For example, after assigning the reviewed absolute paths:

```powershell
$Arguments = @(
  '--check-only',
  '--selection-file', $ExistingSelectionConfiguration,
  '--composition-dir', $OriginalCompositionDirectory,
  '--gh', $ReviewedGh,
  '--cosign', $ReviewedCosign,
  '--registry-config', $PrivateGhcrConfig
)
& $Python (Join-Path $TrustedCheckout 'scripts/selfhost_windows_website.py') @Arguments
if ($LASTEXITCODE -ne 0) { throw 'Managed website inspection did not complete.' }
```

The private registry configuration is the explicit owner-private static
`auths.ghcr.io.auth` input already required for private OCI proof verification.
The verifier does not execute Docker Desktop credential helpers or inherit
unrelated credentials. Do not print its contents. Artifact acquisition and
verification retain the producer, repository, workflow, source, run and attempt
checks documented in [Independent website release](independent-website-release.md).

## What the diagnostic verifies

The command acquires `selfhost_windows_selection.selected_inputs()` and holds
the real project lock and private inputs until inspection completes. Existing
pending-operation, retirement, predecessor and recovery-chain guards remain in
force. A lease refusal cannot be bypassed with the ordinary website command.

Within that lease the diagnostic:

- Authenticates the original outer composition and its embedded website,
  application and backend evidence using the existing verifier.
- Uses the retained Docker pipe and exact engine ID, without selecting a new
  Docker context.
- Renders both retained credential-generation models with every profile and
  verifies that their only difference is the expected secret-file generation.
- Checks the selected service closure, Compose configuration hashes, exact
  configured digest references and installed image IDs.
- Checks selected secret-mount paths and the recorded non-secret data-mount
  identity hash without returning environment or secret contents.
- Preserves the completed `openbao-tls-init` through its existing historical
  receipt. It does not reinterpret that earlier image as the current provider
  image or replay the initializer.
- Compares the exact product role and image map, all four configured OpenBao
  role pins, website audience and independent edge health configuration with
  the authenticated composition.
- For a compatible full standalone v4 composition, binds the retained source
  and rendered edge configurations to the exact installed read-only template
  mount. The selected owner holds the bounded Windows template bytes and their
  namespace through the final container readback and lease exit. The report
  includes the byte count, template digest and mount-record digest. The combined
  baseline must have the website include, independent health location and no
  existing or overlapping website route mount.
- Rechecks installed identities before releasing the lease. Results are emitted
  only after all lease and input exit checks finish successfully.

Docker operations are limited to engine inspection, Compose configuration reads,
container inspection and image inspection. The diagnostic deliberately does
not call the broader recovery configuration callback: that callback can create
temporary kernel-witness containers for a storage-custody proof.

## Interpret the result

The output uses `marty.windows-website-preflight/v1`. Exit status zero means that
the inspection completed and produced a report. It does **not** mean that a
deployment may proceed. A valid authenticated composition can still receive
compatibility blockers.

| Field | Meaning |
| --- | --- |
| `composition_authenticated` | The original composition and embedded proof checks succeeded. |
| `selection_sequence` | The selected record within the active journal segment. |
| `generation_sequence` | The cumulative sequence, including sealed predecessor offsets. |
| `composition_matches_selected_product` | The compared role, pin, audience and edge-configuration requirements match. |
| `compatibility_blockers` | Fixed reason codes for product-role, product-image, OpenBao-image, audience or edge-configuration differences. |
| `mounted_edge_template_checked` | The full v4 preflight bound the installed template mount to held Windows source bytes. |
| `combined_edge_template` | Template byte count, SHA-256 and runtime mount SHA-256 for a compatible full v4 composition, otherwise `null`. |
| `activation_supported` | Always false for this diagnostic milestone. |

The template check establishes the combined host input and mounted source
identity. Qualifying the running Nginx configuration, public routing and
application handoffs requires the managed transition.

## Reconstruct the first-cutover plan

For a compatible signed full v4 composition, add
`--plan-attempt-directory <absolute-path>` to the check-only invocation. Use an
unused `windows-website-<32 lowercase hex>` path directly under the selected
Windows owner root. The planned route directory is its `routes` child.

The signed website digest must already be cached on the selected Docker engine.
The planner checks the cached registry digest, image config ID, Linux/amd64
platform, production website labels, port and volume declarations. It holds the
six original outer proof files under the selected lease and binds the plan to
the selected journal, configuration, template, application and provider
identities. The report's `transition_plan` contains the plan hash, proof hashes
and model, data and route hashes for the combined, staged and split proposals.

This check-only operation leaves the attempt path available for the managed
transition. The transition must rebuild the plan from held inputs, qualify its
rendered models and record the observed runtime changes before admission.
| `production_admission` | Always false; this report is not release or runtime admission. |

The report explicitly leaves native custody, foreign-storage custody, runtime
readiness, mounted edge-template contents and public ingress unqualified. It
does not make those checks successful by omitting them. A healthy edge alone
does not prove that the actual mounted template includes website routes; a
matching image map alone does not prove the application's live journeys.

Unhealthy product containers do not automatically prevent this inspection, but
changed configuration, image bytes, data identities or historical initialization
evidence do. A failed command returns a fixed error without publishing private
native diagnostics or a partial success report. Preserve the existing owner,
guards and records for its normal reconciliation path.

## Ordinary-owner guard

`deploy_website.py` now refuses a known managed owner before creating its own
state directory, and rechecks before every Docker call. It examines only
directory-entry metadata for the project's retained selection, lock and
operation markers among the supplied stack, Compose and env-file ancestors.
An incomplete entry, dangling link or metadata-access failure also refuses.
Directory ancestors are checked before traversal; symlink or Windows reparse
ancestors, including junctions that could hide a managed root, are refused.
It does not open or remove private records and does not perform a recursive
host search.

This is a positive guard for retained managed ownership, not a claim that the
absence of a marker discovers or authorizes every possible installation owner.
Do not move, rename or delete managed records to reach the ordinary deployer.
Existing ordinary-host v1 state and identity serialization remain unchanged.

## Remaining managed integration

The next deployment milestone must define a narrow website transition under the
same selected-owner lease, retain authenticated receipts, add only declared
website slots and the allowed edge route mount, and preserve the complete
product/provider/data baseline. It must include a durable transition journal,
interruption reconciliation and a first-cutover combined backout.

The selected model and installed-identity validators, renewal and reboot
recovery must then recognize the coordinated website ownership. The current
ordinary website lock and generic model repair are not that integration.
Qualify the actual custom edge template, independent public ingress, restart
ordering, live handoffs and backout before live cutover or removal of the
combined website fallback. This preflight makes none of those mutations.
