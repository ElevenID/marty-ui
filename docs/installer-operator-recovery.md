# Retained operator recovery

Operator-only recovery installs a separately authenticated owner beneath the
existing installation. It preserves the original bootstrap executable, signed
release evidence, installation UUID, rootless Docker engine, Compose project,
product image closure, database volumes, application data, and credential
history. It is not a product upgrade, database migration, credential issuer, or
conversion of an older custody receipt.

The **new target executable** runs `operator-upgrade stage`, `activate`, and
`reconcile`. The old executable does not need to understand its successor.
Both the original and target inventory/admission pairs are verified against the
publisher's exact signature and provenance identities. The target's own build
identity, executable digest and size must agree with its admitted inventory;
its release must be newer than the selected predecessor. An unsigned local
build or an unaccepted release cannot become an owner.

## Compiled compatibility profiles

`operator-upgrade-contract` returns a versioned catalog of compiler-owned profiles.
The caller cannot supply a different profile, force adoption, replace product
images, or request a schema change.

| Original source | Admitted retained state |
| --- | --- |
| `b7c7055830722d10512ccac042b1e0abe0e1ecec` | The original v1 operator-only profile: no pending generation; exact retained product model and native census. Its existing contract and transaction bytes remain readable unchanged. |
| `2ed9e4244cae46dc3678209653c22ae91c678583` | The same ordinary quiescent path, plus a completed managed-private generation at attempt zero whose binding and runtime activation have not begun. |

The second profile addresses a completed helper receipt larger than 256 KiB.
That installed operator's binding reader could reject an otherwise admitted
receipt below the producer's 4 MiB limit, leaving maintenance at
`producer_completed`. The corrected reader aligns the bounded evidence limit;
private credential payloads keep their 64 KiB limit.

The pending exception requires all of the following:

- The original source is exactly the source above, with the original signed
  bootstrap operator and product closure intact.
- The selected generation has managed private ingress. Public ACME and imported
  credential generations are not admitted by this pending exception.
- The next contiguous generation is attempt zero at `producer_completed`.
  There is no binding, binding-pending, activation, supersession, feature
  activation, recovery baseline, or OIDC-secret rotation for that attempt.
- Existing generation admission authenticates the selected parent, plan,
  enrollment identity, original inputs, create/start/wait evidence, completed
  unrestarted helper, candidate receipt, all delivered outputs, and historical
  certificate integrity. Expiry does not erase that historical proof.
- Native observation permits only the already authorized helper replacement
  and then requires the whole observed census to equal its completed receipt.
  A running or restarted helper, changed container ID, volume, or network fails.
- The handoff pins the original evidence, pending evidence, read-only input
  copies, renewal identity, and delivered bytes with their original modes.
  Retained infrastructure-recovery and stop receipts are allowed and pinned;
  the old boot unit's supported shutdown may write stop receipts while it is
  being quiesced, without beginning generation activation.
  The retained rootless-canary directory is admitted only by its existing
  completed proof: original receipt chain, stable filesystem/custody binding,
  exact private tree, marker, and removed helper observations. Its file bytes
  and directory identities are pinned; unknown evidence directories fail.
- Each predecessor user unit is persistently masked to `/dev/null` and observed
  inactive or failed, or is observably absent. Disabled alone is insufficient.
  The installation lock remains held, and retained state is rechecked
  immediately before atomic owner selection.

A failed admission preserves the original and pending records. It does not
delete a pending generation, mint another helper, rewrite a receipt, retarget
historical units, or claim runtime recovery.

## Operator procedure

Run all host commands as the existing non-root installation owner, against the
same rootless Docker engine. Keep the original directory and Docker data in
place. First obtain the exact **signed, admitted** corrected release and its
complete verification assets through the ordinary release verification path.
Local tests and a green source PR are not signed-release admission.

The target asset directory contains these six private files:

```text
installer-admission.json
installer-admission.json.sigstore.json
installer-admission.json.provenance.jsonl
installer-inventory.json
installer-inventory.json.sigstore.json
installer-inventory.json.provenance.jsonl
```

The admission must include the publisher's required staged and published
acceptance evidence. Verify the source SHA, release tag and operator artifact
digest against that exact release before running it. Preserve the existing
installation's original proof files; they are independently reverified during
admission.

1. Record the original lifecycle status and exact five original unit names.
   Stop and disable the check/maintenance timers first. Disable the original
   boot service and stop all original owner services. Persistently mask the
   exact five original user units to `/dev/null`; use `systemctl --user mask
   --force` when replacing the user-manager links to their retained exports,
   without `--runtime`. Preserve the original exported files in the installation.
   If previous successors exist, quiesce and mask their unit sets as well.
   Observe the resulting unit-file, active, load and process states. A disabled
   unit, unavailable user manager, or failed stop by itself does not establish
   the operator's required quiescence.
   Stopping the boot unit invokes its retained shutdown operation and can stop
   runtime containers while preserving the installation's running intent,
   data, helper history, and generation transaction.

2. Run staging with the **verified incoming target**, not the old retained
   executable. Paths below are placeholders for the actual verified artifacts:

   ```sh
   /absolute/verified-target/marty-deploy-linux-amd64 operator-upgrade stage \
     --install-dir /absolute/installation \
     --target-assets /absolute/verified-target/assets \
     --tools-dir /absolute/verification-tools \
     --gh-bin /absolute/gh \
     --docker-bin /usr/bin/docker
   ```

   Staging writes only the immutable operator attempt, authenticated target
   closure, distinct executable, and new unit exports. It does not select the
   owner or start runtime work. Review the returned phase and pending sequence.

3. Activate that exact staged sequence with the same target and proof closure:

   ```sh
   /absolute/verified-target/marty-deploy-linux-amd64 operator-upgrade activate \
     --install-dir /absolute/installation \
     --target-assets /absolute/verified-target/assets \
     --tools-dir /absolute/verification-tools \
     --gh-bin /absolute/gh \
     --docker-bin /usr/bin/docker \
     --sequence 1
   ```

   Use the returned sequence instead of assuming one. If an operation loses its
   response, use `operator-upgrade reconcile` with the same arguments and
   sequence. A pre-activation attempt can be canceled using the existing cancel
   command; an activation intent must be reconciled, not silently discarded.

4. Read `operator-upgrade status --install-dir /absolute/installation`.
   Use its exact `selected_operator.entrypoint` for subsequent lifecycle work.
   The selected path is
   `/absolute/installation/operators/<verified-sha256>/marty-deploy`.
   The incoming download path and original bootstrap path are not the selected
   owner. The status also identifies the distinct unit directory and names.

5. Resume with that selected operator:

   ```sh
   /absolute/installation/operators/VERIFIED_SHA256/marty-deploy lifecycle resume \
     --install-dir /absolute/installation \
     --docker-bin /usr/bin/docker
   ```

   In the affected sequence-2 case, the original sequence-2/attempt-0 producer
   and outputs remain intact. Ordinary generation recovery authenticates and
   stages that completed candidate. If its credential admission window or
   serving certificate has expired, the existing supersession transaction
   records a retained baseline and permits at most one new immutable attempt
   in that invocation. The next attempt is sequence 2, attempt 1; the selected
   sequence advances only after fresh output and native activation succeed.
   A running, failed, unknown, or restarted helper does not authorize that
   successor. No clock, expiry, token, selector, or original receipt is edited
   to make the old candidate appear fresh.

6. Verify lifecycle status, selected generation, serving certificate and token
   times, application validation, health, and the intended browser route.
   Link and enable only the new distinct unit set using the selected owner's
   exported commands after the prerequisite observations succeed. Keep every
   predecessor unit persistently masked. Timer enablement alone does not establish a
   renewal pass, successful offline-expiry recovery, or host-reboot qualification.

Do not substitute a whole-machine WSL shutdown, distribution unregister,
Docker-data reset, manual product-image replacement, or new installation for
this admitted owner handoff. A source, custody, or pending-state refusal outside
the profile needs its own supported recovery; this procedure grants no such
extension.

## Validation scope

Local tests exercise the real managed-certificate proof fixture without
publishing a binding, tampered helper/output/parent rejection, preserved file
bytes and modes, the mixed delivered-file modes, retained infrastructure
receipts, unchanged v1 serialization, forbidden transaction stages, changed
pending evidence at atomic selection, exact helper census, and predecessor
quiescence. Synthetic operator release fixtures do not replace cryptographic
release verification. The complete installed handoff and subsequent stale
candidate supersession still require an actual admitted signed release on the
retained Linux installation.
