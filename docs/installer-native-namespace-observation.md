# Native census namespace projection

`installer_namespace_projection` is a dormant, crate-private controller-side
primitive for the distinct native census protocol. It does not change the
legacy normal-31 census, expose a product command, admit an installation, or
produce a deletion manifest.

The controller pins the connected Unix peer with kernel `SO_PEERPIDFD`, then
holds its proc directory and user/PID namespace descriptors. There is no
numeric-PID fallback. Unsupported kernels or inaccessible evidence return
incomplete. A pidfd pins process identity, not namespace membership; namespace,
start identity, liveness and bounded map evidence are checked again around
projection. Borrowed private binding evidence lets the future owner binder
independently correlate the exact Engine/container/image/command/binds, cgroup
and namespaces. Socket credentials, a nonce or a matching executable alone
cannot establish that membership.

UID/GID maps are read from the controller's view of the peer. Same-user-
namespace map interpretation is refused because that proc interface describes
the parent namespace in that case. Both source and destination intervals must
be disjoint, bounded and exclude reserved IDs. Raw map/overflow bytes remain
part of the snapshot. Raw and projected overflow IDs are refused even when a
range numerically covers them. A bounded owner set is projected only between
fresh matching observations, with namespace zero and connection credentials
matching an independently asserted nonroot operator. This does not authenticate
the operator assertion, receipt or census message.

Ordinary tests exercise map refusal and real kernel socket/process lifetime
behavior:

```sh
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-deployment-catalog --lib installer_namespace_projection::tests::
```

The separate qualification requires an admitted ordinary nonroot `unshare`
runner. It executes both single and nested user namespaces, verifies the
controller projection, and rejects unmapped owners, operator substitution and
peer exit:

```sh
cargo test --locked --offline --manifest-path rust/Cargo.toml \
  -p marty-deployment-catalog --lib \
  installer_namespace_projection::tests::actual_single_and_nested_namespace_controller_projection \
  -- --ignored --exact --test-threads=1
```

That is kernel process/namespace qualification, not a Docker or installer run.
The separate `installer_namespace_census` primitive observes the fixed native
23/24-entry profile through held descriptors, including Unix-socket metadata
without opening or connecting to the socket. It refuses unknown/missing top
entries, symlinks, hardlinks, FIFOs and cross-mount traversal, bounds the walk
and private response, and rebinds every path/directory after traversal. Its raw
namespace identities and lexicographic entries are separate from purge types.
The walk itself does not assert that the root's mount is read-only or that
ownership is authenticated; those belong to the protocol/controller.

An equivalent mount ownership view must also be proven independently. A
user-namespace UID/GID projection does not undo an unknown per-mount ID map.
Read-only status, equal device/inode identities and a matching bind-source
string alone do not establish that equivalence. Unavailable mapping evidence
must result in incomplete observation, not inferred host ownership.

The private listener/nonce protocol, independent container/receipt binder,
and bounded native walks/socket observations still need integration. Neither
these primitives nor a matching census can
replace stopped-writer custody, authenticated ownership evidence, explicit
consent, durable intent or separate deletion authorization. Real rootless
mapped-private-tree and isolated installer qualification remain required.
