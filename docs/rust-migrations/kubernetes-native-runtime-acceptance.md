# Kubernetes resolved-runtime acceptance

This is test-only executable qualification of the opt-in
[Kubernetes source composition](kubernetes-native-issuance.md). It does not deploy
anything, read operator Secrets, inspect a kubeconfig, or authorize Python
retirement. DIDComm KMS corrections remain out of scope.

## One shared executable graph, distinct input owners

The existing fresh-renewal graph still owns PostgreSQL admission, credential
materialization, Core encryption/decryption, real HTTPS wallet transport,
synthetic named control-plane/signing peers, and complete response/state checks.
It now accepts a closed Kubernetes profile in addition to the unchanged direct,
base-Compose and Envoy profiles. There is no second crypto or initiation owner.

`ResolvedRuntime` extracts only the shared exact-environment process boundary.
`RenderedBase` retains all actual Compose source/model checks before handing off
its environments. Kubernetes does not masquerade as a Compose result. Both
launch native issuance with `env_clear`; the sole Windows loader exception is
`SystemRoot`. Gateway execution remains Linux-only inside the exact-owned
PostgreSQL network namespace. Kubernetes requires its additional child marker.

The Kubernetes preparation and resolution boundaries are explicit:

1. The outer host runs the actual `envsubst` executable with a closed synthetic
   variable roster over the actual common ConfigMap and complete legacy service
   manifest. Only tool/OS loader paths survive from its environment. Source
   bytes are captured once, hashed, bounded, and checked again after rendering.
2. The resulting typed prepared JSON records the five exact source identities
   and synthetic inputs. An exclusively created, exact-owned temporary file is
   mounted individually read-only into the inner fixture. Its expected whole-file
   hash and profile marker are passed explicitly and checked before use.
3. The inner process invokes the existing public Rust Kubernetes composer for
   each mode. It resolves declared ConfigMap/Secret references against the actual
   composed maps and a fixed synthetic Secret map. It preserves ordered envFrom,
   explicit entry precedence, empty strings and optional missing references.
   Unknown fields, duplicate explicit names, unsupported reference types and
   Kubernetes `$(NAME)` expansion are rejected rather than approximated.
4. Only the named fixture addresses, listener ports, database/Redis URL, loopback
   native host and owned policy/CA file paths are substituted for execution.
   Required source URLs and parsed supported gateway defaults are checked first;
   the previously repaired auth/signing dependencies are not invented by the
   fixture. The secure private-IP default is absent from the source environment
   in refusal cases; positive local-wallet cases select the supported explicit
   opt-in. Authcrypt uses the selected read-only policy Secret path before that
   path is mapped to the owned synthetic file.

The existing base 18-file artifact roster is unchanged. Kubernetes has its own
seven-file roster: common/legacy/native/signing manifests, gateway config source,
and the two existing wallet helper scripts. The generated prepared model is an
additional exact hashed file, not a mounted source directory. The existing
outer helper retains its pinned renderer/artifact prerequisites; Kubernetes
does not execute Compose or require envsubst inside the frozen runtime image.
No host toolchain/library directories or Docker socket are mounted. The inner
container shares only the verified owned PostgreSQL namespace and publishes no
gateway/native host ports. Prepared-model cleanup refuses changed contents;
the mutation test proves retention until the test itself restores its original
exact bytes. Cleanup failures remain failures, not a successful child result.

## Evidence and limits

The Windows native-only gate
`kubernetes_resolved_native_profile_delivers_both_encryption_modes` passed both
fresh renewal modes through the actual issuance executable in 6.91 seconds.
It used actual published PostgreSQL migrations, real Core and HTTPS, verified
the signature/disclosure attachment and complete renewal DTO plus durable
source/successor/delivery state. Named organization/template/status/signing/DID
peers and historical source rows are synthetic. The controlled signer is not a
live OpenBao or signing-service capability test. Three exact-owned PG/probe/Redis
containers were independently verified absent after the passing run; all three
from the preceding fixture-expectation failure were also absent.

Three reference/preparation/cleanup controls and three shared outer ownership/
completion controls passed. Strict target Clippy passed in 10.11 seconds. The
initial fixture expectation incorrectly compared a parsed gRPC target against
its unprefixed source spelling; it now requires the actual gateway config
owner's HTTP-prefixed value, without changing raw source or runtime behavior.
The 115 new/retained Python source, model and required-CI guards passed. Existing
rendered-base and original fresh-main regressions passed in 9.99 and 4.83 seconds;
the retained 19-case DIDComm regression passed in 125.36 seconds. All 29
exact-owned containers from those retained runs, including the controlled Redis
constructor timeout, were independently verified absent (35 total across the
new success, preceding failure and retained regressions). Final package formatting
and diff checks passed. The complete existing published-contract preflight suite
also passed all 123 tests in 72.66 seconds after the new required registrations.

The mandatory Linux outer gate is
`kubernetes_profile_gateway_composition_isolated`, with the exact dedicated
child and required cleanup control also registered in the published contract
runner. It must execute the actual gateway and native binaries, both modes'
default-private-IP refusal and positive delivery cases, shared ordinary/token/
nonce/discovery and six Canvas operation-read cases, authenticated owner reads,
legacy POST traps, and unavailable-native refusal without legacy fallback.
Ordinary keyed replay at the gateway is Redis-cache replay, not a second native
admission recovery lookup. Existing separate native recovery and full Canvas
lifecycle gates retain their distinct evidence. The Linux outer gate has **not
been executed by this Windows checkpoint**; compiling it and testing its
inspection controls are not a substitute.

Still outstanding: exact-head Linux outer execution, real Kubernetes
Secret-volume/env projection and Service/DNS/network/probe behavior, full
deployment migration ordering, actual signing/Redis/OpenBao capabilities,
authenticated registry pull and reviewed release-image boot/provenance. Mounted
local test ELF files in a frozen owned runtime image do not prove the released
services image. A later real Kubernetes gate must use an explicitly owned
ephemeral cluster/namespace, never the ambient current kubeconfig. No source
wrappers may be deleted merely because this adapter compiles or its native-only
gate passes.
