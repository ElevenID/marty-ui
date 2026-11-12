# Early workload profile admission

When recovery requests an owned-workload reload, the authenticated caller reads
all 16 original Deployment profiles before creating the temporary producer or
issuing credentials. It uses the same admission policy as final reload: original
images, Helm ownership, release annotations, single-replica/unpaused configuration
and Pod security.

This GET-only preflight has one 600-second observation budget. It admits cold
workloads without requiring Ready Pods and records the successful observation in
private `reload-preflight.json`. An incompatible profile stops credential requests.
The receipt remains bound to the attempt's private evidence while recovery proceeds.
The caller refreshes namespace and original OpenBao Pod identity after this
observation, before creating the producer.

The earlier observation cannot replace final live admission, Secret checks or
qualification freshness. Readiness and full-environment health remain separate.

## Version checks at restart dispatch

The reload owner keeps its initial 16-workload inventory fixed. Before each
single restart patch, it reads that Deployment once more. A controller status
update may advance the resource version; the UID, generation, complete spec and
all metadata other than server bookkeeping and the controller's revision field
must still match the original observation. The patch retains atomic tests of the
UID, freshly read resource version and complete Pod template. A race after this read stops the
attempt without retrying the patch.

Private evidence retains both observations, the exact request and its intent.
Completion verification checks their semantic relationship and the captured
response, as well as the journal's byte and file-identity bindings. The original
qualification deadline is still checked immediately before dispatch.

If Secret activation completed but workload reload failed, the command reports
the 34 verified Secret updates and incomplete reload separately. The failed
attempt remains preserved and cannot be replayed automatically.
