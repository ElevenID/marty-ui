# KMS recovery investigation

Merge-candidate run 39848444458 failed at bootstrap root self-revocation with
HTTP 500 (job 120069531887). Later protected candidates 39852668850 and
39853152062 passed the OpenBao job. The original failure remains unresolved;
neither a retry nor the absence of another failure establishes its cause.

The disposable probe now reports fixed, bounded revocation error classes and
the subsequent root-lookup and public health status. It never returns the raw
error body or token. A failed revocation response still fails the probe even
when readback suggests the token was removed. There is no mutation retry.

Local Ubuntu 24.04 execution of the unchanged probe reproduced a separate
snapshot-unseal HTTP 400, classified as authentication/decryption failure. The
probe now reloads the replacement process before submitting the separately held
original key, matching the existing coordinated restore path. A shared process
replacement helper maintains cleanup custody and resolves its new published
port. Transit ciphertext and both versioned plugin keys must still survive this
restore and a subsequent independent process restart.

One run with the reload change failed the same unseal check; a subsequent run
completed HTTPS bootstrap, root retirement, cold-copy and snapshot recovery.
Recovery reliability is therefore still unresolved. These local operations used
cached plugin image
`sha256:156717cf81d3059297d53117ce61a728cf8429bbe957ec57b0ef3393e914e475`
(OpenBao 2.5.5), not a new image built from this source. Fourteen focused Python
checks cover safe diagnostics, single-shot initialization, endpoint replacement
and cleanup ownership; Ruff passes. No beta or real self-host custody state was
used. The successful local recovery is not official conformance, current-image
qualification, or a passing D07/D08 demo.

Next, retain the first restore process's classified failure diagnostics and
determine the actual persisted-state failure before claiming a reliable repair.
The official release prerequisite remains exact-main qualification followed by
the real seven-lane candidate run. Source and fixture checks cannot replace it.
