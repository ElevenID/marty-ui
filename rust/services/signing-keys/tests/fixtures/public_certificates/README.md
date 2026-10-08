# Public certificate and CSR vectors

These are synthetic public artifacts generated on 2026-10-07 by disposable
OpenBao 2.5.2 (`quay.io/openbao/openbao` image digest
`sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878`).
The dev instance used separate internal PKI keys for the root CA, intermediate
CA, short-lived CA, and DSC CSR. OpenBao generated and retained all private
keys; only the PEM certificates and CSR were copied into this directory.
The intermediate CA was signed by the root CA and has a path-length limit of
zero. The short-lived CA expires about one day after generation and is used
only with a synthetic future verification time. These vectors are test-only
and must never be treated as trust anchors or deployment credentials.
