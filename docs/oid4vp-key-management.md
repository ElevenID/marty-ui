# OID4VP key-management boundary

Marty does not accept verifier private keys through environment variables,
files, Compose values, or API payloads.

Request Objects are signed through an active issuer profile. The flow service
selects `OID4VP_ISSUER_PROFILE_ID`; the gateway resolves that profile's DID,
verification method, signing purpose, and non-exportable KMS binding. The flow
service receives public DID material and a signature, but never a KMS service
ID, provider key reference, or private key.

HAIP and Digital Credentials API responses require a fresh ECDH recipient key
for each flow. Marty generates that short-lived protocol key in memory and
immediately persists its private JWK as an authenticated OpenBao Transit
ciphertext bound to the organization, flow instance, and
`oid4vp_response_decryption` purpose. The plaintext is unwrapped only for the
callback decryption operation and is never written to flow storage.

The HAIP `x509_hash` certificate is public identity material. Its leaf public
key must match the public key published by the selected issuer profile; its
matching private key remains in KMS.

Official third-party interoperability containers may have their own disposable
test keys when their unmodified upstream image requires them. Those keys are
not Marty identities, are isolated to the test Compose project, and are removed
with that project. This exception does not permit a Marty service to load or
persist private key files.
