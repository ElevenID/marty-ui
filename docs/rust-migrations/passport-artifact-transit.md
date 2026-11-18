# Passport artifact Transit boundary (not activated)

The Rust signing-keys service exposes two authenticated, organization-scoped
internal operations for passport artifact chunks. A dedicated, non-exportable
OpenBao Transit key, `passport-artifact-marty-aes256`, encrypts and decrypts the
chunks. Neither the signing-keys service nor the issuance service receives the
key or a plaintext data key. The shared OpenBao client does not follow HTTP
redirects with its service token.

The encrypted envelope binds `organization_id`, `artifact_id`, `chunk_index`,
and `chunk_count` inside the Transit ciphertext. Decryption verifies those
fields before releasing the chunk. A chunk is at most 512 KiB; the fixed-size
limit keeps each base64-encoded Transit request well below the
[OpenBao HTTP request limit](https://openbao.org/docs/next/secrets/transit/)
while allowing an artifact to span many chunks. The versioned
behavior contract is `contracts/passport-artifact-transit-behavior.json`.

This PR provides the KMS and gateway layer only. It does **not** select the
provider in native issuance, replace the Fernet artifact format, remove an
existing artifact secret file, or activate the beta passport overlay. The next
consumer PR must store a versioned chunk manifest, preserve the legacy read
path where existing native artifacts need it, encrypt before insertion,
decrypt only after tenant-scoped job lookup, and encrypt the scrubbed artifact
on activation. KMS-only beta readiness must require the new Transit path and
must not accept a mounted Fernet key as proof of readiness.

Before any beta activation, provision the dedicated key and the least-privilege
encrypt/decrypt permissions in the existing beta OpenBao instance, prove a
tenant-bound round trip through the deployed Rust services, and verify that
production configuration and traffic remain unchanged. The OpenBao init script
declares the key and policy for new/self-hosted instances; an existing instance
needs an explicit operator-controlled migration rather than a second provider
deployment. Passport callback HMAC custody and bureau delivery remain separate
cutover gates.
