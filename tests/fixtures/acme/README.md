# Historical public ACME certificate fixture

These files contain public certificates only. They are used for offline
signature, certificate-path and historical admission tests against the
unchanged compiled Mozilla trust anchors. They do not establish current
certificate validity, revocation status, domain control, private-key custody,
successful ACME issuance by Marty, or readiness of a deployment.

`le-first-shortlived-leaf.pem` is the first short-lived certificate published
by Let's Encrypt in its February 20, 2025 article:

https://letsencrypt.org/2025/02/20/first-short-lived-cert-issued

The PEM is reproduced from the article's public certificate block. Its only
DNS SAN is `helloworld.letsencrypt.org`; its public key is P-256 and its lifetime
is just under 160 hours. The article states that this certificate was
immediately revoked. It is also expired. Tests use a fixed historical clock
solely for signature/path validation, explicitly report that revocation is
not checked, and verify that current-time admission refuses it.

`le-e6.pem` is the corresponding E6 intermediate, signed by ISRG Root X2,
downloaded from the official certificate repository:

https://letsencrypt.org/certs/2024/e6.pem

Its provenance is listed on https://letsencrypt.org/certificates/ under the
retired E6 intermediate. No downloaded certificate is added to production
trust anchors. The test sends no network request and contains no private key.

Downloaded November 1, 2026. SHA-256 of the normalized PEM bytes (LF, one final
newline):

| File | SHA-256 |
| --- | --- |
| `le-first-shortlived-leaf.pem` | `043db46b06fc65e861177ded01bdbac511335c4a0025f49abb8c55adb17aa922` |
| `le-e6.pem` | `1429463d25654be735b6af5026b96ac989709b04a8107580bc5efcd8209ae72d` |
