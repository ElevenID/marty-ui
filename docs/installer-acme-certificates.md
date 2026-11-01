# External ingress CSR and certificate admission

`marty_deployment_catalog::installer_acme_certificates` prepares public CSR
templates and validates signed CSRs and returned certificate chains. It is an
isolated library boundary: no installer command selects an ACME certificate
source, persists an order, renews a certificate, or activates its output yet.
The module creates and exports no private key.

## Identity and retained key

`CertificateIdentity::from_ingress` requires one canonical, qualified DNS name
and permits one explicitly configured nonloopback IPv4 or IPv6 address. DNS is
the stable identity; ports belong to hosting origins and are absent from SANs.
Wildcard, extra DNS, duplicate, email and URI SANs are refused. IP addresses use
the X.509 IP SAN representation, never a DNS SAN containing an address string.

`RetainedIngressKey::bind` binds an installation UUID, its existing ingress
Transit resource name, independently recorded SPKI, and observed OpenBao key
metadata. This release requires the original nonimported, nonderived P-256 key
at version 1, with no additional versions, signing enabled, export disabled,
and plaintext backup disabled. The metadata public key must exactly match the
recorded SPKI. A CA response cannot select or replace the key.

The integrating owner must fetch metadata using its authenticated OpenBao
connection and call `require_metadata` before and after a CSR operation. This
library validates the supplied public evidence; it does not fetch it or make
claims about the server based on an unauthenticated document. Key rotation and
adoption of an existing or imported key remain separate operations.

## Public template and signed CSR

`csr_template` creates a PKCS#10 template containing the retained public key,
the canonical DNS common name, and exactly the selected DNS/IP SAN extension.
Its signature is empty. It does not generate a throwaway private key.

`RetainedIngressKey::csr_request` returns the exact OpenBao request with an
explicit `version: "1"` on the wire, matching the narrow ACL's exact string
constraint. The retained version remains numeric version 1. OpenBao 2.5.5 accepts the public template at
`transit/keys/<retained-name>/csr`, replaces its key and signature internally,
and preserves the requested subject and extensions. The versioned source
parses the template without requiring an existing valid signature; the actual
CSR is produced by OpenBao's retained private key.

`validate_signed_csr` checks the returned subject, exact SANs, extension shape,
retained SPKI and ECDSA SHA-256 signature. It returns `ValidatedCsr`, whose DER
bytes can be passed unchanged to `marty_acme_client::protocol::Order::finalize_csr`.
Only the validated signed CSR belongs in an ACME finalization request. Its
metadata binds the installation, key version, SPKI digest, names and DER digest.

Primary references:

- [OpenBao 2.5 Transit API](https://openbao.org/docs/2.5.x/api/secret/transit/)
- [OpenBao 2.5.5 CSR parsing and request handler](https://github.com/openbao/openbao/blob/v2.5.5/builtin/logical/transit/path_certificates.go)
- [OpenBao 2.5.5 retained-key CSR creation](https://github.com/openbao/openbao/blob/v2.5.5/sdk/helper/keysutil/policy.go)

## Certificate admission and trust

Both admission functions require a bounded, leaf-first PEM chain and verify:

- Exact retained P-256 SPKI and DNS/IP SAN set, with no extra identity.
- An empty subject or the canonical DNS common name; an empty subject requires
  a critical SAN extension.
- A non-CA leaf, digital-signature-only key usage and server-auth-only extended
  key usage. Duplicate extensions and malformed or unsupported critical
  extensions are refused.
- Current validity, at least one hour remaining, and a total leaf lifetime no
  longer than 100 days. These are release admission bounds, not renewal timing.
- A cryptographically verified complete chain with exactly the supplied
  intermediates in order. Missing, duplicate, unrelated or unused members are
  refused. An optional final root must match the verified trust anchor and is
  removed from normalized fullchain output.

`admit_production` uses only the maintained Mozilla root set compiled by
`webpki-roots`. Host trust settings, returned chain roots and caller-supplied
staging roots cannot widen that set. Its metadata records
`trust_class: production_public`, the compiled root-set digest, the chosen
anchor's public-key digest, validity, and output digests.

`admit_staging_test` accepts explicitly supplied test roots, validates their CA
shape and self-signatures, and always reports `trust_class: staging_test` with
`public_chain_validated: false`. That remains true even if a supplied test root
also happens to be publicly trusted. Staging is never promoted implicitly.

`ValidatedCertificate` exposes public leaf/fullchain PEM and metadata. Neither
function claims activation, browser acceptance, revocation status or installation
readiness. In particular, successful public path validation is not proof of
HTTP challenge reachability or a successful browser visit.

The one-hour/100-day bounds accommodate Let's Encrypt's current 160-hour
`shortlived` profile, including its empty-subject certificate form. The
integrating owner must select and persist the intended profile and enforce any
narrower profile-specific lifetime and renewal policy. See the
[Let's Encrypt certificate profiles](https://letsencrypt.org/docs/profiles/)
and [IP certificate announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/).

## Installation handoff and verification

The owner must retain the exact identity, key/version/SPKI binding, signed CSR
bytes and digest, selected directory/profile, and account/order references
under the installation's existing lock and journal. It must validate the
returned chain before any certificate generation becomes active. Recovery,
atomic activation, persisted ARI scheduling and credential renewal belong to
the installation lifecycle; this module performs none of those mutations.
See [the ACME client contract](installer-acme-client.md) for the transport and
durable-order boundaries.

Ordinary tests cover custody, exact identity and CSR shape, adversarial SANs,
leaf usage, lifetime and closed PEM input. Positive cryptographic issuance is
covered by the opt-in
`official_openbao_signs_exact_public_template_and_chain_admission_keeps_staging_separate`
test with `MARTY_TEST_OPENBAO_EXECUTABLE` set to a verified OpenBao 2.5.5 binary.
It starts an ephemeral loopback TLS server, signs exact DNS-only, DNS/IPv4 and
DNS/IPv6 CSRs with a nonexportable Transit key, and issues test certificates
through an internal root and intermediate. It checks staging acceptance,
production refusal, chain tampering and retained-key rotation refusal. It
does not contact a live ACME CA or establish AWS, shipped-image, renewal or
reboot qualification.
