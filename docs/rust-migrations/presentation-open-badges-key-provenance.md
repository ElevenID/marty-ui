# Presentation Policy Open Badges key provenance

For JSON OB2 and OB3 policy evaluation, proof keys come from the verifier-owned
Trust Profile `resolved_verification_methods` projection of trusted issuer
relationships. The presented `document_store` is never a source of proof-key
authority: OB3 ignores it, while OB2 may use it only to resolve badge and issuer
references. OB2 overwrites the exact signed `verification.creator` entry with
the governed key and rejects missing or ambiguous governed key evidence.
When a signed OB2 assertion names an issuer directly, it must exactly equal
the governed key controller; case-folding a DID or URL path is not proof of
identity.
The signed OB2 payload must match the assertion after removing the signature.
For legacy credentials that appended verification instructions after signing,
only an otherwise exact signed payload and exactly `{type, creator}` instructions
(`signed` or `signedbadge`) are accepted; unsigned claim changes still fail.
Claims projected from OB2 badge and issuer references use only signed assertion
fields, not holder-supplied reference-document metadata. The compact VC-JWT
route retains its separately governed outer-JWT verification path.

Core can parse unsigned hosted OB2 assertions, but Presentation Policy reports
them as unverified, with no verified claims or issuer trust. A standard signed
OB2 assertion may sign only a BadgeClass reference; its signature can verify,
but an issuer named solely by holder-supplied BadgeClass/Profile documents is
not authenticated issuer evidence. Positive issuer trust for that form awaits
governed BadgeClass/Profile document resolution and binding. This change does
not relax policy, status, or holder-binding gates.
