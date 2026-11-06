# Presentation Policy Open Badges verification and migration

Open Badges 3.0 is the only supported Open Badges format. The JSON proof path
uses the verifier-owned Trust Profile `resolved_verification_methods` projection
of trusted issuer relationships. A presented `document_store` never supplies
proof-key authority. Compact OB3 VC-JWTs retain their separately governed
outer-JWT verification path. Policy, status and holder-binding gates still apply.

## Open Badges 2.0 retirement

OB2 signed assertions, unsigned hosted assertions, and assertions transported
inside credential, presentation or JWT envelopes are rejected before issuer-key
resolution and policy evaluation. Mixed OB2/OB3 contexts are also rejected.
The old `assertion` request wrapper is also retired; submit an OB3 credential
using the `credential` field. The rejection directs the holder to request a newly
issued Open Badges 3.0 credential. The verifier produces no verified claims, issuer trust, status
acceptance or authenticated outer-JWT identifier from a retired assertion.

Native diagnostics advertise only `open_badges_v3`. Canvas readiness and signing
guards reject `OpenBadgeV2` template aliases, including snapshots whose readiness
was approved before retirement. Configure an OB3 template and obtain a fresh
readiness result before issuing a replacement badge. Do not rename the type or
context of an already signed OB2 credential: reissuance requires the issuer to
construct and sign a new OB3 credential from authoritative achievement evidence.
The shared native issuance boundary also rejects retired transaction types and
credential-document markers before allocating status or invoking any credential
builder, including generic SD-JWT and DIDComm delivery paths.
Cached credential replay, concurrent issuance recovery and pending DIDComm
transport apply the same rejection to the transaction and stored JSON or JWT
credential. Historical records and terminal delivery receipts remain intact;
retired credentials are neither returned as successful issuance nor resent.

The `governed_ob2.json` test fixture is retained only as an archived negative
vector. It proves that previously accepted signed badges and hosted variants
cannot regain acceptance through a different wrapper or native-format hint.
OB3 governed-key positive tests remain in place. The Open Badge browser flow
exercises OB3 issuance, verification and wallet display.
