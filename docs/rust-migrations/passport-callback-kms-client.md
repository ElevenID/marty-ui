# Native passport callback KMS cutover gate

`PASSPORT_KMS_CALLBACKS_ENABLED` defaults to `false`. When enabled on native
issuance, the callback handler no longer loads either form of
`PERSONALIZATION_BUREAU_WEBHOOK_SECRET`. It requires the existing internal
signing-keys service credential and sends the original callback body and
versioned signature to the tenant-bound KMS verifier. Only a positive result
constructs a verified callback; the repository still matches the signed
`organization_id` to the durable job before updating it. The repository also
ignores stale progress callbacks and polled bureau states, as well as updates
to terminal jobs, returning the unchanged job idempotently as recorded in
`contracts/passport-webhook-progress-behavior.json`. This protects both legacy
and KMS-verified callbacks and subsequent polls from status reversal. Invalid signatures
remain 401, invalid events 422, and KMS outages 503. There is no legacy-secret
fallback in KMS mode.

The provider contract is
`contracts/passport-bureau-callback-kms-behavior.json` in the provider PR.
This consumer must not be enabled until that provider is merged, its
non-exportable OpenBao HMAC key and policy are provisioned, and the beta-only
bureau emits callbacks using the versioned signature and signed tenant fields.
The current beta overlay still uses the legacy file-backed webhook secret and
is **not** a KMS-only activation configuration. Existing outbound bureau APIs
and default-off legacy callback behavior are unchanged.
