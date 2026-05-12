# KMS UI & Implementation Gap Analysis

**Date:** 2026-04-17  
**Scope:** Full remote key management support across all Marty credential issuance, verification, and lifecycle flows — from UI surface through gateway API layer through Rust core.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully implemented (UI + API + backend) |
| 🔶 | Partially implemented — infrastructure exists but surface is incomplete |
| ❌ | Not yet implemented |

---

## Executive Summary

The gateway backend now has 20+ KMS endpoints covering service registration, signing, certificate lifecycle, JWKS/DID publication, rotation, holder keys, and format/purpose routing.

**The UI has not kept up.** `signingKeysApi.js` exposes only 9 of those endpoints, the `KeyManagementServiceWizard` does not collect `key_purposes`, `credential_formats`, `rotation_policy`, or travel-credential namespace fields, and the `SigningKeysPage` has no actions for certificate management, JWKS publication, per-service rotation, or holder-key management.

Additionally, the credential issuance flow has **no KMS service selector** — there is no mechanism in the credential template wizard or the trust profile editor to bind a specific KMS service to a credential format, so the "default service" concept is the only selection path, and format-based routing is silently unused from the UI.

Policy direction for the next phase is now explicit:
- The portal must never import or handle private keys.
- Key lifecycle operations are owned by the external KMS/HSM.
- did:web X.509 chaining must be gated to premium tier or self-hosted deployments.
- Delegated/chained developer-domain onboarding (for `dev.elevenidllc.com`) requires a dedicated implementation track.

---

## Gap Detail

### KMSUI-001 — API Client Completeness

**Priority:** HIGH  
**File:** `marty-ui/ui/src/services/signingKeysApi.js`  
**Status:** 🔶 9 of 21 gateway endpoints wired to client

**Gateway endpoints with no client call:**

| Endpoint | Purpose |
|---|---|
| `POST /v1/signing-keys/services/{id}/sign` | Ad-hoc payload signing via KMS |
| `POST /v1/signing-keys/services/{id}/publish-jwks` | Publish public key to org JWKS |
| `POST /v1/signing-keys/services/{id}/publish-did-vm` | Publish public key to org DID document |
| `GET /v1/signing-keys/services/{id}/certificate` | Retrieve stored certificate + chain |
| `PUT /v1/signing-keys/services/{id}/certificate` | Store signed certificate response |
| `POST /v1/signing-keys/services/{id}/certificate-csr` | Generate PKCS#10 CSR |
| `GET /v1/signing-keys/config/certificate-expiry-alerts` | List services with expiring certificates |
| `GET /v1/signing-keys/config/purposes` | List valid key purposes |
| `GET /v1/signing-keys/config/service-capabilities` | List provider capabilities per type |
| `POST /v1/signing-keys/config/resolve` | Resolve best service for format/purpose |
| `POST /v1/signing-keys/services/{id}/rotate` | Rotate per-service key (OpenBao) |
| `POST /v1/signing-keys/holder-keys` | Register wallet/holder binding key |
| `GET /v1/signing-keys/holder-keys` | List registered holder keys |
| `POST /v1/signing-keys/holder-keys/derive` | Derive holder binding key reference |
| `GET /v1/signing-keys/jwks` | Get org JWKS document |
| `GET /v1/signing-keys/did-document` | Get org DID document |
| `GET /v1/signing-keys/services/{id}/mdoc-x5c` | Get mDoc X.509 header material |

**Tasks:**
- [ ] `KMSUI-001-a` Add `publishServiceToJwks(serviceId)` → `POST /services/{id}/publish-jwks`
- [ ] `KMSUI-001-b` Add `publishServiceToDidVm(serviceId)` → `POST /services/{id}/publish-did-vm`
- [ ] `KMSUI-001-c` Add `getServiceCertificate(serviceId)` → `GET /services/{id}/certificate`
- [ ] `KMSUI-001-d` Add `setServiceCertificate(serviceId, data)` → `PUT /services/{id}/certificate`
- [ ] `KMSUI-001-e` Add `generateServiceCsr(serviceId, subjectFields)` → `POST /services/{id}/certificate-csr`
- [ ] `KMSUI-001-f` Add `getCertificateExpiryAlerts(threshold?)` → `GET /config/certificate-expiry-alerts`
- [ ] `KMSUI-001-g` Add `listKeyPurposes()` → `GET /config/purposes`
- [ ] `KMSUI-001-h` Add `listServiceCapabilities()` → `GET /config/service-capabilities`
- [ ] `KMSUI-001-i` Add `resolveSigningService(credentialFormat, keyPurpose, algorithm?)` → `POST /config/resolve`
- [ ] `KMSUI-001-j` Add `rotateServiceKey(serviceId, options?)` → `POST /services/{id}/rotate`
- [ ] `KMSUI-001-k` Add `registerHolderKey(keyData)` → `POST /holder-keys`
- [ ] `KMSUI-001-l` Add `listHolderKeys(filters?)` → `GET /holder-keys`
- [ ] `KMSUI-001-m` Add `deriveHolderBindingKey(serviceId, params)` → `POST /holder-keys/derive`
- [ ] `KMSUI-001-n` Add `getOrgJwks()` → `GET /jwks`
- [ ] `KMSUI-001-o` Add `getOrgDidDocument()` → `GET /did-document`
- [ ] `KMSUI-001-p` Add `getMdocX5cMaterial(serviceId)` → `GET /services/{id}/mdoc-x5c`
- [ ] `KMSUI-001-q` Add `signPayload(serviceId, payload)` → `POST /services/{id}/sign`

---

### KMSUI-002 — Service Registration Wizard Field Coverage

**Priority:** HIGH  
**File:** `marty-ui/ui/src/components/console/deploy/KeyManagementServiceWizard.jsx`  
**Status:** 🔶 Collects connection + auth + key reference; missing purpose, format, rotation, and namespace fields

The wizard sends these fields to the gateway:
`service_type`, `name`, `endpoint`, `region`, `mount`, `namespace`, `auth_mode`, `auth_reference`, `key_reference`, `key_aliases`, `algorithms`

The gateway `_normalize_registered_service()` also recognises and uses:
`key_purposes`, `credential_formats`, `rotation_policy` (`rotation_interval_days`, `overlap_days`, `auto_publish`), `country_code`, `authority_code`

None of these are collected by the wizard, so:
- All services have empty `key_purposes` → format/purpose routing never selects them by purpose
- All services have empty `rotation_policy` → rotation endpoint has nothing to act on for auto-rotation
- Travel credential services have no country/authority namespace → VDS-NC and regulated credentials cannot be attributed to an authority

**Tasks:**
- [ ] `KMSUI-002-a` Add **Key purposes** multi-select step (or sub-section in Key Access step) with all defined purposes (`vc_jwt_issuer`, `mdoc_dsc`, `x509_doc_signer`, `holder_binding`, `presentation_signing`, `vdsnc_signing`, `jwks_signing`)
- [ ] `KMSUI-002-b` Add **Credential formats** derived display (auto-populated from purposes; allow override) — `jwt_vc_json`, `dc+sd-jwt`, `mso_mdoc`, `zk_mdoc`, `vds_nc`
- [ ] `KMSUI-002-c` Add **Rotation policy** section in Key Access step: interval in days, overlap days, auto-publish toggle
- [ ] `KMSUI-002-d` Add **Country/Authority** fields shown only when purpose includes `vdsnc_signing`, `mdoc_dsc`, `x509_doc_signer`
- [ ] `KMSUI-002-e` Pass all new fields through `createKeyManagementServicePayload()` in `keyManagementServiceCatalog.js`
- [ ] `KMSUI-002-f` Add wizard validation for key purpose–algorithm compatibility (e.g., warn if `mdoc_dsc` selected with RS256)

---

### KMSUI-003 — Service Registry Actions (SigningKeysPage)

**Priority:** HIGH  
**File:** `marty-ui/ui/src/components/console/deploy/SigningKeysPage.jsx`  
**Status:** 🔶 Shows service cards; only actions are "Make default" and "Remove"

Missing per-service actions that map directly to implemented gateway endpoints:

| Missing Action | Gateway Endpoint | When Needed |
|---|---|---|
| Publish to JWKS | `POST /services/{id}/publish-jwks` | After registering any JWT/SD-JWT issuer service |
| Publish to DID document | `POST /services/{id}/publish-did-vm` | After registering any DID-bound issuer service |
| Generate CSR | `POST /services/{id}/certificate-csr` | For mDoc DSC or X.509 doc-signer services |
| Upload certificate | `PUT /services/{id}/certificate` | After external CA signs the CSR |
| View certificate | `GET /services/{id}/certificate` | Audit / expiry check |
| Rotate key | `POST /services/{id}/rotate` | Production key lifecycle |
| View mDoc x5c material | `GET /services/{id}/mdoc-x5c` | Debug / verify mDoc issuance chain |
| Test sign (dev mode) | `POST /services/{id}/sign` | Connectivity smoke-test |

Missing page-level panels:

| Missing Panel | Source | When Needed |
|---|---|---|
| Certificate expiry alerts | `GET /config/certificate-expiry-alerts` | Ops dashboard / notifications |
| JWKS preview | `GET /jwks` | Confirm published keys before going live |
| DID document preview | `GET /did-document` | Confirm verification methods |
| Format/purpose routing map | `keyManagementConfig.format_defaults`, `type_defaults` | Multi-format issuer orgs |

**Tasks:**
- [ ] `KMSUI-003-a` Add **Certificate management panel** to `ServiceCard`: CSR generation button, certificate upload, view/expiry badge
- [ ] `KMSUI-003-b` Add **Publish keys** action to `ServiceCard` for JWT/SD-JWT/DID-bound services: calls publish-jwks + publish-did-vm
- [ ] `KMSUI-003-c` Add **Rotate key** action to `ServiceCard` (for OpenBao services; disabled with tooltip for cloud KMS)
- [ ] `KMSUI-003-d` Add **Certificate expiry alerts panel** at page level (shows services expiring within threshold)
- [ ] `KMSUI-003-e` Add **JWKS preview** expandable panel — fetches and renders org JWKS JSON
- [ ] `KMSUI-003-f` Add **DID document preview** expandable panel — fetches and renders org DID document JSON
- [ ] `KMSUI-003-g` Add **Format routing configuration panel** — lets admin set `format_defaults` (per-format → service) and `type_defaults` (per-credential-type → service)
- [ ] `KMSUI-003-h` Show `key_purposes` and `credential_formats` on service cards from normalized service data
- [ ] `KMSUI-003-i` Show `rotation_policy` summary on service card when present

---

### KMSUI-013 — Portal Key Custody Guardrails

**Priority:** HIGH  
**File:** `marty-ui/ui/src/components/console/deploy/SigningKeysPage.jsx`  
**Status:** 🔶 In progress (policy partially enforced in UI)

Portal UX must enforce metadata-only registration and must not expose private key creation/import/deletion flows.

**Tasks:**
- [x] `KMSUI-013-a` Remove portal-native key upload/create entry points from Signing Keys UI.
- [x] `KMSUI-013-b` Remove portal-native key delete and direct key-level rotation actions from key inventory.
- [ ] `KMSUI-013-c` Remove or deprecate unused native key CRUD client methods from `signingKeysApi.js` once backend compatibility window closes.
- [ ] `KMSUI-013-d` Add copy and runbook links that direct all key lifecycle steps (generate, rotate, revoke, destroy) to external KMS/HSM procedures.
- [ ] `KMSUI-013-e` Add an explicit policy banner in wizard and service pages: "Marty stores connector metadata only; private keys never enter the portal."

---

### KMSUI-014 — did:web X.509 Chaining Entitlement Gate

**Priority:** HIGH  
**File:** `marty-ui/ui/src/components/console/deploy/SigningKeysPage.jsx` and DID onboarding surfaces  
**Status:** 🔶 Partially implemented (initial CTA gating added)

did:web X.509 chain management is a deployment/plan capability and must be consistently gated.

**Tasks:**
- [x] `KMSUI-014-a` Disable trust-chain setup CTA unless organization is self-hosted or on premium plan tier.
- [ ] `KMSUI-014-b` Centralize entitlement resolution in a shared hook (plan tier + deployment mode + future feature flags).
- [ ] `KMSUI-014-c` Apply the same gate in `DidIdentitiesPage` and DID creation/edit wizard so users see consistent behavior.
- [ ] `KMSUI-014-d` Add upgrade/self-host guidance panel for blocked orgs, including documentation links.

---

### KMSUI-015 — Delegated Developer Domain Chaining (`dev.elevenidllc.com`)

**Priority:** MEDIUM-HIGH  
**File:** Multi-surface (DID onboarding, domain validation, trust chain UX)  
**Status:** ❌ Not implemented

Developer onboarding for delegated/chained domains requires first-class workflows beyond current trust-profile shortcuts.

**Tasks:**
- [ ] `KMSUI-015-a` Define supported delegated-domain models (`did:web` direct host, delegated subdomain, chained x5c authority) and validation rules.
- [ ] `KMSUI-015-b` Add domain ownership + DNS proof UX for delegated subdomains (starting with `dev.elevenidllc.com`).
- [ ] `KMSUI-015-c` Add chain-assembly guidance (leaf/intermediate/root) tied to key records, not trust profile ownership.
- [ ] `KMSUI-015-d` Add publish/verify preflight checks to confirm JWKS + DID document + certificate chain consistency.
- [ ] `KMSUI-015-e` Add rollout strategy with environment guards (developer sandbox, hosted pilot, self-host production).

---

### KMSUI-004 — Credential Template KMS Binding

**Priority:** HIGH  
**File:** `marty-ui/ui/src/components/console/templates/` (credential template wizard)  
**Status:** ❌ No signing service selector in credential template creation or editing

Credential templates define `credential_format` (`jwt_vc_json`, `dc+sd-jwt`, `mso_mdoc`, `zk_mdoc`). The gateway's `POST /config/resolve` endpoint can return the right signing service for a format+purpose combination. However:
- The credential template wizard has no field for `signing_service_id` override
- There is no call to `POST /config/resolve` during template creation to suggest the right service
- When a template has `mso_mdoc` format, there is no prompt to ensure a DSC (document signer certificate) service is linked

**Tasks:**
- [ ] `KMSUI-004-a` Add **Signing service** selector step/field in credential template wizard — calls `POST /config/resolve` to suggest the best match, but allows manual override
- [ ] `KMSUI-004-b` Add warning when selected service algorithm does not match format requirements (e.g., RS256 for mso_mdoc)
- [ ] `KMSUI-004-c` For `mso_mdoc`/`zk_mdoc` templates, add DSC service field + certificate expiry indicator
- [ ] `KMSUI-004-d` Store `signing_service_id` on credential template model and pass through to issuance request

---

### KMSUI-005 — Trust Profile KMS Integration

**Priority:** HIGH  
**File:** `marty-ui/ui/src/components/console/trust/`  
**Status:** 🔶 `KeyLocationSelector` collects `kmsArn` + `kmsRegion` for trust sources; not connected to signing service registry

The trust profile wizard has a `KeyLocationSelector` component that accepts `IssuerKeySource.KMS` with `kmsArn` and `kmsRegion`. This is a legacy standalone KMS field that is not connected to the signing service registry. When a trust profile references a KMS key, there is no way to:
- Look up which registered signing service owns that ARN
- Know whether the certificate has been installed
- Trigger JWKS/DID publication from the trust profile editor

**Tasks:**
- [ ] `KMSUI-005-a` Update `KeyLocationSelector` to offer a "From signing service registry" option that shows a dropdown of registered services (calls `GET /config` to list them)
- [ ] `KMSUI-005-b` When a signing service is selected, auto-populate `kmsArn`/`kmsRegion`/`endpoint` from the service record
- [ ] `KMSUI-005-c` Show certificate status inline (valid / missing / expiring) for X.509-backed trust sources
- [ ] `KMSUI-005-d` Add **Publish to JWKS** shortcut action inside trust profile editor for KMS-backed trust sources

---

### KMSUI-006 — Holder Key Management

**Priority:** MEDIUM  
**File:** `marty-ui/ui/src/` — no holder key UI exists  
**Status:** ❌ No UI surface for holder key registration, listing, or derivation

The gateway has:
- `POST /v1/signing-keys/holder-keys` — register wallet/holder binding key
- `GET /v1/signing-keys/holder-keys` — list keys
- `POST /v1/signing-keys/holder-keys/derive` — derive binding key reference from KMS service

Device-bound credentials (`mso_mdoc`, `zk_mdoc`) require holder binding keys. These are currently registered only programmatically.

**Tasks:**
- [ ] `KMSUI-006-a` Add **Holder keys** sub-page or tab within Deploy / Signing Keys section
- [ ] `KMSUI-006-b` Show list of registered holder keys with purpose, associated credential format, expiry
- [ ] `KMSUI-006-c` Add holder key registration form (for server-managed wallets; key material input or derivation from KMS)
- [ ] `KMSUI-006-d` Add key derivation UI for server-managed holder binding key derivation from registered KMS service

---

### KMSUI-007 — DID Identity Page KMS Integration

**Priority:** MEDIUM  
**File:** `marty-ui/ui/src/components/console/deploy/DidIdentitiesPage.jsx` (inferred from route)  
**Status:** 🔶 DID identities exist as a separate page; no connection to signing service publication flow

When a DID identity is created or updated, the corresponding signing service public key must be published to the DID document as a `verificationMethod`. Currently these are disconnected concepts.

**Tasks:**
- [ ] `KMSUI-007-a` Add **Signing service** selector on DID identity detail/edit page — links a DID to a registered signing service
- [ ] `KMSUI-007-b` Add **Publish verification method** action that calls `POST /services/{id}/publish-did-vm` and updates the DID document record
- [ ] `KMSUI-007-c` Show publication status badge (published / unpublished / stale) based on comparison of service public key vs DID document content

---

### KMSUI-008 — Issuance Flow Signing Service Visibility

**Priority:** MEDIUM  
**File:** `marty-ui/ui/src/components/console/operate/IssuancePage.jsx` (inferred)  
**Status:** ❌ Issuance UI has no visibility into which signing service will be used

When an operator manually triggers credential issuance from the console, there is no indication of which KMS service will sign the credential or confirmation that the service is healthy.

**Tasks:**
- [ ] `KMSUI-008-a` Add signing service health indicator on issuance confirmation view — resolves via `POST /config/resolve` + `POST /config/validate`
- [ ] `KMSUI-008-b` For mDoc credentials, show DSC certificate expiry warning on issuance screen if cert expires within 30 days
- [ ] `KMSUI-008-c` Add issuance dry-run option that uses `POST /services/{id}/sign` with test payload to validate signing connectivity before actual issuance

---

### KMSUI-009 — VDS-NC / Regulated Travel Credential UI

**Priority:** MEDIUM  
**File:** `marty-ui/ui/src/` — no VDS-NC specific UI  
**Status:** ❌ No UI for VDS-NC signing key registration with country/authority namespacing

The gateway supports `vdsnc_signing` and `csca` key purposes with `country_code`/`authority_code` fields, but there is no UI path that exposes these fields.

**Tasks:**
- [ ] `KMSUI-009-a` Add VDS-NC signing service registration flow — either as a dedicated wizard step or a sub-section in `KeyManagementServiceWizard` shown when `vdsnc_signing` purpose is selected
- [ ] `KMSUI-009-b` Show CSCA/IACA trust chain status alongside VDS-NC signing service registration
- [ ] `KMSUI-009-c` Add country-code–scoped service listing in `SigningKeysPage` (grouped by authority/country when present)

---

### KMSUI-010 — Gateway: Issuance Route KMS Integration

**Priority:** HIGH  
**File:** `marty-ui/services/gateway/routes/issuance.py`  
**Status:** ❌ Issuance route does not call signing service registry or KMS adapters

The signing_keys gateway routes implement the complete KMS adapter layer, but the `issuance.py` route (which orchestrates credential issuance) does not:
- Call `_resolve_service_for_format()` to select the right signing service
- Call `_get_adapter()` to get the KMS adapter
- Invoke `adapter.sign()` for the credential payload
- Pass x5c material for mDoc/ZK-mDoc formats

Without this wiring, even though all the KMS adapter infrastructure is in place, actual credential issuance still uses a different signing path (likely local keys or a hardcoded approach) rather than routing through the registered KMS services.

**Tasks:**
- [ ] `KMSUI-010-a` In `issuance.py`, add `_select_signing_service(org_id, credential_format, key_purpose)` helper that calls the signing_keys registry resolver
- [ ] `KMSUI-010-b` Wire `adapter.sign()` into the JWT/SD-JWT issuance signing path
- [ ] `KMSUI-010-c` Wire `adapter.sign()` into the mDoc COSE signing path (replace or supplement existing Rust call)
- [ ] `KMSUI-010-d` For mDoc/ZK-mDoc, fetch x5c material from `GET /services/{id}/mdoc-x5c` and pass to Rust core
- [ ] `KMSUI-010-e` Add fallback: if no registered KMS service matches, fall back to local key or return 503 with actionable error

---

### KMSUI-011 — Gateway: Missing `GET /signing-keys/:keyId` and Single-Key Operations

**Priority:** LOW-MEDIUM  
**File:** `marty-ui/services/gateway/routes/signing_keys.py`  
**Status:** ❌ No `GET /v1/signing-keys/{keyId}`, `PATCH /v1/signing-keys/{keyId}`, `DELETE /v1/signing-keys/{keyId}` endpoints

`signingKeysApi.js` calls `getSigningKey(keyId)`, `updateSigningKey(keyId, updates)`, `deleteSigningKey(keyId)` — none of these have corresponding gateway route handlers. The UI silently fails on individual key operations.

**Tasks:**
- [ ] `KMSUI-011-a` Add `GET /v1/signing-keys/{key_id}` — return single key metadata from adapter
- [ ] `KMSUI-011-b` Add `PATCH /v1/signing-keys/{key_id}` — update key metadata (name, status, aliases)
- [ ] `KMSUI-011-c` Add `DELETE /v1/signing-keys/{key_id}` — deregister/deprecate a key

---

### KMSUI-012 — Notifications and Webhooks for KMS Events

**Priority:** LOW  
**File:** `marty-ui/ui/src/services/webhooksApi.jsx`, `marty-ui/services/gateway/routes/`  
**Status:** 🔶 Webhook event types for `trust.certificate_issued` and `trust.certificate_expiring` exist; no KMS-specific events

**Missing webhook event types:**
- `signing_key.rotated` — key was rotated; downstream verifiers should update trust anchors
- `signing_key.certificate_expiring` — signing certificate expires within threshold
- `signing_key.published` — public key published to JWKS/DID document
- `signing_key.service_unreachable` — KMS adapter connectivity check failed

**Tasks:**
- [ ] `KMSUI-012-a` Define KMS webhook event types in gateway event emitter
- [ ] `KMSUI-012-b` Add KMS event types to webhook management UI event selector

---

## Format × KMS UI Coverage Matrix

| Credential Format | Service Registration | Signing Service Binding | Certificate Lifecycle | JWKS/DID Publication | Issuance Integration |
|---|---|---|---|---|---|
| `jwt_vc_json` | ✅ wizard | ❌ no template binding | ❌ no UI | ❌ no UI action | ❌ gateway not wired |
| `dc+sd-jwt` | ✅ wizard | ❌ no template binding | ❌ no UI | ❌ no UI action | ❌ gateway not wired |
| `mso_mdoc` | 🔶 wizard (missing DSC purpose) | ❌ no template binding | ❌ no UI | ❌ no UI action | ❌ gateway not wired |
| `zk_mdoc` | 🔶 wizard (missing DSC purpose) | ❌ no template binding | ❌ no UI | ❌ no UI action | ❌ gateway not wired |
| VDS-NC | ❌ no wizard path | ❌ | ❌ | ❌ | ❌ |

---

## Implementation Priority Order

| Order | Gap | Effort | Impact |
|---|---|---|---|
| 1 | KMSUI-013 Portal key custody guardrails | Medium | **Enforces no-private-key policy in product UX** |
| 2 | KMSUI-010 Gateway issuance route KMS wiring | Large | **Unblocks actual KMS-signed credential issuance** |
| 3 | KMSUI-014 did:web X.509 chaining entitlement gate | Small-Medium | Prevents unsupported setup paths |
| 4 | KMSUI-001 signingKeysApi client completeness | Small | Prerequisite for all UI actions |
| 5 | KMSUI-003 Service registry actions in SigningKeysPage | Medium | Operators can complete service setup without API access |
| 6 | KMSUI-002 Wizard key purposes + rotation + namespace | Medium | Correct service selection for multi-format orgs |
| 7 | KMSUI-004 Credential template KMS binding | Medium | Per-template signing service selection |
| 8 | KMSUI-005 Trust profile KMS integration | Medium | Coherent key source selection in trust profiles |
| 9 | KMSUI-007 DID identity publication flow | Small | DID resolution correctness |
| 10 | KMSUI-006 Holder key management | Medium | Device-bound credential support |
| 11 | KMSUI-008 Issuance flow signing visibility | Small | Operator confidence before issuing |
| 12 | KMSUI-009 VDS-NC travel credential UI | Medium | Regulated travel credential issuance |
| 13 | KMSUI-015 Delegated developer domain chaining | Medium-Large | Unlocks delegated onboarding under shared domains |
| 14 | KMSUI-011 Single-key CRUD endpoints | Small | UI stability (currently silently fails) |
| 15 | KMSUI-012 KMS webhook events | Small | Operational alerting |

---

## Tracking

**Total gap tasks:** 68  
**Completed:** 3  
**Remaining:** 65  

**Prerequisite relationship:**  
`KMSUI-001` (API client) must precede `KMSUI-003`, `KMSUI-005`, `KMSUI-006`, `KMSUI-007`, `KMSUI-008`.  
`KMSUI-002` (wizard fields) must precede `KMSUI-004` (template binding uses purposes from services).  
`KMSUI-010` (gateway issuance wiring) is independent of UI and is the highest-value single item.
