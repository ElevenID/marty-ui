# iOS Wallet Routing & Scheme-Collision Strategy

> **Problem.** On iOS, multiple wallets register the same custom URL schemes
> (`openid4vp://`, `openid-credential-offer://`). When more than one is installed,
> iOS shows an OS-level chooser — or, worse, silently routes to whichever wallet
> registered the scheme last. Custom schemes are **not** deterministic on iOS.
>
> **Only deterministic same-device routing on iOS is HTTPS Universal Links**
> (Apple App Site Association). Custom schemes remain the fallback when a vendor
> has not published an AASA file.

This document is the operator/runbook reference for how Marty handles this.
Update it whenever the wiring changes.

---

## 1. Routing layers (in priority order)

For both **login (OID4VP)** and **issuance (OID4VCI)**, the credential-login
page and wallet-offer dialog try, in order:

1. **Digital Credentials API** (W3C `navigator.credentials.get({digital: ...})`)
   — preferred when the browser advertises support
   (`DigitalCredential.userAgentAllowsProtocol(...)`). The OS picks the wallet;
   no deeplink is emitted. This sidesteps the scheme collision entirely.
2. **Per-wallet HTTPS Universal Link** (when configured) — deterministic; iOS
   routes directly to the vendor's bundle id via AASA.
3. **Raw protocol scheme** (`openid4vp://...`, `openid-credential-offer://...`,
   or Android `intent://...;scheme=openid4vp;...`) — fallback. iOS may show a
   chooser if multiple wallets are installed.
4. **User preference persistence** — the credential-login page remembers the
   user's last-picked wallet/platform in `localStorage`, so a returning user
   gets one tap to their known wallet without re-prompting.

---

## 2. Login (OID4VP) — auth service

**File:** `marty-ui/services/auth/infrastructure/adapters/http_adapter.py`

### Per-wallet env hooks

Set these in `.env.tunnel.beta.local` (or any environment file) when a vendor
publishes an AASA. Empty/unset means "use raw `openid4vp://`".

| Wallet    | Env var                                                  |
| --------- | -------------------------------------------------------- |
| SpruceKit | `CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE` |
| LISSI     | `CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE`     |

The template **must** include `{request_uri_encoded}` and should include
`{client_id_param}` plus `{request_uri_method_param}` so the outer OID4VP
identity and POST retrieval mode remain bound to the signed Request Object.
The adapter adds these parameters to older request-URI-only templates at
runtime, but new templates should be explicit. Example:

```bash
CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE=https://wallet.spruceid.com/openid4vp?{client_id_param}{request_uri_method_param}request_uri={request_uri_encoded}
```

LISSI's compatibility Request Object uses a bare DID verifier identity. Marty
only offers the LISSI route when the standard flow was created with a DID-based
`client_id`; `redirect_uri`, `x509_hash`, and HAIP verifier identities remain on
their standard wallet routes and are never rewritten silently.

The adapter resolves templates in this order, per platform:

- **iOS** → `*_IOS_UNIVERSAL_LINK_TEMPLATE` → `*_IOS_TEMPLATE` → generic template.
- **Android** → `*_ANDROID_TEMPLATE` (intent: scheme).
- **Web/desktop** → generic template.

See `_credential_login_wallet_template()` and `_build_credential_login_wallet_options()`.

### Persistence keys (localStorage)

Set by the credential-login page JS (asset version bumped to force refresh):

| Key                              | Value                              |
| -------------------------------- | ---------------------------------- |
| `marty.credential_login.wallet`  | wallet `id` (e.g. `sprucekit`)     |
| `marty.credential_login.platform`| `auto` \| `ios` \| `android` \| `web` |

`restoreWalletPreference()` reads them on page load; `syncWalletLaunch()` and
`persistPlatformPreference()` write on change. Bump
`_CREDENTIAL_LOGIN_ASSET_VERSION` whenever the JS changes so browsers refetch.

### Tests

`marty-ui/services/auth/tests/test_oidc_claims_and_http_user.py`:

- `test_credential_login_js_persists_wallet_and_platform_preferences`
- `test_build_credential_login_wallet_options_uses_ios_universal_link_when_env_set`

---

## 3. Issuance (OID4VCI) — credential_template service

**File:** `marty-ui/services/credential_template/main.py` and the
`wallet_registry` table in schema `credential_template_service`.

### Per-wallet `universal_link_template` column

The `wallet_registry` row carries a nullable `universal_link_template` column
(see migration `20260503_0001_add_wallet_routing_metadata.py`). When set, it is
promoted by `_wallet_routing_templates()` to the `web` and `ios` slots in the
routing payload, taking precedence over the raw protocol fallback.

Example update for SpruceKit once an AASA is published:

```sql
UPDATE credential_template_service.wallet_registry
SET universal_link_template = 'https://wallet.spruceid.com/credential-offer?credential_offer_uri={offer_uri_encoded}'
WHERE wallet_id = 'wr-spruce-001';
```

`{offer_uri_encoded}` is the only required placeholder.

### Schema-based fallback

`_is_wallet_routing_template()` excludes raw protocol schemes
(`openid-credential-offer`, `openid4vp`, `haip-vci`, `haip-vp`) so the registry
keeps emitting the unencoded `openid-credential-offer://?credential_offer_uri=...`
shape on iOS when no Universal Link is configured. Android keeps the
`intent://...;scheme=openid-credential-offer;package=<bundle>;end` shape, which
is deterministic on Android via package targeting.

---

## 4. UI client (wallet-offer dialog)

**Files:**
- `marty-ui/ui/src/services/credentialLinkUtils.js`
- `marty-ui/ui/src/application/applications/walletOfferDialogUseCases.js`

The known-route fallback for SpruceKit uses **raw** `openid-credential-offer://`
on iOS/web and `intent://...;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end`
on Android. `PROTOCOL_ROUTE_SCHEMES` filters protocol schemes from
`isWalletRoutingTemplate()` so they aren't mistakenly treated as HTTPS routes.

If the registry returns a `universal_link_template`, the UI will use it ahead of
the known-route fallback.

---

## 5. Operator runbook — adding a Universal Link for a wallet

When a wallet vendor publishes their AASA (e.g. `https://wallet.example.com/.well-known/apple-app-site-association`):

1. **Login (OID4VP):** add the env var to `marty-ui/.env.tunnel.beta.local`:
   ```bash
   CREDENTIAL_LOGIN_<WALLET>_IOS_UNIVERSAL_LINK_TEMPLATE=https://wallet.example.com/openid4vp?{client_id_param}{request_uri_method_param}request_uri={request_uri_encoded}
   ```
   Bump `_CREDENTIAL_LOGIN_ASSET_VERSION` only if the JS itself changes; env
   changes do not require an asset bump but **do** require an auth restart:
   ```powershell
   docker compose --env-file .env.tunnel.beta.local `
     -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.tunnel.yml `
     up -d --no-deps auth
   make beta-tunnel-refresh-upstreams
   make beta-public-ui-check
   ```
2. **Issuance (OID4VCI):** update the `wallet_registry` row:
   ```sql
   UPDATE credential_template_service.wallet_registry
   SET universal_link_template = 'https://wallet.example.com/credential-offer?credential_offer_uri={offer_uri_encoded}'
   WHERE wallet_id = '<wallet-id>';
   ```
   No restart required (read on each request).
3. **Verify**:
   ```powershell
   Invoke-WebRequest -Uri 'https://beta.elevenidllc.com/v1/auth/credential-login' -UseBasicParsing | Select-Object -ExpandProperty Content | Select-String 'data-ios-link'
   ```
   Confirm the iOS link is the `https://...` Universal Link, not `openid4vp://`.

---

## 6. Why custom schemes can't fix this

iOS gives no API to express "prefer this wallet for this scheme." The OS picks
based on install order and shows a chooser only sometimes. SpruceKit Mobile, per
[`SameDeviceOID4VP.md`](https://github.com/spruceid/sprucekit-mobile), registers
**only** `openid4vp://` for OID4VP and `openid-credential-offer://` for OID4VCI.
The `spruceid://` scheme opens the app shell but does **not** route into the
flow. Path-based shapes like `spruceid://openid4vp/authorize?...` are ignored.

Universal Links are the only Apple-sanctioned way to bind an HTTPS URL to a
specific bundle id. Until a vendor publishes an AASA we are stuck with the OS
chooser; user-preference persistence (Section 2) reduces the impact for repeat
users.

---

## 7. Files referenced

- [marty-ui/services/auth/infrastructure/adapters/http_adapter.py](../services/auth/infrastructure/adapters/http_adapter.py)
- [marty-ui/services/credential_template/main.py](../services/credential_template/main.py)
- [marty-ui/services/credential_template/infrastructure/migrations/versions/20260503_0001_add_wallet_routing_metadata.py](../services/credential_template/infrastructure/migrations/versions/20260503_0001_add_wallet_routing_metadata.py)
- [marty-ui/ui/src/services/credentialLinkUtils.js](../ui/src/services/credentialLinkUtils.js)
- [marty-ui/ui/src/application/applications/walletOfferDialogUseCases.js](../ui/src/application/applications/walletOfferDialogUseCases.js)
- [marty-ui/services/auth/tests/test_oidc_claims_and_http_user.py](../services/auth/tests/test_oidc_claims_and_http_user.py)
