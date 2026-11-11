# Isolated final testing

The workbench creates its own PostgreSQL, HTTPS OpenBao, packaged Keycloak,
test realm/accounts, captured-mail inbox and a dedicated signed Open Badge
fixture. It uses the native `11id` theme and passkey implementation. It does
not connect to or change the held elevenidllc deployment.

From the repository root, with the qualified local images and Python test tools:

```powershell
py -3.12 scripts/run_passkey_test_lab.py --keycloak-image marty-passkey-keycloak:native-26.8 --openbao-image marty-kms-final-openbao:d7285b9
```

The launcher prints a localhost URL when ready, plus a private output folder.
Open that page for the generated usernames/passwords, account-console link,
captured enrollment/recovery mail, Google setup and credential downloads.
The lab lasts 20 minutes by default; `--minutes` accepts 1â€“30. Close lab stops
the interactive window early. The launcher then finishes the custody regression
and removes its disposable containers/network. Keep the terminal process alive
during testing; do not reuse production accounts, credentials or RP IDs.

The output folder contains `lab-accounts.json`, `openbadge.jwt`, its decoded
credential, public issuer/holder details and `RESULT-TEMPLATE.md`. The issuer
and holder use separate non-exportable lab Transit keys, distinct from OAuth
signing keys. OpenBao verifies the issued JWT signature before export. Public
issuer material must be registered through the governed test trust-profile
path; a presented document never establishes issuer trust. A working wallet,
Marty presentation policy and actual credential-login journey remain separate
integration requirements. The badge account's mail action tests the native
Keycloak enrollment portion of that path.

Use standalone desktop Edge or Chrome and sign in with the password account first.
Choose **Signing in → Set up Passkey → REGISTER**, then complete the browser
prompt using Windows Hello or a hardware key. Sign out
and use a private browser window to prove a fresh passkey login. Rename the
key, add another, and remove one. For the password-free account, use the local
mail action and captured link. Test cancellation and native removal confirmation;
Keycloak permits final-passkey deletion, so retain a working fallback/recovery
method. Capture actual results in the template.
Label real test keys clearly. Closing the lab removes its server-side records;
remove only the corresponding lab entries from your authenticator afterward.

The Test broker option uses a separate native OIDC identity in the disposable
fixture. It prepares a broker account and exercises account continuity; actual
Google qualification remains open. To connect real Google, create a separate
web OAuth client with the exact redirect URI shown in the workbench, then enter
its client ID/secret into the local form. Do not send them to chat. See the
[version-matched Google setup](https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/identity-broker/social/google.adoc).

Desktop localhost is a secure browser context. Native phone enrollment and
cross-device authentication need suitable devices and a trusted HTTPS test
origin; do not waive certificate checks or assume a virtual authenticator proves
those cases. Real device prompts require user participation. The lab's seeded
accounts, broker simulator and fixture do not by themselves complete the real
Google/Open Badge/application/device acceptance matrix.

The workbench smoke probe verifies its seeded broker account can enroll without
a local password, retains the same account, and can use the captured-mail UI:

```powershell
py -3.12 scripts/probe_passkey_test_lab.py <private-lab-output-folder>
```

Run it before handing the lab to a person. It removes only the virtual key it
created, leaving the account available for that person's real device. The
synthetic credential follows the [Open Badges3 credential example](https://www.imsglobal.org/spec/ob/v3p0).

For the automated combined PostgreSQL/two-node/KMS proof:

```powershell
$env:MARTY_PASSKEY_PACKAGED_IMAGE='marty-passkey-keycloak:native-26.8'
$env:MARTY_PASSKEY_PACKAGED_OPENBAO_IMAGE='marty-kms-final-openbao:d7285b9'
py -3.12 -m pytest -q -s tests/test_keycloak_passkey_packaged.py
```
