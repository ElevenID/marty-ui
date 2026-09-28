# Beta passport ceremony credentials

The opt-in simulator profile reads separate DSC and CSCA operator credentials
from files. These credentials authenticate Gateway to Signing Keys after an
operator session and organization permission check. They are not signing keys:
issuer-profile private keys and passport cryptographic operations remain in
managed KMS. No external CA or bureau is selected by this profile.

Before selecting `-EnablePassportNative`, prepare a private absolute directory
whose final component is `elevenid-beta-passport-ceremony`. Put two distinct,
single-line, 32–256 character ASCII values in files named
`dsc_issue_gateway_key` and `csca_issue_gateway_key`. Use letters, digits,
periods, underscores, or hyphens; do not add a trailing newline. Bind the
directory path as `PASSPORT_BETA_CEREMONY_SECRET_DIR` in the generated beta env
file. Do not put either credential value in an env file. The selector checks
the source files and rendered Compose model before any image or service
mutation; only Gateway and Signing Keys may mount them.

This wiring does not authorize a ceremony by itself. The CSCA and DSC routes
still require separate authenticated operator sessions with the correct
organization grants. The beta acceptance probe must verify the public X.509
chain, followed by the aggregate beta deployment, soak, and recorded demo.
The disposable rehearsal uses its own generated files and does not supply
beta credentials.
