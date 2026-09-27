# Supported physical bureau callback K8s binding

`k8s/oracle/07c-passport-provider-supported.yaml` stages the trusted provider
ingress and a separate production-mode KMS callback signer. The normal
`deploy-kubernetes.sh` path does not apply this opt-in manifest. The Gateway
provider selector remains false by default.

Provision three distinct Secrets in `marty-prod`: `passport-provider-webhook`
with key `secret`, `passport-callback-signer-api` with key `api_key`, and
`passport-callback-signer-bao-token` with key `token`. Only the signer mounts
the OpenBao token; only ingress mounts the provider webhook secret. The signer
API key must be at least 32 characters and differ from both the provider
secret and ordinary signing credential. Verify the actual token has only the
`passport-callback-hmac-service` policy and the intended HMAC capability.

The registered physical provider profile ID in `marty-config`, the native
`marty-secrets` database URL, and an immutable `MARTY_SERVICES_IMAGE` digest
must be available. Verify the cluster's CNI enforces NetworkPolicy. The
manifest admits only Gateway to ingress and only ingress to signer; the signer
uses outbound access to the configured external OpenBao endpoint. Neither
service is publicly exposed.

Apply the private manifest in a controlled beta environment, run a callback
smoke test through an internal route, then explicitly set
`PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=true` and
`PASSPORT_PROVIDER_INGRESS_SERVICE_URL=http://passport-provider-ingress:8021`
for the physical-provider acceptance run. Keep Python as the rollback owner
until that gate passes. Roll back by disabling the Gateway selector before
removing the opt-in manifest.
