# Legacy optional physical bureau callback K8s binding

This opt-in external-provider manifest is outside Marty's Rust-only simulator acceptance and is not deployed by the disposable flow below.

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

Render and validate the private manifest before applying it in a controlled
beta environment:

```sh
python scripts/render_passport_provider_k8s.py --image "$MARTY_SERVICES_IMAGE" > /tmp/passport-provider-supported.yaml
kubectl apply --dry-run=server -f /tmp/passport-provider-supported.yaml
kubectl apply -f /tmp/passport-provider-supported.yaml
```

The renderer rejects mutable tags, missing digests, and unresolved variables.
Run a callback smoke test through an internal route, then explicitly set
`PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=true` and
`PASSPORT_PROVIDER_INGRESS_SERVICE_URL=http://passport-provider-ingress:8021`
for a separate physical-provider acceptance run. The disposable Marty flow
below keeps this ingress disabled and uses only Rust passport services.

## Disposable Rust runtime identity preflight

The supported-consumer collector requires a Kubernetes identity plan before
it inspects a disposable namespace. The plan follows
`contracts/passport-supported-kubernetes-preflight.json` and records the exact
context, HTTPS API server, CA digest, namespace UID, and ConfigMap, Deployment,
and private Service UIDs. It binds the plan run ID to ownership labels and
simulator selectors. Its source commit and services image must match the
signed aggregate manifest. The read-only preflight checks those identities,
the selected Rust values in an immutable, run-scoped ConfigMap, and services
images pinned by digest. The identity plan contains only Rust passport services.
Services must be ClusterIP without external IPs, load balancer exposure, or
node ports. Each observed Pod must be owned by a ReplicaSet owned by the
expected Deployment UID. The collector requires a completed current rollout
with each Pod created after the
ConfigMap. It checks the running service process's routing flags through a
bounded Pod exec that emits only a fixed success marker, never environment
values. The disposable services image includes the shell and utilities used
for this check; a missing exec permission or utility blocks acceptance.
The collector repeats the full identity preflight
after runtime inspection, then repeats the simulator runtime probe. Both
passes reject physical-provider ingress and require Gateway and native
issuance to select Marty's simulator profile. Identity or routing drift blocks
the report.

Pass the plan with `--kubernetes-identity-plan` to the supported-consumer
collector, or run `scripts/check_passport_supported_kubernetes_model.py` on
its own. A matching operator-supplied plan is only static identity evidence.
It is not a protected plan attestation or a live nine-route test. Both outputs remain `blocked`; the preflight never
applies a manifest or changes a running owner.
