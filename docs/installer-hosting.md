# Configurable hosting for the signed installer

The signed installer can keep its private localhost endpoint, expose its owned
HTTPS ingress on a selected host address, or sit behind an external HTTPS
proxy. Hosting configuration is independent of key custody: omitting
`--foundation-file` continues to select managed OpenBao. Choosing an AWS VM,
another cloud, a private server, or Cloudflare does not select AWS KMS.

Use a newly published signed nightly that contains this implementation. A
source checkout or an older installer does not gain these options automatically.
Candidate installation remains experimental: its journal stays `Provisioning`,
and it does not claim installer admission, browser qualification, or production
readiness. The existing Linux amd64, regular user, no-new-privileges, and
pre-existing rootless Docker requirements still apply. See
[installer bootstrap](installer-bootstrap.md).

## Select the access path

| Mode | Browser address | Owned host listener | Public TLS owner | Local Cloudflare container |
| --- | --- | --- | --- | --- |
| `local` | `https://localhost:<selected-port>` by default | Loopback only | Marty keyless ingress | None |
| `direct` | Configured HTTPS DNS name or IPv4 address | Explicit non-loopback IP and unprivileged port | Marty keyless ingress | None |
| `external-proxy` | Configured public HTTPS origin | Explicit backend listener | The external proxy; Marty retains keyless backend TLS | Only with the explicit `cloudflare-tunnel` connector |

No hosting file preserves automatic localhost port selection. For an explicit
local port, use `mode: "local"`, a matching `https://localhost:18443` origin,
and `listener: {"bind_address":"127.0.0.1","port":18443}` with the same TLS
selection as the examples below.

The schema is `elevenid.installation-hosting/v1`. Unknown keys and unsupported
mode combinations are refused. Origins must be canonical HTTPS authorities:
lowercase ASCII DNS names or standard IPv4 literals, with no credentials, path,
query, fragment, trailing slash, or wildcard. Omit `:443` for the standard HTTPS
port. Public IPv6 literal origins are refused before provisioning because the
application's current `did:web` authority contract does not support them. A DNS
origin can use an IPv6 listener, such as `"bind_address":"::"`, when the host
and network support it. Low-level IPv6 TLS checks do not establish an installed
IPv6 application journey. Host listener ports must be at least 1024; the
installer does not change host sysctls or grant privileged-port access.

`public_origin` controls the UI/API URLs, credential issuer URL, CORS origin,
Keycloak hostname, and OIDC callback/logout URLs. `listener` controls the socket
published by the rootless Docker host. For example, public HTTPS port 443 can
map to backend host port 8443. That mapping belongs to the selected network or
proxy setup. Changing only the JSON URL does not create a port-forwarding rule.

## Direct AWS or other VM hosting

Start with [the direct example](examples/installation-hosting.direct.json):

```json
{
  "schema": "elevenid.installation-hosting/v1",
  "mode": "direct",
  "public_origin": "https://marty.example.com:8443",
  "listener": {"bind_address": "0.0.0.0", "port": 8443},
  "tls": {"termination": "marty-keyless", "certificate_source": "managed-ca"}
}
```

A provider-assigned public IPv4 address can be used as the origin host instead, for
example `https://203.0.113.10:8443`; replace this documentation address with the
current address of the intended host. The certificate then needs that exact IP
SAN, which the managed issuer creates. A DNS origin receives its configured DNS
SAN. When a provider maps a public IP to a private interface, bind to an actual
local interface address or `0.0.0.0`, not to an address absent from the VM.

The operator must configure DNS, any provider address mapping, and the cloud and
host firewall for the chosen ingress port. Publish only the owned ingress;
OpenBao, Keycloak, gateway diagnostics, databases, and internal service ports do
not become public through this setting. Keep the configured address stable for
the installation. A changed public IP needs reviewed configuration/certificate
replacement; changing an environment file by hand is not a supported repair.

Marty does not create a VM, paid upgrade, address reservation, load balancer,
security-group rule, or DNS record. An existing 8 GiB test instance can retain
its size for this work; that does not establish production capacity.

## Existing reverse proxy, load balancer, or Cloudflare proxy

Use [the external proxy example](examples/installation-hosting.external-proxy.json)
when another component owns browser-facing HTTPS:

```json
{
  "schema": "elevenid.installation-hosting/v1",
  "mode": "external-proxy",
  "public_origin": "https://marty.example.com",
  "listener": {"bind_address": "127.0.0.1", "port": 8443},
  "tls": {"termination": "marty-keyless", "certificate_source": "managed-ca"}
}
```

This loopback example is for a proxy on the same host. A proxy on another host
needs a reachable backend address and explicit network restrictions. Choose a
proxy that can verify the exported backend CA and certificate hostname, configure
HTTPS to the selected listener, and send the canonical HTTP Host. Forwarding to
an HTTPS target alone does not establish certificate verification; a load
balancer that skips target-certificate validation does not satisfy this backend
trust requirement. The owned edge still
performs keyless TLS; `tls.termination` describes that backend. The
`external-proxy` mode identifies the separate public TLS owner.

Cloudflare DNS-only service can resolve a direct deployment without a tunnel
container. For Cloudflare's reverse proxy, standard
[Full (strict) mode](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/)
does not automatically accept Marty's managed private CA. A verified origin
chain accepted by Cloudflare or its separately configured
[Custom Origin Trust Store](https://developers.cloudflare.com/ssl/origin-configuration/custom-origin-trust-store/)
is required. That trust-store feature has separate availability requirements;
the installer does not enable or purchase it. The explicit Tunnel add-on below
supports the managed CA through its `caPool` setting. Do not disable origin
certificate verification to make a proxy connect.

For an external proxy, browser trust is determined by the frontend certificate.
Marty does not claim custody of its private key or infer that the public route
works from a healthy backend.

Incoming forwarding headers are not trusted as authority. Marty pins the
canonical Host, HTTPS scheme, and public port from the configuration and strips
caller-supplied forwarding headers at its owned edge. Client-IP attribution
through a proxy/rootless network is not qualified by this feature. The installer
disables gateway client-IP observation, and ingress leaves client-IP headers
absent. Session rate limits and the existing anonymous unknown-client bucket
remain enforced. Do not treat an internal proxy address as the original client.

## Optional Cloudflare Tunnel for new installations

[The Cloudflare Tunnel example](examples/installation-hosting.cloudflare-tunnel.json)
adds this field to `external-proxy`:

```json
"connector": {
  "kind": "cloudflare-tunnel",
  "token_file": "/home/marty/private/cloudflare-tunnel-token"
}
```

The token file must be a regular, operator-owned 0600 file in a private 0700
directory. Supply the token through the existing secret-management process.
Do not put its value in the hosting JSON, a shell command, source control, or a
diagnostic report. The installer checks and copies the selected token through
its existing scalar credential owner and mounts a readonly container-readable
projection inside the private installation. Evidence contains its digest and
file reference, never its contents.

Only this explicit connector selection downloads and verifies the separate
signed Cloudflare add-on, admits its pinned connector image, and merges its
Compose layer. Core installations do not require a Cloudflare token or run the
connector. Existing Cloudflare deployments remain an available architecture;
this feature does not automatically migrate or adopt an old manually managed
stack into the signed installer.

Configure the tunnel's remote public-hostname route consistently:

| Setting | Value for the example |
| --- | --- |
| Public hostname | `marty.example.com` |
| Backend service URL | `https://installer-ingress:8443` |
| HTTP Host override | `marty.example.com` (the configured public authority) |
| Origin TLS server name | `marty.example.com` (host only, without a port) |
| Backend CA pool | `/run/installer/ca.crt` |
| TLS certificate verification | Enabled |

The add-on mounts the selected backend CA at that CA-pool path. Do not enable
`noTLSVerify`. The installer does not modify the provider's remote routing
configuration. Connector readiness proves its observed readiness endpoint, not
the remote route's hostname, TLS settings, public reachability, or a browser
login. Verify those separately from the actual browser-facing network.

## Run the exact signed candidate

Save the chosen complete JSON as an absolute path, for example
`/home/marty/private/hosting.json`, with mode 0600 in a private 0700 directory.
Both tag placeholders below must identify the same newly published nightly:

```sh
/usr/bin/setpriv --no-new-privs -- bash -o pipefail -c 'curl -fsSL https://github.com/ElevenID/marty-ui/releases/download/vX.Y.Z-nightly.YYYYMMDD.RUN_ID/install.sh | sh -s -- --candidate-test vX.Y.Z-nightly.YYYYMMDD.RUN_ID --hosting-file /home/marty/private/hosting.json'
```

Omit `--foundation-file` to keep managed OpenBao. The same `--hosting-file`
option is forwarded by admitted `--version` and `--channel` paths; those paths
still require their independent signed admission. The bootstrap verifies the
selected operator and inventory, and the operator verifies payloads before
runtime provisioning. An unsigned development launcher is a separate tool and
does not substitute for this command.

The installer validates configuration before confirmation, records the source
and selection hashes in private evidence, and binds the selection in its
journal before certificate provisioning or ingress exposure. It prints the
selected origin, listener, TLS owner, and connector in the host-impact summary.
Do not patch the generated Compose model, environment, certificate files, or
journal to change hosting: later operations verify their recorded bindings.

An existing AWS KMS foundation remains available. Combine it with an explicit
hosting file using `tls.certificate_source: "foundation-import"`, and require
the two files' public origins to match. `managed-ca` plus a foundation, or
`foundation-import` without one, is refused. The imported certificate must
already cover the selected origin and match its preprovisioned signer. A legacy
foundation without a hosting file retains its existing loopback behavior.

## Inspect the installation and open the browser

Use the verified operator retained at the installation path printed during
installation:

```sh
/absolute/installation/marty-deploy status --install-dir /absolute/installation
/absolute/installation/marty-deploy doctor --install-dir /absolute/installation
/absolute/installation/marty-deploy trust-info --install-dir /absolute/installation
/absolute/installation/marty-deploy validate --install-dir /absolute/installation
```

`status` reports journal history. `doctor` observes the recorded runtime.
`trust-info` exports recorded certificate material and its bindings without
installing trust. Its `origin` is the browser URL; `local_probe_address` is the
owned local listener used by validation, and `certificate_scope` distinguishes
`public-ingress` from an external proxy's `backend`. A local successful HTTPS
probe does not prove public access. `public_endpoint_observed` remains false in
the trust export. Likewise, `restart_history_observed: false` and
`oom_kill_history_observed: false` mean those histories were not observed; they
do not mean zero restarts or OOM events.

For direct access, open the exact `origin` after checking the provider routing
and firewall. For `local` mode on a remote VM, establish an SSH tunnel from the
browser's computer with the same local and remote port. For an origin of
`https://localhost:18443`, for example:

```sh
ssh -N -o ExitOnForwardFailure=yes -L 18443:127.0.0.1:18443 marty-host
```

Use the existing authenticated SSH alias/configuration for that host; add its
`-F /absolute/ssh_config` option when needed. Keep the tunnel running, then open
`https://localhost:18443`. Opening the VM's public IP does not reach a listener
that was intentionally bound to loopback.

With `managed-ca` on local or direct ingress, the browser does not automatically
trust the installation's private CA. Obtain `ca_certificate_pem` and the
`ca_der_sha256` fingerprint through the authenticated operator/SSH route,
compare the fingerprint of the exported CA, and explicitly add only that CA to
the intended test browser or operating-system trust store. Use the exact origin
covered by the certificate. The installer never edits browser or host trust,
and certificate-warning bypasses are not trust verification.

With `external-proxy`, the browser must trust the frontend certificate. The
exported Marty CA authenticates the proxy-to-Marty backend and does not replace
the frontend certificate. After configuration, test the actual public URL,
login redirect, callback, logout, and credential workflow in a browser. Those
observations are separate from installer status and local validation.

## Scope and remaining work

This schema accepts `managed-ca` or the existing `foundation-import` path. It
does not accept uploaded TLS private keys, arbitrary public certificate files,
or an ACME option. Managed public-certificate enrollment needs a separately
reviewed prepare-CSR, attach-matching-chain, activation, and renewal lifecycle
for the nonexportable ingress key. Do not relabel a private managed CA as a
publicly trusted certificate.

For a fresh managed installation, the native generation owner now uses the
scoped renewal identity to produce and validate the selected ingress certificate
and signer token alongside the existing workload credentials. The existing
generation selector binds these files, and native Compose starts the application
with that selected generation. `trust-info` reports the selected ingress leaf
and its metadata, which can differ from the earlier bootstrap certificate.

The renewal principal retains certificate-issuing authority for the exact
configured DNS or IP identity. Its ACL fixes the name/SAN and lifetime
parameters, while the renewal helper and immutable generation checks bind the
selected certificate to the retained Transit public key. The ACL does not
restrict the public key inside an arbitrary CSR: a compromised renewal
principal could directly obtain a certificate for the same permitted identity
using another key. The activation checks would reject that replacement, so
renewal credentials must be protected as issuer credentials.

This is the initial generation handoff. Repeated automatic renewal/cutover and
an installed journey across the expiry boundary are not implemented or
qualified by this hosting feature. Check `certificate_expires_at` and
`recorded_token_expires_at` for the selected ingress; do not infer an unattended
continuous-runtime guarantee from initial startup. Root retirement and recovery
retain their separate evidence and qualification requirements. Neither a
longer-lived frontend certificate nor a healthy connector proves that backend
credentials have renewed. Preserve uncertain state for review.

The hosting inputs separate public identity, listener exposure, TLS ownership,
and connector selection so later Kubernetes Service/Gateway/Ingress adapters
can consume the same intent. This implementation's installer runtime is
rootless Compose. It does not install a Kubernetes cluster or claim that the
new hosting modes have passed Kubernetes or production qualification.
