# Optional Cloudflare hosting

The core single-host package has no Cloudflare service, image, token, or account
requirement. Cloudflare Tunnel remains an explicit hosting integration for new
installations. It uses the same public-origin, managed OpenBao and keyless ingress
contracts as other hosting choices.

## Release prerequisite

For a new signed installation, the release producer must select
`publish_cloudflare_addon` in **Nightly installation release** or **Stack release**
for the stable version. The optional job runs after that workflow's core
publication. It publishes these separate immutable subjects:

- `selfhost-cloudflare-addon.zip`
- `selfhost-cloudflare-images.json`
- `cloudflared_wrapper.sbom.cdx.json`

Each subject has a `.sigstore.json` signature and `.provenance.jsonl` sidecar.
The add-on binds the exact core release tag, source commit, producer run and
attempt, one approved connector image digest, and every packaged runtime file.
The producer verifies image provenance, signature, and anonymous Linux amd64
pull before publication. A core-only release remains installable without these
optional assets. Selecting an unavailable or mismatched add-on fails closed.
An interrupted optional upload also leaves the complete core usable. Core
consumers ignore only the known optional asset names; unknown or duplicated
assets remain invalid. The selected connector alone is blocked until all of its
exact signed assets and proofs are available.
The installer derives the allowed signer workflow from the release tier. A
stable add-on must come from `cd.yml`; a nightly add-on must come from
`nightly-release.yml`. Both must use the core inventory's original producer run
and attempt. A later rerun or resumed publication cannot relabel an old core or
append an add-on from a different attempt. Select the add-on when producing the
release; if that exact producer cannot complete it, publish a new release.

The optional job supplies a distribution artifact; it does not qualify a live
Cloudflare route, grant installer admission, or turn a candidate into Ready.
The first release must still pass an actual external browser and login journey.

## Hosting selection

Use the signed installer's documented `--hosting-file` input. The connector
selection belongs in an `external-proxy` hosting configuration:

```json
{
  "schema": "elevenid.installation-hosting/v1",
  "mode": "external-proxy",
  "public_origin": "https://marty.example.com",
  "listener": {"bind_address": "127.0.0.1", "port": 8443},
  "tls": {"termination": "marty-keyless", "certificate_source": "managed-ca"},
  "connector": {
    "kind": "cloudflare-tunnel",
    "token_file": "/absolute/private/cloudflare.token"
  }
}
```

The token file must be private to its owner and outside the source checkout.
The installer copies it into its owned secret generation and records only a
digest. The connector receives a read-only file mount; its value must not be
placed in command-line arguments or diagnostic output.

Cloudflare owns frontend browser TLS. Marty retains the separately managed
keyless backend TLS identity. Configure the tunnel's public hostname route to
`https://installer-ingress:8443`, set the origin server name to the canonical
public hostname, preserve its canonical HTTP Host, and use
`/run/installer/ca.crt` as the connector's CA pool. The add-on mounts this public
CA file. Keep TLS verification enabled. The tunnel's remote routing configuration
is customer-owned and must agree with the selected hosting origin.

The connector adds no public host port. Direct hosting and existing external
proxy deployments do not download or start this add-on.

## Existing separately operated deployments

Existing retained installation models and historical releases stay unchanged.
Source-managed legacy production/beta deployments now select their old tunnel
wiring explicitly with `docker-compose.selfhost.cloudflare-legacy.yml`. Their
HTTP edge and beta proxy routing are preserved in that compatibility overlay.

`make selfhost-prod-cloudflare-up` starts the explicitly selected legacy primary
connector. Existing `selfhost-prod-beta-tunnel-*` targets include the compatibility
overlay automatically and continue operating only the selected beta services.

For legacy image-based composition, add
`docker-compose.selfhost.cloudflare-legacy.images.yml` and provide the approved
exact connector digest in `MARTY_CLOUDFLARED_IMAGE`; the new core image lock does
not supply that optional image. New signed installer deployments use the add-on
manifest and keyless route described above.
The legacy image build helper builds its wrapper only with
`BUILD_CLOUDFLARE_ADDON=true`; ordinary core builds omit it.

Kubernetes retains its separately operated optional connector manifest. Its
presence is no longer required by the core catalog or manifest preflight when
the connector is not selected. This cleanup does not qualify a new Kubernetes
package or controller implementation.
