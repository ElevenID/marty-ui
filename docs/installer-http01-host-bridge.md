# Customer-managed HTTP-01 routing

The rootless installer publishes its independent challenge responder on
`127.0.0.1:<tls.http01_host_port>`. Public TCP port 80 must reach that responder
for both the canonical DNS name and any configured IP entry alias. The
application continues to use its configured HTTPS port. Opening only 8443 does
not provide HTTP-01 validation.

The supplied host units target Ubuntu 24.04 with systemd 255 and a dedicated
HTTP port 80. They use the host system manager to open the privileged socket;
the forwarding process has a dynamic unprivileged identity and no capabilities.
The responder remains a separate unprivileged Compose service. The installer
does not execute these administrator commands, modify AWS security groups,
change privileged-port sysctls, or grant capabilities to rootless Docker.

## Configure before enrollment

1. Choose a stable canonical DNS origin, its application listener, an optional
   exact IP entry alias, and an unused loopback challenge port at or above 1024.
   The example units use 18080. Keep the same value in `tls.http01_host_port` and
   the service's `ExecStart` destination.
2. Point the selected name's A/AAAA records at the host's reachable addresses.
   Each published address must serve the challenge. Remove an unusable AAAA
   record before enrollment instead of relying on an IPv4 fallback.
3. Make public TCP 80 and the selected HTTPS application port reachable in the
   customer firewall and AWS security group. Keep the Docker socket, OpenBao,
   databases and internal service ports private.
4. Inspect `deploy-config/host/marty-acme-http01.socket` and the matching
   `.service`. If another web service already owns port 80, route only the
   challenge path to the responder through that customer's existing service;
   do not start a competing socket. Use a single routing owner for this port.
5. An administrator copies the reviewed units into root-owned system storage
   and enables the socket:

```sh
sudo install -o root -g root -m 0644 deploy-config/host/marty-acme-http01.socket /etc/systemd/system/marty-acme-http01.socket
sudo install -o root -g root -m 0644 deploy-config/host/marty-acme-http01.service /etc/systemd/system/marty-acme-http01.service
sudo systemd-analyze verify /etc/systemd/system/marty-acme-http01.socket /etc/systemd/system/marty-acme-http01.service
sudo systemctl daemon-reload
sudo systemctl enable --now marty-acme-http01.socket
```

These are system units for the port-forwarding helper. Docker itself uses the
customer's **user** `docker.service`, with lingering enabled so it can start
without an interactive login. The forwarding helper shares the host network
namespace to reach the responder's loopback publication. Its 64-connection
limit bounds simultaneous forwarding; it is not application capacity evidence.

The socket opens both IPv4 and IPv6 independently. On an IPv4-only host with
kernel IPv6 disabled, remove the IPv6 `ListenStream` line and do not select an
IPv6 alias or publish AAAA records. No application or administrative route is
served over this HTTP listener: the responder admits only active challenge
GET/HEAD requests with the exact configured authority.

## Observe routing and recover a pending order

Use `systemctl status marty-acme-http01.socket marty-acme-http01.service` and
`journalctl -u marty-acme-http01.service` for the customer-managed bridge.
The service starts when traffic arrives. A running socket alone does not prove
Internet reachability, DNS correctness, or a valid challenge response.

The installer prints a retained continuation command when an order is pending:

```sh
/absolute/installation/marty-deploy acme status --install-dir /absolute/installation
/absolute/installation/marty-deploy acme continue --install-dir /absolute/installation --docker-bin /usr/bin/docker
```

Keep the recorded installation, exact operator and origin. A continuation uses
the same account and known order and does not recreate the initial keys or
setup jobs. Observe the recorded retry time before repeating a pending request.
An uncertain new-order creation remains a separate reconciliation hold; it is
not permission to create another account or order.

Staging requires an explicitly selected staging directory and a protected PEM
file passed through `--acme-staging-roots`. The admitted roots are retained with
that installation. A staging candidate is qualification evidence only and is
never selected as production TLS. Production uses the compiled public root
set and refuses the staging-root override.

## Verification boundary

The packaged units are syntax-checked with systemd 255. Socket forwarding,
public port-80 reachability, AWS firewall behavior, and reboot enablement still
require the composed-host qualification. The static unit files do not assert
that any host was changed or that the user service and socket are enabled.

## Primary references

- [systemd 255 socket proxy](https://www.freedesktop.org/software/systemd/man/255/systemd-socket-proxyd.html)
- [systemd 255 socket units and IPv6 binding](https://www.freedesktop.org/software/systemd/man/255/systemd.socket.html)
- [Rootless Docker user services and lingering](https://docs.docker.com/engine/security/rootless/tips/)
- [Let's Encrypt HTTP-01 requirements](https://letsencrypt.org/docs/challenge-types/)
