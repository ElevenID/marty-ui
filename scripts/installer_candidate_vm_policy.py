"""Exact disposable Ubuntu guest bootstrap policy shared by seed and probe."""

GUEST_USER = "installer"
# Engineering bootstrap policy; installed acceptance records actual package
# identities and source before it may qualify a release.
PACKAGES = {
    "openssh-server": "1:9.6p1-3ubuntu13.20",
    "docker.io": "29.1.3-0ubuntu3~24.04.2",
    "docker-compose-v2": "2.40.3+ds1-0ubuntu1~24.04.1",
    "containerd": "2.2.1-0ubuntu1~24.04.4",
    "runc": "1.3.4-0ubuntu1~24.04.1",
}
