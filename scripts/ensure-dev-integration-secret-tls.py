"""Provision a disposable local TLS identity for the remote secret endpoint.

The CA signing key exists only while issuing the leaf. The output directory is
ignored by Git and is renewed before its short-lived certificate expires.
"""

from pathlib import Path
import ipaddress
import os
import ssl
import subprocess
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / ".dev-integration-secret-tls"
FILES = ("ca.crt", "tls.crt", "tls.key")


def openssl(*arguments: str, config: Path | None = None) -> bool:
    environment = os.environ.copy()
    if config is not None:
        environment["OPENSSL_CONF"] = str(config)
    try:
        result = subprocess.run(
            ("openssl", *arguments),
            env=environment,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def identity(server_name: str) -> tuple[str, str, str]:
    try:
        ipaddress.ip_address(server_name)
    except ValueError:
        if server_name != "signing-keys":
            raise ValueError("unsupported development TLS DNS name") from None
        return "DNS:signing-keys", "-verify_hostname", server_name
    if server_name != "127.0.0.1":
        raise ValueError("unsupported development TLS IP address")
    return "IP:127.0.0.1", "-verify_ip", server_name


def valid(output: Path, server_name: str = "signing-keys") -> bool:
    ca, cert, key = (output / name for name in FILES)
    _, verify_option, expected_name = identity(server_name)
    if not all(path.is_file() and not path.is_symlink() for path in (ca, cert, key)):
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError):
        return False
    return (
        openssl("x509", "-checkend", "86400", "-noout", "-in", str(cert))
        and openssl(
            "verify",
            "-CAfile",
            str(ca),
            "-purpose",
            "sslserver",
            verify_option,
            expected_name,
            str(cert),
        )
        and openssl("x509", "-checkend", "86400", "-noout", "-in", str(ca))
    )


def ensure_tls(output: Path = OUTPUT, server_name: str = "signing-keys") -> None:
    san, _, _ = identity(server_name)
    if output.is_symlink():
        raise ValueError("development TLS directory must not be a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.chmod(0o700)
    if valid(output, server_name):
        return
    existing = tuple((output / name).exists() for name in FILES)
    if any(existing) and not all(existing):
        raise ValueError("development TLS identity is incomplete")
    if any((output / name).is_symlink() for name in FILES):
        raise ValueError("development TLS identity must not contain symlinks")
    with TemporaryDirectory(prefix=".integration-secret-tls-", dir=output) as temporary:
        work = Path(temporary)
        config = work / "openssl.cnf"
        config.write_text(
            "[req]\ndistinguished_name=req_distinguished_name\n"
            "[req_distinguished_name]\n",
            encoding="ascii",
        )
        if not openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=Marty Development Secret Transport CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(work / "ca.key"),
            "-out",
            str(work / "ca.crt"),
            config=config,
        ):
            raise RuntimeError("could not create development TLS CA")
        if not openssl(
            "req",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-subj",
            f"/CN={server_name}",
            "-keyout",
            str(work / "tls.key"),
            "-out",
            str(work / "tls.csr"),
            config=config,
        ):
            raise RuntimeError("could not create development TLS server key")
        (work / "tls.ext").write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n",
            encoding="ascii",
        )
        if not openssl(
            "x509",
            "-req",
            "-in",
            str(work / "tls.csr"),
            "-CA",
            str(work / "ca.crt"),
            "-CAkey",
            str(work / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(work / "tls.crt"),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(work / "tls.ext"),
            config=config,
        ):
            raise RuntimeError("could not issue development TLS server certificate")
        if not valid(work, server_name):
            raise RuntimeError("development TLS server certificate failed verification")
        for name in FILES:
            destination = output / name
            (work / name).replace(destination)
            # Compose's file-backed secret is read by the non-root service UID.
            # The ignored parent remains owner-traversable only on POSIX hosts.
            destination.chmod(0o644)


if __name__ == "__main__":
    ensure_tls()
    print(f"Development integration-secret TLS identity ready in {OUTPUT}")
