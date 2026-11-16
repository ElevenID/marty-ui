"""Exercise secret-read failures at the shipped shell-to-service boundary."""

from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
LOADERS = [
    "scripts/load-secrets-env.sh",
    "deploy/helm/marty/files/keycloak/load-secrets-env.sh",
]


@pytest.mark.parametrize("loader", LOADERS)
@pytest.mark.parametrize("entrypoint", [
    '. "$1" && exec "$2"',
    'set -e; . "$1" && exec "$2"',
    'set -e; . "$1"; exec "$2"',
])
@pytest.mark.parametrize("partial_output", ["", "partial-private-file-value"])
def test_failed_secret_read_never_launches_the_service_or_discloses_output(
    tmp_path, loader, entrypoint, partial_output,
):
    # A selected file can pass stat/access checks and then fail while being
    # read. The controlled reader models both an immediate and a partial read
    # failure, without needing a damaged host filesystem.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    reader = bin_dir / "tr"
    reader.write_text(
        "#!/bin/sh\nprintf '%s' \"$PARTIAL_READ\"\n"
        "printf '%s' 'private-reader-diagnostic' >&2\nexit 1\n"
    )
    reader.chmod(0o755)
    secret = tmp_path / "service-token"
    secret.write_text("complete-private-file-value\n")
    marker = tmp_path / "service-started"
    child = tmp_path / "service"
    child.write_text('#!/bin/sh\nprintf started > "$STARTUP_MARKER"\n')
    child.chmod(0o755)

    result = subprocess.run(
        ["/bin/sh", "-c", entrypoint, "startup-test", str(ROOT / loader), str(child)],
        env={
            "PATH": str(bin_dir) + ":/usr/bin:/bin",
            "GRPC_SERVICE_TOKEN_FILE": str(secret),
            "PARTIAL_READ": partial_output,
            "STARTUP_MARKER": str(marker),
        },
        capture_output=True, text=True, check=False, timeout=5,
    )

    assert result.returncode != 0
    assert not marker.exists()
    assert result.stdout == ""
    assert result.stderr == "Secret file for GRPC_SERVICE_TOKEN could not be read before startup.\n"


@pytest.mark.parametrize("loader", LOADERS)
def test_optional_empty_file_remains_a_successful_explicit_disable(tmp_path, loader):
    secret = tmp_path / "optional-public-setting"
    secret.write_text("\r\n\n")
    result = subprocess.run(
        ["/bin/sh", "-c", '. "$1" && test -z "$GOOGLE_SITE_VERIFICATION" '
         '&& test -z "${GOOGLE_SITE_VERIFICATION_FILE+x}"',
         "startup-test", str(ROOT / loader)],
        env={"PATH": "/usr/bin:/bin", "GOOGLE_SITE_VERIFICATION_FILE": str(secret)},
        capture_output=True, text=True, check=False, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
