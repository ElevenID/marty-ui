"""Synthetic, non-VM checks for the closed Ubuntu package admission boundary."""
import datetime as dt
import hashlib
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_package_admission as admission


def _row(name="rootlesskit", version="1.1.1-1ubuntu0.24.04.3", data=b"deb"):
    return {"Package": name, "Version": version, "Architecture": "amd64",
            "Filename": f"pool/universe/r/{name}/{name}_{version}_amd64.deb",
            "SHA256": hashlib.sha256(data).hexdigest(), "Size": str(len(data)),
            "Depends": "uidmap"}


def test_package_index_and_deb_chain_rejects_digest_path_and_duplicates(tmp_path):
    row = _row()
    plain = ("\n".join(f"{key}: {value}" for key, value in row.items()) + "\n\n").encode()
    compressed = lzma.compress(plain)
    index = tmp_path / "Packages.xz"
    index.write_bytes(compressed)
    hashes = {"universe/binary-amd64/Packages.xz":
              (len(compressed), admission.sha(compressed))}
    selected = admission.select_package(admission.verify_index(index, hashes, "universe"),
                                        row["Package"], row["Version"])
    deb = tmp_path / "package.deb"
    deb.write_bytes(b"deb")
    assert admission.verify_deb(deb, selected)["sha256"] == row["SHA256"]
    with pytest.raises(admission.Refused, match="digest"):
        admission.verify_index(index, {"universe/binary-amd64/Packages.xz":
                                       (len(compressed), "0" * 64)}, "universe")
    with pytest.raises(admission.Refused, match="ambiguous"):
        admission.select_package([row, row], row["Package"], row["Version"])
    with pytest.raises(admission.Refused, match="reference"):
        admission.select_package([{**row, "Filename": "../foreign.deb"}],
                                 row["Package"], row["Version"])
    deb.write_bytes(b"bad")
    with pytest.raises(admission.Refused, match="digest"):
        admission.verify_deb(deb, selected)


def test_simulation_rejects_existing_change_unknown_action_and_dependency():
    admitted = {"uidmap": "1:4.13+dfsg1-4ubuntu3.2", "rootlesskit": "1.1.1-1ubuntu0.24.04.3"}
    transcript = (b"Reading package lists...\nBuilding dependency tree...\n"
                  b"Reading state information...\n"
                  b"Inst uidmap (1:4.13+dfsg1-4ubuntu3.2 Ubuntu:24.04/noble-updates [amd64])\n"
                  b"Inst rootlesskit (1.1.1-1ubuntu0.24.04.3 Ubuntu:24.04/noble-updates [amd64])\n"
                  b"Conf rootlesskit (1.1.1-1ubuntu0.24.04.3 Ubuntu:24.04/noble-updates [amd64])\n"
                  b"Conf uidmap (1:4.13+dfsg1-4ubuntu3.2 Ubuntu:24.04/noble-updates [amd64])\n")
    assert len(admission.inspect_simulation(transcript, {"docker.io": "29.1.3"}, admitted)) == 2
    for changed in (transcript.replace(b"Inst uidmap", b"Remv uidmap"),
                    transcript.replace(b"Inst uidmap", b"Inst docker.io"),
                    transcript.replace(b"Inst uidmap", b"Inst foreignkit"),
                    transcript.replace(b"Conf uidmap", b"Conf docker.io")):
        with pytest.raises(admission.Refused):
            admission.inspect_simulation(changed, {"docker.io": "29.1.3"}, admitted)


def test_read_refuses_special_link_and_growth(tmp_path):
    value = tmp_path / "value"
    value.write_bytes(b"ok")
    assert admission.private_file(value, 4) == b"ok"
    with pytest.raises(admission.Refused):
        admission.private_file(value, 1)
    os.link(value, tmp_path / "other")
    with pytest.raises(admission.Refused):
        admission.private_file(value, 4)
    (tmp_path / "link").symlink_to(value)
    with pytest.raises(admission.Refused):
        admission.private_file(tmp_path / "link", 4)
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(admission.Refused):
        admission.private_file(tmp_path / "pipe", 4)


def test_https_source_is_closed_and_refuses_redirect_oversize(monkeypatch):
    assert admission.fixed_url("noble-updates", "dists/noble-updates/InRelease") == (
        "https://archive.ubuntu.com/ubuntu/dists/noble-updates/InRelease")
    for pocket, relative in (("foreign", "dists/noble/InRelease"),
                             ("noble", "../secret"),
                             ("noble", "dists/noble-security/InRelease")):
        with pytest.raises(admission.Refused):
            admission.fixed_url(pocket, relative)
    redirect = admission._NoRedirect()
    with pytest.raises(admission.Refused, match="redirect"):
        redirect.redirect_request(None, None, 302, "redirect", {}, "https://foreign.example/")

    class Response:
        status = 200
        def __init__(self, raw):
            self.raw = raw
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def geturl(self):
            return admission.fixed_url("noble", "dists/noble/InRelease")
        def read(self, count):
            part, self.raw = self.raw[:count], self.raw[count:]
            return part
    class Opener:
        def __init__(self, raw):
            self.raw = raw
        def open(self, request, timeout):
            return Response(self.raw)
    monkeypatch.setattr(admission.urllib.request, "build_opener", lambda *args: Opener(b"x" * 4))
    assert admission.fetch_fixed("noble", "dists/noble/InRelease",
                                 admission.MAX_INRELEASE) == b"x" * 4
    monkeypatch.setattr(admission.urllib.request, "build_opener",
                        lambda *args: Opener(b"x" * (admission.MAX_INRELEASE + 1)))
    with pytest.raises(admission.Refused, match="oversized"):
        admission.fetch_fixed("noble", "dists/noble/InRelease",
                              admission.MAX_INRELEASE)


def test_exclusive_bundle_record_refuses_partial_retry(tmp_path):
    private = tmp_path / "bundle"
    private.mkdir(mode=0o700)
    record = admission._publish_file(private, "record", b"opaque")
    assert admission.private_file(record, 6) == b"opaque"
    with pytest.raises(FileExistsError):
        admission._publish_file(private, "record", b"other")
    (private / "orphan").write_bytes(b"x")
    with pytest.raises(admission.Refused, match="fresh"):
        admission.acquire_verified_bundle(private, tmp_path / "keyring", dt.datetime.now(dt.timezone.utc))


@pytest.mark.skipif(not Path("/usr/bin/gpg").exists(), reason="requires Linux gpg")
def test_real_gpgv_signature_wrong_key_and_stale_release(tmp_path, monkeypatch):
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    env = {"GNUPGHOME": str(home), "PATH": "/usr/bin", "LC_ALL": "C"}
    subprocess.run(["/usr/bin/gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                    "Synthetic Ubuntu Archive <synthetic@example.invalid>", "rsa2048", "sign", "0"],
                   env=env, capture_output=True, check=True, timeout=30)
    fingerprint = subprocess.run(["/usr/bin/gpg", "--batch", "--with-colons", "--list-keys"],
                                 env=env, capture_output=True, check=True, timeout=10).stdout
    fpr = next(line.split(b":")[9].decode() for line in fingerprint.splitlines()
               if line.startswith(b"fpr:"))
    keyring = tmp_path / "keyring.gpg"
    keyring.write_bytes(subprocess.run(["/usr/bin/gpg", "--batch", "--export", fpr],
                                       env=env, capture_output=True, check=True).stdout)
    now = dt.datetime.now(dt.timezone.utc)
    date = now.strftime("%a, %d %b %Y %H:%M:%S UTC")
    release = (f"Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble-updates\nCodename: noble\n"
               f"Date: {date}\nArchitectures: amd64 arm64\nComponents: main universe\n"
               f"SHA256:\n {'0'*64} 4 universe/binary-amd64/Packages.xz\n")
    unsigned = tmp_path / "Release"
    unsigned.write_text(release)
    signed = tmp_path / "InRelease"
    signed.write_bytes(subprocess.run(["/usr/bin/gpg", "--batch", "--armor", "--clearsign",
                                      "--output", "-", str(unsigned)], env=env,
                                     capture_output=True, check=True).stdout)
    original = admission.private_file
    monkeypatch.setattr(admission, "private_file", lambda p, limit, uid=None: original(p, limit))
    monkeypatch.setattr(admission, "ARCHIVE_FINGERPRINT", fpr)
    observation, hashes = admission.verify_inrelease(signed, keyring, "noble-updates", now)
    assert observation["signer_fingerprint"] == fpr
    assert hashes["universe/binary-amd64/Packages.xz"] == (4, "0" * 64)
    with pytest.raises(admission.Refused, match="signer"):
        monkeypatch.setattr(admission, "ARCHIVE_FINGERPRINT", "0" * 40)
        admission.verify_inrelease(signed, keyring, "noble-updates", now)
    monkeypatch.setattr(admission, "ARCHIVE_FINGERPRINT", fpr)
    with pytest.raises(admission.Refused, match="stale"):
        admission.verify_inrelease(signed, keyring, "noble-updates", now + dt.timedelta(days=3))
