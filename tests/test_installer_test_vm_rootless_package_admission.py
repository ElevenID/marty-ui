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
              (len(compressed), admission.sha(compressed)),
              "universe/binary-amd64/Packages": (len(plain), admission.sha(plain))}
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
    assert admission._consistent_candidate([{**selected, "pocket": "noble-updates"},
                                            {**selected, "pocket": "noble-security"}])["sha256"] == row["SHA256"]
    with pytest.raises(admission.Refused, match="mixed"):
        admission._consistent_candidate([selected, {**selected, "sha256": "0" * 64}])


def test_simulation_rejects_existing_change_unknown_action_and_dependency():
    admitted = {"uidmap": "1:4.13+dfsg1-4ubuntu3.2", "rootlesskit": "1.1.1-1ubuntu0.24.04.3"}
    transcript = (b"Reading package lists...\nBuilding dependency tree...\n"
                  b"Reading state information...\n"
                  b"The following NEW packages will be installed:\n  uidmap rootlesskit\n"
                  b"0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n"
                  b"Inst uidmap (1:4.13+dfsg1-4ubuntu3.2 Ubuntu:24.04/noble-updates [amd64])\n"
                  b"Inst rootlesskit (1.1.1-1ubuntu0.24.04.3 Ubuntu:24.04/noble-updates [amd64])\n"
                  b"Conf rootlesskit (1.1.1-1ubuntu0.24.04.3 Ubuntu:24.04/noble-updates [amd64])\n"
                  b"Conf uidmap (1:4.13+dfsg1-4ubuntu3.2 Ubuntu:24.04/noble-updates [amd64])\n")
    assert len(admission.inspect_simulation(transcript, {"docker.io": "29.1.3"}, admitted)) == 2
    for changed in (transcript.replace(b"Inst uidmap", b"Remv uidmap"),
                    transcript.replace(b"Inst uidmap", b"Inst docker.io"),
                    transcript.replace(b"Inst uidmap", b"Inst foreignkit"),
                    transcript.replace(b"Conf uidmap", b"Conf docker.io"),
                    transcript.replace(b"0 to remove", b"1 to remove"),
                    transcript.replace(b"2 newly installed", b"3 newly installed")):
        with pytest.raises(admission.Refused):
            admission.inspect_simulation(changed, {"docker.io": "29.1.3"}, admitted)


def test_guest_status_and_apt_command_are_closed(tmp_path):
    status = (b"Package: docker.io\nStatus: install ok installed\n"
              b"Version: 29.1.3-0ubuntu3~24.04.2\n\n"
              b"Package: libc6\nStatus: install ok installed\nVersion: 2.39-0ubuntu8\n\n")
    assert admission._installed_status(status)["docker.io"] == "29.1.3-0ubuntu3~24.04.2"
    for changed in (status.replace(b"install ok installed", b"deinstall ok config-files", 1),
                    status + status.split(b"\n\n")[0] + b"\n\n"):
        with pytest.raises(admission.Refused):
            admission._installed_status(changed)
    with pytest.raises(admission.Refused, match="not admitted"):
        admission._apt_run(["install", "docker-ce"], tmp_path / "config")


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


@pytest.mark.skipif(not Path("/usr/bin/python3").exists(), reason="requires Linux")
def test_bounded_child_reaps_on_output_cap_and_timeout():
    good = admission.run_bounded(["/usr/bin/python3", "-c",
                                  "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                                 input_bytes=b"fixed", env={"PATH": "/usr/bin"},
                                 timeout=3, stdout_limit=16, stderr_limit=16)
    assert good.returncode == 0 and good.stdout == b"fixed"
    bad = admission.run_bounded(["/usr/bin/python3", "-c", "import sys;sys.exit(7)"],
                                env={"PATH": "/usr/bin"}, timeout=3,
                                stdout_limit=16, stderr_limit=16)
    assert bad.returncode == 7
    with pytest.raises(admission.Refused, match="oversized"):
        admission.run_bounded(["/usr/bin/python3", "-c",
                               "import os;os.write(1,b'x'*100000)"],
                              env={"PATH": "/usr/bin"}, timeout=3,
                              stdout_limit=64, stderr_limit=64)


@pytest.mark.skipif(not Path("/usr/bin/python3").exists(), reason="requires Linux")
def test_bounded_child_kills_closed_pipe_descendant_before_reaping():
    code = ("import os,time; p=os.fork(); "
            "\nif p: print(p,flush=True); os._exit(0)"
            "\nos.close(1); os.close(2); time.sleep(20)")
    done = admission.run_bounded(["/usr/bin/python3", "-c", code],
                                 env={"PATH": "/usr/bin"}, timeout=3,
                                 stdout_limit=32, stderr_limit=32)
    assert done.returncode == 0
    child_pid = int(done.stdout.strip())
    for _ in range(100):
        try:
            state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
        except FileNotFoundError:
            break
        if state == "Z":
            break
        __import__("time").sleep(0.01)
    else:
        pytest.fail("closed-pipe descendant remained running")
    with pytest.raises(admission.Refused, match="timed out"):
        admission.run_bounded(["/usr/bin/python3", "-c", "import time;time.sleep(3)"],
                              env={"PATH": "/usr/bin"}, timeout=1,
                              stdout_limit=64, stderr_limit=64)


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
    monkeypatch.setattr(admission, "KEYRING", keyring)
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


@pytest.mark.skipif(not Path("/usr/bin/apt-get").exists() or
                    not Path("/usr/bin/gpg").exists(), reason="requires Linux APT and gpg")
def test_real_private_apt_solver_accepts_only_new_packages(tmp_path, monkeypatch):
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    env = {"GNUPGHOME": str(home), "PATH": "/usr/bin", "LC_ALL": "C"}
    subprocess.run(["/usr/bin/gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                    "Synthetic Ubuntu Archive <synthetic@example.invalid>", "rsa2048", "sign", "0"],
                   env=env, capture_output=True, check=True, timeout=30)
    listing = subprocess.run(["/usr/bin/gpg", "--batch", "--with-colons", "--list-keys"],
                             env=env, capture_output=True, check=True).stdout
    fpr = next(line.split(b":")[9].decode() for line in listing.splitlines()
               if line.startswith(b"fpr:"))
    keyring = tmp_path / "keyring.gpg"
    keyring.write_bytes(subprocess.run(["/usr/bin/gpg", "--batch", "--export", fpr],
                                       env=env, capture_output=True, check=True).stdout)
    monkeypatch.setattr(admission, "KEYRING", keyring)
    monkeypatch.setattr(admission, "ARCHIVE_FINGERPRINT", fpr)
    monkeypatch.setattr(admission, "POCKETS", {"noble-updates": "https://archive.ubuntu.com/ubuntu/"})
    monkeypatch.setattr(admission, "COMPONENTS", ("main",))
    monkeypatch.setattr(admission, "TARGETS", ("uidmap", "rootlesskit"))
    monkeypatch.setattr(admission, "EXPECTED_VERSIONS", {"uidmap": "1", "rootlesskit": "1"})
    original = admission.private_file
    monkeypatch.setattr(admission, "private_file", lambda p, limit, uid=None: original(p, limit))
    bundle = tmp_path / "bundle"
    bundle.mkdir(mode=0o700)
    rows = []
    selected = []
    for package in admission.TARGETS:
        payload = b"synthetic-" + package.encode()
        row = _row(package, "1", payload)
        rows.append(row)
        (bundle / f"{package}.deb").write_bytes(payload)
        selected.append({"package": package, "version": "1", "pocket": "noble-updates",
                         "component": "main", "sha256": row["SHA256"], "size": len(payload)})
    plain = b"".join(("\n".join(f"{k}: {v}" for k, v in row.items()) +
                      "\nDescription: Synthetic package\n\n").encode() for row in rows)
    compressed = lzma.compress(plain)
    (bundle / "noble-updates.main.packages.xz").write_bytes(compressed)
    now = dt.datetime.now(dt.timezone.utc)
    release = (f"Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble-updates\nCodename: noble\n"
               f"Date: {now.strftime('%a, %d %b %Y %H:%M:%S UTC')}\n"
               f"Architectures: amd64\nComponents: main universe\nSHA256:\n"
               f" {hashlib.sha256(plain).hexdigest()} {len(plain)} "
               "main/binary-amd64/Packages\n"
               f" {hashlib.sha256(compressed).hexdigest()} {len(compressed)} "
               "main/binary-amd64/Packages.xz\n")
    unsigned = tmp_path / "Release"
    unsigned.write_text(release)
    signed = subprocess.run(["/usr/bin/gpg", "--batch", "--armor", "--clearsign",
                             "--output", "-", str(unsigned)], env=env,
                            capture_output=True, check=True).stdout
    (bundle / "noble-updates.inrelease").write_bytes(signed)
    status = (b"Package: docker.io\nStatus: install ok installed\n"
              b"Version: 29.1.3-0ubuntu3~24.04.2\n\n")
    result = admission.simulate_verified_bundle(bundle, keyring, status,
                                                {"packages": selected}, now)
    assert result["transaction_simulated"] is True
    assert {row["package"] for row in result["new_package_actions"]} == set(admission.REQUIRED)
    assert result["rootful_docker_package_simulated_change"] is False
