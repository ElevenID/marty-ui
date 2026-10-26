"""Synthetic transport checks; signed build authenticity is checked at grant retrieval."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_staged_assets as staged
import installer_candidate_public_release as public_release

SOURCE = "a" * 40
TAG = "v0.0.0-nightly.20261025.1"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="private Linux transport")


def scenario(tmp_path):
    tmp_path.chmod(0o700)
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in public_release.expected_assets():
            archive.writestr(name, b"x")
        archive.writestr("nightly-runtime.json", b"extra")
    raw = source.getvalue()
    item = dict(id=72, name="nightly-publication-assets-77", size_in_bytes=len(raw),
                digest="sha256:" + hashlib.sha256(raw).hexdigest(), expired=False,
                created_at="fixed", updated_at="fixed",
                workflow_run=dict(id=77, repository_id=1140864197,
                    head_repository_id=1140864197, head_branch="main", head_sha=SOURCE))
    class API:
        token = "synthetic-token"
        def __init__(self):
            self.item = item.copy()
            self.calls = []
        def request(self, method, path):
            assert method == "GET"
            self.calls.append(path)
            if path.endswith("/actions/runs/77"):
                return dict(repository=dict(full_name="ElevenID/marty-ui"), id=77,
                    run_attempt=2, path=".github/workflows/nightly-release.yml",
                    head_sha=SOURCE, head_branch="main", event="workflow_dispatch",
                    status="completed", conclusion="success")
            if path.endswith("/artifacts?per_page=100"):
                return dict(total_count=1, artifacts=[self.item.copy()])
            raise AssertionError(path)
    api = API()
    def download(gh, token, artifact_id, destination, parent, **limits):
        assert token == api.token and artifact_id == 72
        assert limits["maximum"] == staged.ARCHIVE_MAX
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
    kwargs = dict(client=api, output=tmp_path / "assets", gh=tmp_path / "gh",
                  source_sha=SOURCE, release_tag=TAG, build_run_id=77,
                  build_run_attempt=2, clock=lambda:100000, downloader=download)
    return kwargs, api, raw


def test_staged_transport_selects_only_fifteen_inputs(tmp_path):
    kwargs, api, raw = scenario(tmp_path)
    result = staged.acquire(**kwargs)
    assert result["scope"] == "controller-transport-only"
    assert result["signatures_authenticated"] is False
    assert result["selected_files"] == 15 and result["archive_sha256"] == hashlib.sha256(raw).hexdigest()
    assert {path.name for path in kwargs["output"].iterdir()} == set(public_release.expected_assets())
    assert (tmp_path / "assets.verified.json").is_file()
    assert len(api.calls) == 4
    bound = staged.verify_acquisition(client=api, assets=kwargs['output'],
        source_sha=SOURCE, release_tag=TAG, build_run_id=77, build_run_attempt=2)
    assert bound == result


def test_staged_grant_binding_refuses_replaced_selected_file(tmp_path):
    kwargs, api, _ = scenario(tmp_path)
    staged.acquire(**kwargs)
    victim = kwargs['output'] / 'install.sh'
    victim.write_bytes(b'y')
    with pytest.raises(ValueError, match='differs from artifact'):
        staged.verify_acquisition(client=api, assets=kwargs['output'],
            source_sha=SOURCE, release_tag=TAG, build_run_id=77, build_run_attempt=2)


def test_staged_grant_binding_refuses_changed_archive(tmp_path):
    kwargs, api, _ = scenario(tmp_path)
    staged.acquire(**kwargs)
    archive = tmp_path / 'assets.archive.zip'
    archive.write_bytes(archive.read_bytes() + b'x')
    with pytest.raises(ValueError, match='archive identity differs'):
        staged.verify_acquisition(client=api, assets=kwargs['output'],
            source_sha=SOURCE, release_tag=TAG, build_run_id=77, build_run_attempt=2)


def test_staged_grant_binding_refuses_file_changed_during_final_api_call(tmp_path):
    kwargs, api, _ = scenario(tmp_path)
    staged.acquire(**kwargs)
    original = api.request
    listings = [0]
    def mutate(method, path):
        value = original(method, path)
        if path.endswith('/artifacts?per_page=100'):
            listings[0] += 1
            if listings[0] == 2:
                (kwargs['output'] / 'install.sh').write_bytes(b'y')
        return value
    api.request = mutate
    with pytest.raises(ValueError, match='changed after artifact observation'):
        staged.verify_acquisition(client=api, assets=kwargs['output'],
            source_sha=SOURCE, release_tag=TAG, build_run_id=77, build_run_attempt=2)


def test_staged_grant_binding_rejects_duplicate_zip_even_with_matching_local_record(tmp_path):
    kwargs, api, _ = scenario(tmp_path)
    staged.acquire(**kwargs)
    source = io.BytesIO()
    with zipfile.ZipFile(source, 'w') as archive:
        for name in public_release.expected_assets():
            archive.writestr(name, b'x')
        with pytest.warns(UserWarning, match='Duplicate name'):
            archive.writestr('install.sh', b'x')
    raw = source.getvalue()
    archive = tmp_path / 'assets.archive.zip'
    archive.write_bytes(raw)
    api.item['size_in_bytes'] = len(raw)
    api.item['digest'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
    record_path = tmp_path / 'assets.verified.json'
    record = json.loads(record_path.read_bytes())
    record['archive_sha256'] = hashlib.sha256(raw).hexdigest()
    record['artifact']['size_in_bytes'] = len(raw)
    record['artifact']['digest'] = api.item['digest']
    record_path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='member closure differs'):
        staged.verify_acquisition(client=api, assets=kwargs['output'],
            source_sha=SOURCE, release_tag=TAG, build_run_id=77, build_run_attempt=2)


def test_staged_transport_refuses_changed_artifact(tmp_path):
    kwargs, api, _ = scenario(tmp_path)
    original = api.request
    calls = [0]
    def changed(method, path):
        value = original(method, path)
        if path.endswith("/artifacts?per_page=100"):
            calls[0] += 1
            if calls[0] == 2:
                value["artifacts"][0]["digest"] = "sha256:" + "0" * 64
        return value
    api.request = changed
    with pytest.raises(ValueError, match="identity changed"):
        staged.acquire(**kwargs)
    assert kwargs["output"].is_dir() and not (tmp_path / "assets.verified.json").exists()


def test_staged_transport_bounds_directory_before_zip_parser(tmp_path, monkeypatch):
    kwargs, api, _ = scenario(tmp_path)
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        for name in public_release.expected_assets():
            archive.writestr(name, b"x")
        for index in range(101):
            archive.writestr(f"extra-{index}", b"x")
    raw = source.getvalue()
    api.item["size_in_bytes"] = len(raw)
    api.item["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    def download(_gh, _token, _id, destination, parent, **_limits):
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
    kwargs["downloader"] = download
    def forbidden(*_args, **_kwargs):
        raise AssertionError("ZIP parser called before metadata bound")
    monkeypatch.setattr(staged.zipfile, "ZipFile", forbidden)
    with pytest.raises(ValueError, match="directory exceeds bound"):
        staged.acquire(**kwargs)
    assert not kwargs["output"].exists()


def test_staged_transport_rejects_zip64_locator_before_parser(tmp_path, monkeypatch):
    kwargs, api, _ = scenario(tmp_path)
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        names = sorted(public_release.expected_assets())
        for name in names[:-1]:
            archive.writestr(name, b"x")
        last = zipfile.ZipInfo(names[-1])
        last.comment = b"PK\x06\x07" + b"\0" * 16
        archive.writestr(last, b"x")
    raw = source.getvalue()
    assert raw[-42:-38] == b"PK\x06\x07"
    api.item["size_in_bytes"] = len(raw)
    api.item["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    def download(_gh, _token, _id, destination, parent, **_limits):
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
    kwargs["downloader"] = download
    def forbidden(*_args, **_kwargs):
        raise AssertionError("ZIP parser called before ZIP64 rejection")
    monkeypatch.setattr(staged.zipfile, "ZipFile", forbidden)
    with pytest.raises(ValueError, match="ZIP64 locator refused"):
        staged.acquire(**kwargs)
    assert not kwargs["output"].exists()


def test_staged_transport_allows_non_zip64_extra_payload(tmp_path):
    kwargs, api, _ = scenario(tmp_path)
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        names = sorted(public_release.expected_assets())
        for name in names[:-1]:
            archive.writestr(name, b"x")
        last = zipfile.ZipInfo(names[-1])
        last.extra = struct.pack("<HH", 0xcafe, 2) + b"\x01\x00"
        archive.writestr(last, b"x")
    raw = source.getvalue()
    api.item["size_in_bytes"] = len(raw)
    api.item["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    def download(_gh, _token, _id, destination, parent, **_limits):
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
    kwargs["downloader"] = download
    assert staged.acquire(**kwargs)["selected_files"] == 15


@pytest.mark.parametrize("member", ["../bad", "nested/bad", "bad file"])
def test_staged_transport_refuses_unsafe_archive_member(tmp_path, member):
    kwargs, api, _ = scenario(tmp_path)
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        for name in public_release.expected_assets():
            archive.writestr(name, b"x")
        archive.writestr(member, b"extra")
    raw = source.getvalue()
    api.item["size_in_bytes"] = len(raw)
    api.item["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    def download(_gh, _token, _id, destination, parent, **_limits):
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
    kwargs["downloader"] = download
    with pytest.raises(ValueError, match="member differs"):
        staged.acquire(**kwargs)
    assert not (tmp_path / "assets.verified.json").exists()
