import hashlib
import os
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_public_release as subject
import installer_candidate_published_assets as controller_assets
import installer_candidate_dispatch as dispatch
import installer_release as release


TAG = "v0.0.0-nightly.20261025.1"
SOURCE = "a" * 40
TAG_SHA = "b" * 40


def fixture():
    assets = [{"name": name, "id": index + 1, "size": 1,
               "digest": "sha256:" + hashlib.sha256(b"x").hexdigest(), "state": "uploaded"}
              for index, name in enumerate(subject.expected_assets())]
    return {
        "releases/tags/" + TAG: {"id": 123, "tag_name": TAG, "draft": False,
                                    "prerelease": True, "immutable": True, "assets": assets},
        "git/ref/tags/" + TAG: {"ref": "refs/tags/" + TAG,
                                  "object": {"type": "tag", "sha": TAG_SHA}},
        "git/tags/" + TAG_SHA: {"sha": TAG_SHA, "tag": TAG,
                                 "object": {"type": "commit", "sha": SOURCE}},
    }


def observe(responses):
    return subject.observe(lambda path: deepcopy(responses[path]), TAG, SOURCE)


def test_observe_immutable_annotated_tag_and_exact_assets(tmp_path):
    snapshot = observe(fixture())
    assert snapshot["immutable"] is True
    assert snapshot["tag_chain"][-1]["sha"] == SOURCE
    assert len(snapshot["assets"]) == 15
    tmp_path.chmod(0o700)
    for item in snapshot["assets"]:
        path = tmp_path / item["name"]
        path.write_bytes(b"x")
        path.chmod(0o600)
    subject.verify_downloads(snapshot, tmp_path)
    (tmp_path / snapshot["assets"][0]["name"]).write_bytes(b"y")
    with pytest.raises(ValueError):
        subject.verify_downloads(snapshot, tmp_path)


@pytest.mark.parametrize("replacement", ["symlink", "fifo", "oversize"])
def test_download_validation_rejects_replaced_file(tmp_path, replacement):
    tmp_path.chmod(0o700)
    snapshot = observe(fixture())
    for item in snapshot["assets"]:
        path = tmp_path / item["name"]
        path.write_bytes(b"x")
        path.chmod(0o600)
    victim = tmp_path / snapshot["assets"][0]["name"]
    victim.unlink()
    if replacement == "symlink":
        victim.symlink_to(tmp_path / snapshot["assets"][1]["name"])
    elif replacement == "fifo":
        os.mkfifo(victim, 0o600)
    else:
        victim.write_bytes(b"xx")
        victim.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        subject.verify_downloads(snapshot, tmp_path)


@pytest.mark.parametrize("mutate", [
    lambda r: r["releases/tags/" + TAG].update(immutable=False),
    lambda r: r["releases/tags/" + TAG].pop("immutable"),
    lambda r: r["git/tags/" + TAG_SHA]["object"].update(sha="c" * 40),
    lambda r: r["git/ref/tags/" + TAG]["object"].update(sha="c" * 40),
    lambda r: r["releases/tags/" + TAG]["assets"][0].update(digest="sha256:" + "0" * 64),
    lambda r: r["releases/tags/" + TAG]["assets"][0].update(state="starter"),
])
def test_rejects_changed_release_identity(mutate):
    responses = fixture()
    before = observe(responses)
    mutate(responses)
    if responses["releases/tags/" + TAG]["assets"][0]["digest"] == "sha256:" + "0" * 64:
        assert observe(responses) != before
    else:
        with pytest.raises((ValueError, KeyError)):
            observe(responses)


def controller_scenario(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    responses=fixture()
    class API:
        token='synthetic-token'
        def __init__(self):self.calls=[];self.release_reads=0
        def request(self,method,path):
            assert method=='GET'
            self.calls.append(path)
            if path.endswith('/actions/runs/77'):
                return dict(repository=dict(full_name=release.REPOSITORY),id=77,run_attempt=2,
                    path='.github/workflows/nightly-release.yml',head_sha=SOURCE,
                    head_branch='main',event='workflow_dispatch',status='completed',conclusion='success')
            key=path.split('/repos/ElevenID/marty-ui/',1)[1]
            if key=='releases/tags/'+TAG:self.release_reads+=1
            return deepcopy(responses[key])
    api=API()
    original=dispatch.private_file
    def pinned(path,maximum,executable=False):
        if executable:return dispatch.TOOLS[path.name]
        return original(path,maximum,executable=executable)
    monkeypatch.setattr(dispatch,'private_file',pinned)
    monkeypatch.setattr(release,'verify_inventory_assets',lambda *a,**k:dict(verified=True))
    proofs=[]
    monkeypatch.setattr(controller_assets.provenance,'verify_subject',lambda *a,**k:proofs.append(a[0].name))
    downloads=[]
    def download(url,path,held,limit):
        assert url.startswith('https://github.com/ElevenID/marty-ui/releases/download/'+TAG+'/')
        assert 'synthetic-token' not in url and limit==1
        downloads.append(path.name)
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=held)
        with os.fdopen(fd,'wb') as stream:stream.write(b'x')
    kwargs=dict(client=api,output=tmp_path/'assets',gh=tmp_path/'gh',cosign=tmp_path/'cosign',
        source_sha=SOURCE,release_tag=TAG,build_run_id=77,build_run_attempt=2,
        clock=lambda:100000,downloader=download)
    return kwargs,api,responses,downloads,proofs


def test_controller_acquires_exact_published_assets_without_guest_claim(tmp_path,monkeypatch):
    kwargs,api,_,downloads,proofs=controller_scenario(tmp_path,monkeypatch)
    result=controller_assets.acquire(**kwargs)
    assert result['scope']=='controller-acquisition-only' and result['guest_acquisition'] is False
    assert result['artifact_count']==15 and len(downloads)==15 and len(proofs)==5
    assert {p.name for p in kwargs['output'].iterdir()}==set(subject.expected_assets())
    assert (tmp_path/'assets.release.json').is_file() and (tmp_path/'assets.verified.json').is_file()
    assert api.release_reads==2


def test_controller_refuses_changed_release_after_download(tmp_path,monkeypatch):
    kwargs,api,responses,_,_=controller_scenario(tmp_path,monkeypatch)
    original=api.request
    def changed(method,path):
        if api.release_reads==1 and path.endswith('/releases/tags/'+TAG):
            responses['releases/tags/'+TAG]['assets'][0]['digest']='sha256:'+'0'*64
        return original(method,path)
    api.request=changed
    with pytest.raises(ValueError,match='identity changed'):
        controller_assets.acquire(**kwargs)
    assert kwargs['output'].is_dir() and not (tmp_path/'assets.verified.json').exists()


def test_controller_refuses_failed_provenance_and_repeat(tmp_path,monkeypatch):
    kwargs,_,_,_,_=controller_scenario(tmp_path,monkeypatch)
    def invalid(*a,**k):raise ValueError('invalid signature')
    monkeypatch.setattr(controller_assets.provenance,'verify_subject',invalid)
    with pytest.raises(ValueError,match='invalid signature'):
        controller_assets.acquire(**kwargs)
    assert kwargs['output'].is_dir() and not (tmp_path/'assets.verified.json').exists()
    with pytest.raises(ValueError,match='already exists'):
        controller_assets.acquire(**kwargs)


@pytest.mark.parametrize('replacement', ['oversize', 'symlink'])
def test_controller_refuses_mutated_release_record(tmp_path, monkeypatch, replacement):
    kwargs, _, _, _, _ = controller_scenario(tmp_path, monkeypatch)
    def mutate(*args, **unused):
        record = tmp_path / 'assets.release.json'
        record.unlink()
        if replacement == 'oversize':
            record.write_bytes(b'x' * 65537)
            record.chmod(0o600)
        else:
            record.symlink_to(tmp_path / 'assets.intent.json')
    monkeypatch.setattr(controller_assets.provenance, 'verify_subject', mutate)
    with pytest.raises((ValueError, OSError)):
        controller_assets.acquire(**kwargs)
    assert not (tmp_path / 'assets.verified.json').exists()


def test_controller_refuses_changed_verifier_after_proofs(tmp_path, monkeypatch):
    kwargs, _, _, _, _ = controller_scenario(tmp_path, monkeypatch)
    original = dispatch.private_file
    calls = 0
    def changed(path, maximum, executable=False):
        nonlocal calls
        if executable:
            calls += 1
            if calls > 2:
                return ('0' * 64, maximum)
        return original(path, maximum, executable=executable)
    monkeypatch.setattr(dispatch, 'private_file', changed)
    with pytest.raises(ValueError, match='verifier tool changed'):
        controller_assets.acquire(**kwargs)
    assert not (tmp_path / 'assets.verified.json').exists()
