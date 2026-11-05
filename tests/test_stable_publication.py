"""Failure injection for v2 authority/custody; crypto adapters are synthetic."""
import copy
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import stable_publication as p
import stable_publication_intake as intake
import test_stable_publication_candidate as candidates
from test_stable_publication_candidate import sealed
from test_stable_publication_checkpoint import NOW, SOURCE, RUN, TAG

PUBLISHER = 56789
ENV = {"GITHUB_REPOSITORY": p.h.REPOSITORY, "GITHUB_REF": "refs/heads/main",
       "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_WORKFLOW_REF":
       f"{p.h.REPOSITORY}/{p.c.PUBLISHER_WORKFLOW}@refs/heads/main", "GITHUB_RUN_ATTEMPT": "1",
       "GITHUB_RUN_ID": str(PUBLISHER), "GITHUB_SHA": SOURCE}


class API(candidates.API):
    release_at_tag = p.GitHub.release_at_tag

    def __init__(self, directory, manifest):
        super().__init__(directory, manifest)
        self.original_artifact = {"id": 77, "digest": "sha256:" + "c" * 64}
        self.main_sha = SOURCE
        self.publisher = {**self.run_value, "id": PUBLISHER, "path": p.c.PUBLISHER_WORKFLOW,
                          "status": "in_progress", "conclusion": None}
        self.releases = []
        self.content = {}
        self.writes = []
        self.upload_hook = None
        self.read_hook = None
        self.pages = None
        self.paths = []

    def json(self, path, **kwargs):
        self.paths.append(path)
        if self.read_hook:
            self.read_hook(path)
        if path == f"repos/{p.h.REPOSITORY}/actions/runs/{PUBLISHER}":
            return copy.deepcopy(self.publisher)
        if path.startswith(f"repos/{p.h.REPOSITORY}/releases?"):
            assert "per_page=20&" in path
            page = int(path.split("page=")[-1])
            return copy.deepcopy(self.pages[page - 1] if self.pages is not None else self.releases)
        if path.startswith(f"repos/{p.h.REPOSITORY}/releases/"):
            assert path.endswith("/100")
            return copy.deepcopy(self.releases[0])
        return super().json(path, **kwargs)

    def artifact(self, run_id, name, source):
        if name.startswith("stack-release-publication-inputs-"):
            assert (run_id, name, source) == (RUN, f"stack-release-publication-inputs-{RUN}-1", SOURCE)
            return copy.deepcopy(self.original_artifact)
        return super().artifact(run_id, name, source)

    def main(self):
        return {"commit": {"sha": self.main_sha}, "protected": True}

    def response(self, path, *, method="GET", payload=None):
        self.writes.append((method, path, copy.deepcopy(payload)))
        if method == "POST":
            assert path == f"repos/{p.h.REPOSITORY}/releases" and not self.releases
            row = {**payload, "id": 100, "assets": []}
            self.releases.append(row)
            return 201, p.h.encoded(row)
        assert method == "PATCH" and path.endswith("/100")
        self.releases[0].update(payload)
        return 200, p.h.encoded(self.releases[0])

    def upload(self, release_id, name, source, metadata):
        assert release_id == 100
        if self.upload_hook:
            self.upload_hook(name)
        assert not any(row["name"] == name for row in self.releases[0]["assets"])
        self.writes.append(("upload", name, None))
        asset_id = 1000 + len(self.releases[0]["assets"])
        self.content[asset_id] = source.read_bytes()
        self.releases[0]["assets"].append({"id": asset_id, "name": name, "size": metadata["size"],
                                          "digest": metadata["sha256"], "state": "uploaded"})

    def verify_asset(self, row, expected):
        assert p.h.sha256(self.content[row["id"]]) == expected["sha256"]
        assert len(self.content[row["id"]]) == expected["size"]


class Proof:
    def __init__(self, root):
        self.root = root
        self.sources = []
        self.verified = []

    def source(self, request, deadline):
        self.sources.append((copy.deepcopy(request), deadline))

    def assets(self, directory, request, deadline, observations):
        self.verified.append((directory, copy.deepcopy(request), deadline))


class Owner:
    def sign(self, receipt):
        return {"synthetic_not_crypto": p.h.sha256(p.h.encoded(receipt))}

    def verify(self, receipt, bundle):
        p.h.require(bundle == self.sign(receipt), "synthetic owner verification refused")


@pytest.fixture
def setup(sealed, monkeypatch):
    fixture, directory, manifest, _ = sealed
    api = API(directory, manifest)
    root = fixture.base / "source"
    (root / "release").mkdir(parents=True)
    (root / p.c.POLICY_PATH).write_bytes((p.ROOT / p.c.POLICY_PATH).read_bytes())
    (root / "release/stack-lock.json").write_bytes((fixture.control / "stack-lock.json").read_bytes())
    proof = Proof(root)
    admission = json.loads((directory / "tag-admission.json").read_bytes())
    tag = {"sha": admission["tag_object_sha"], "object": {"type": "commit", "sha": SOURCE},
           "message": p.h.tag_message(fixture.request(), manifest["files"]["checkpoint/request.json"]["sha256"],
                api.original_artifact, admission["operator_run_id"], intent_object_sha=admission["intent_object_sha"])}
    intent = {"sha": admission["intent_object_sha"], "object": {"type": "commit", "sha": SOURCE},
              "message": p.h.intent_message(fixture.request(), manifest["files"]["checkpoint/request.json"]["sha256"],
                                            api.original_artifact, admission["operator_run_id"])}
    monkeypatch.setattr(p.h, "annotated_tag", lambda _, name: copy.deepcopy(intent if name == admission["intent_tag"] else tag))
    monkeypatch.setattr(p.h, "successful_result", lambda *_: copy.deepcopy(admission))
    return fixture, directory, manifest, api, proof, tag


def authorization(setup, now=NOW + timedelta(hours=1)):
    _, directory, _, api, proof, _ = setup
    return p.authorize(api, directory, api.items[0], proof=proof, environment=ENV, now=now)


def publisher(setup, *, clock=lambda: NOW + timedelta(hours=1)):
    _, directory, _, api, proof, _ = setup
    return p.Publisher(api, directory, authorization(setup, clock()), Owner(), root=proof.root, clock=clock)


def test_fresh_authorization_authenticates_original_success_and_caps_expiry(setup):
    _, _, manifest, api, proof, _ = setup
    first = authorization(setup)
    assert first["created_at"] == "2026-11-04T02:02:03Z"
    assert p.h.timestamp(first["not_after"]) - p.h.timestamp(first["created_at"]) == timedelta(seconds=900)
    assert proof.sources and proof.verified
    near_expiry = p.h.timestamp(manifest["not_after"]) - timedelta(seconds=30)
    late = authorization(setup, near_expiry)
    assert late["not_after"] == manifest["not_after"]
    assert api.deadline == p.h.timestamp(late["not_after"])
    assert not api.writes


@pytest.mark.parametrize("field,value", [("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_REF", "refs/tags/v1.2.3"), ("GITHUB_SHA", "b" * 40), ("GITHUB_WORKFLOW_REF", "foreign")])
def test_reruns_and_foreign_publisher_contexts_have_no_authority(setup, field, value):
    _, directory, _, api, proof, _ = setup
    with pytest.raises(ValueError):
        p.authorize(api, directory, api.items[0], proof=proof, environment={**ENV, field: value},
                    now=NOW + timedelta(hours=1))
    assert not api.writes


@pytest.mark.parametrize("mutation", ["failed", "in_progress", "rerun", "main", "policy", "lock", "tag", "artifact"])
def test_changed_original_authority_is_rejected(setup, mutation):
    _, _, _, api, proof, tag = setup
    if mutation == "failed": api.run_value["conclusion"] = "failure"
    elif mutation == "in_progress": api.run_value["status"] = "in_progress"
    elif mutation == "rerun": api.run_value["run_attempt"] = 2
    elif mutation == "main": api.main_sha = "b" * 40
    elif mutation == "policy": (proof.root / p.c.POLICY_PATH).write_text("{}")
    elif mutation == "lock": (proof.root / "release/stack-lock.json").write_text("{}")
    elif mutation == "tag": tag["sha"] = "e" * 40
    elif mutation == "artifact": api.items[0]["expired"] = True
    with pytest.raises(ValueError): authorization(setup)
    assert not api.writes


@pytest.mark.parametrize("mutation", ["absent", "object", "source", "operator", "checkpoint"])
def test_authorization_requires_the_retained_exact_original_operator_intent(setup, monkeypatch, mutation):
    original = p.h.annotated_tag
    def changed(github, name):
        value = original(github, name)
        if name == "v-release-intent-1.2.3":
            if mutation == "absent": return None
            if mutation == "object": value["sha"] = "7" * 40
            elif mutation == "source": value["object"]["sha"] = "b" * 40
            elif mutation == "operator": value["message"] = value["message"].replace("Operator-Run: 991", "Operator-Run: 993")
            elif mutation == "checkpoint": value["message"] += "Foreign-Checkpoint: true\n"
        return value
    monkeypatch.setattr(p.h, "annotated_tag", changed)
    with pytest.raises(ValueError, match="intent"):
        authorization(setup)
    assert not setup[3].writes


@pytest.mark.parametrize("mutation", ["absent", "object", "source"])
def test_intent_change_during_upload_stops_before_the_next_mutation(setup, monkeypatch, mutation):
    pub = publisher(setup); api = setup[3]
    original = p.h.annotated_tag
    changed = [False]
    def read(github, name):
        value = original(github, name)
        if changed[0] and name == "v-release-intent-1.2.3":
            if mutation == "absent": return None
            if mutation == "object": value["sha"] = "7" * 40
            if mutation == "source": value["object"]["sha"] = "b" * 40
        return value
    monkeypatch.setattr(p.h, "annotated_tag", read)
    api.upload_hook = lambda _: changed.__setitem__(0, True)
    with pytest.raises(ValueError, match="intent changed"):
        pub.publish()
    assert len(api.content) == 1 and api.releases[0]["draft"] is True
    assert not any(write[2] == {"draft": False, "make_latest": "true"} for write in api.writes)


def test_publish_creates_owned_draft_exact_assets_and_one_final_transition(setup):
    pub = publisher(setup)
    result = pub.publish()
    assert result["status"] == "published"
    api = setup[3]
    assert api.releases[0]["draft"] is False
    assert set(row["name"] for row in api.releases[0]["assets"]) == p.cp.ASSET_NAMES
    assert len([w for w in api.writes if w[0] == "upload"]) == len(p.cp.ASSET_NAMES)
    assert len([w for w in api.writes if w[2] == {"draft": False, "make_latest": "true"}]) == 1
    before = copy.deepcopy(api.writes)
    # Fully matching published state is a read-only idempotent success.
    assert publisher(setup).publish()["release_id"] == result["release_id"]
    assert api.writes == before


def test_fresh_retry_resumes_only_owned_exact_partial_uploads(setup):
    pub = publisher(setup); api = setup[3]
    def fail(name):
        if len(api.content) == 5:
            raise ValueError("network outcome unknown")
    api.upload_hook = fail
    with pytest.raises(ValueError, match="unknown"): pub.publish()
    assert len(api.content) == 5 and api.releases[0]["draft"] is True
    api.upload_hook = None
    publisher(setup).publish()
    uploaded = [w[1] for w in api.writes if w[0] == "upload"]
    assert len(uploaded) == len(set(uploaded)) == len(p.cp.ASSET_NAMES)


@pytest.mark.parametrize("mutation", ["unowned", "foreign", "extra", "starter", "digest", "bytes", "duplicate", "coordinate"])
def test_conflicting_draft_is_preserved_without_any_mutation(setup, mutation):
    publisher(setup).publish(); api = setup[3]
    row = api.releases[0]; row["draft"] = True
    if mutation == "unowned": row["body"] = ""
    elif mutation == "foreign": row["body"] = row["body"].replace('"release_id":100', '"release_id":101')
    elif mutation == "extra": row["assets"].append({"id": 9999, "name": "foreign"})
    elif mutation == "starter": row["assets"][0]["state"] = "starter"
    elif mutation == "digest": row["assets"][0]["digest"] = "sha256:" + "0" * 64
    elif mutation == "bytes": api.content[row["assets"][0]["id"]] = b"foreign"
    elif mutation == "duplicate": row["assets"].append(copy.deepcopy(row["assets"][0]))
    elif mutation == "coordinate": row["target_commitish"] = "b" * 40
    before = copy.deepcopy(api.writes)
    with pytest.raises((ValueError, AssertionError)): publisher(setup).publish()
    assert api.writes == before and row["draft"] is True


def test_main_change_during_upload_stops_before_next_mutation(setup):
    api = setup[3]; pub = publisher(setup)
    api.upload_hook = lambda _: setattr(api, "main_sha", "b" * 40)
    with pytest.raises(ValueError, match="main changed"): pub.publish()
    assert len(api.content) == 1 and api.releases[0]["draft"] is True


def test_authorization_expiry_during_api_read_prevents_mutation(setup):
    current = [NOW + timedelta(hours=1)]
    pub = publisher(setup, clock=lambda: current[0]); api = setup[3]
    def expire(path):
        if "/actions/runs/" in path:
            current[0] += timedelta(minutes=16)
    api.read_hook = expire
    with pytest.raises(ValueError, match="expired"): pub.publish()
    assert not api.writes


def test_signing_failure_leaves_unowned_draft_for_explicit_incident(setup):
    pub = publisher(setup); api = setup[3]
    pub.ownership.sign = lambda _: (_ for _ in ()).throw(ValueError("signing refused"))
    with pytest.raises(ValueError, match="signing refused"): pub.publish()
    assert len(api.writes) == 1 and api.releases[0]["body"] == ""
    before = copy.deepcopy(api.writes)
    with pytest.raises(ValueError, match="no authenticated"): publisher(setup).publish()
    assert api.writes == before


def test_release_listing_exhausts_small_pages_and_rejects_duplicate_coordinates(setup):
    api = setup[3]
    api.pages = [[{"id": i, "tag_name": f"v0.0.{i}"} for i in range(1, 21)], [{"id": 50, "tag_name": TAG}]]
    assert api.release_at_tag(TAG)["id"] == 50
    api.pages[0][0]["tag_name"] = TAG
    with pytest.raises(ValueError, match="multiple releases"): api.release_at_tag(TAG)


def test_intake_uses_original_completed_api_run_before_tag_concurrency(setup):
    api = setup[3]
    event = {"repository": {"id": p.h.REPOSITORY_ID, "full_name": p.h.REPOSITORY},
             "workflow_run": copy.deepcopy(api.run_value)}
    automatic = {**ENV, "GITHUB_EVENT_NAME": "workflow_run"}
    assert intake.intake(api, event, automatic) == {"eligible": "true", "candidate_run_id": str(RUN), "tag": TAG}
    event["workflow_run"]["conclusion"] = "failure"
    with pytest.raises(ValueError): intake.intake(api, event, automatic)
    api.items = []
    assert intake.intake(api, {**event, "workflow_run": api.run_value}, automatic) == {"eligible": "false"}
    with pytest.raises(ValueError): intake.intake(api, event, ENV, str(RUN))


@pytest.mark.parametrize("key,value", [("run_attempt", 2), ("run_attempt", True), ("event", "pull_request"),
    ("head_branch", "foreign"), ("head_sha", "b" * 40), ("id", True), ("status", "in_progress")])
def test_intake_rejects_foreign_event_authority(setup, key, value):
    api = setup[3]
    event = {"repository": {"id": p.h.REPOSITORY_ID, "full_name": p.h.REPOSITORY},
             "workflow_run": {**api.run_value, key: value}}
    with pytest.raises(ValueError): intake.intake(api, event, {**ENV, "GITHUB_EVENT_NAME": "workflow_run"})


def test_upload_transport_uses_exact_allowlisted_endpoint_without_overwrite(setup, monkeypatch):
    _, directory, _, _, _, _ = setup
    api = p.GitHub("/pinned/gh"); calls = []
    name = "install.sh"; path = directory / "checkpoint/assets" / name
    expected = {"size": path.stat().st_size, "sha256": p.h.file_digest(path)}
    def command(arguments, **kwargs):
        calls.append(arguments)
        return 0, p.h.encoded({"id": 1000, "name": name})
    monkeypatch.setattr(p.h, "command", command)
    api.upload(100, name, path, expected)
    args = calls[0]
    assert args[0] == "/pinned/gh" and args[args.index("--input") + 1] == str(path)
    assert f"https://uploads.github.com/repos/{p.h.REPOSITORY}/releases/100/assets?name=install.sh" in args
    assert "--clobber" not in args and "DELETE" not in args


def test_owner_crypto_command_binds_exact_publisher_run_and_custom_predicate(monkeypatch):
    api = p.GitHub("/pinned/gh"); calls = []; certificates = []
    receipt = {"publisher_run_id": PUBLISHER, "publisher_source_sha": SOURCE}
    monkeypatch.setattr(p, "publisher_run", lambda *args, **kwargs: {})
    monkeypatch.setattr(p.h, "command", lambda arguments, **kwargs: (calls.append(arguments) or 0, b"[]"))
    monkeypatch.setattr(p.provenance, "verified_certificate", lambda *args, **kwargs: certificates.append(kwargs))
    p.Ownership(Path("/pinned/gh"), Path("/pinned/cosign"), api).verify(receipt, {})
    assert "--deny-self-hosted-runners" in calls[0]
    assert calls[0][calls[0].index("--predicate-type") + 1] == p.OWNER_TYPE
    assert certificates == [{"workflow": p.c.PUBLISHER_WORKFLOW, "source_sha": SOURCE,
                             "run_id": PUBLISHER, "run_attempt": 1}]
