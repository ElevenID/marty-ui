"""Optional source-consumer boundaries; synthetic packs never qualify a runtime."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace
import urllib.request

import pytest
from referencing import Registry

from scripts import check_agent_trust_protocol_consumer as consumer


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def lock():
    return json.loads(consumer.LOCK_PATH.read_text())


def test_reviewed_lock_pins_optional_source_without_switching_public_version():
    document = lock()
    consumer.validate_lock(document)
    assert document["protocol"]["revision"] == "6126da7619e057be2ff58dd38a5d50f49891d1b3"
    assert document["protocol"]["manifest_sha256"] == "3d9fc9475050d80ea2e0a835a3c8cf801a642303a063fa4d3014485ceb6b8d37"
    assert document["public_protocol_revision"] == "76c37dc229b328afe002b911a26624543f814a64"
    assert document["public_mip_version"] == "0.5.0"
    assert document["runtime_qualification"] == "NOT_ASSESSED"
    assert document["public_discovery"] is False


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("status", "ACTIVE"), ("public_discovery", True),
    ("public_discovery", 0), ("runtime_qualification", "RUNTIME_QUALIFIED"),
    ("public_mip_version", "0.6.0"), ("fixture_policy", "execute-upstream"),
    ("unknown_critical_context", True),
])
def test_lock_cannot_escalate_or_change_the_consumer_policy(field, value):
    document = lock()
    document[field] = value
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.validate_lock(document)


@pytest.mark.parametrize("field,value", [
    ("revision", "main"), ("revision", "6126da7"), ("manifest_sha256", "unverified"),
    ("repository", "https://attacker.example/repo"), ("version", "latest"),
    ("manifest_path", "../../outside"), ("capability_register_path", "https://attacker.example/catalog"),
    ("verified", True),
])
def test_lock_rejects_mutable_sources_self_attestation_and_unreviewed_locations(field, value):
    document = lock()
    document["protocol"][field] = value
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.validate_lock(document)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "schema", "extra"])
def test_profile_selection_is_explicit_and_closed(mutation):
    document = lock()
    profiles = document["selected_profiles"]
    if mutation == "missing":
        profiles.pop()
    elif mutation == "duplicate":
        profiles[1] = copy.deepcopy(profiles[0])
    elif mutation == "unknown":
        profiles[0]["id"] = "unknown.v1"
    elif mutation == "schema":
        profiles[0]["schemas"] = ["schemas/unreviewed.json"]
    else:
        profiles[0]["runtime_qualified"] = True
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.validate_lock(document)


@pytest.mark.parametrize("raw", [
    b'{"version":1,"version":1}', b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":1e999}', b'[]', b'null', b'{"x":"\xff"}',
    b'{"a":' * 70 + b'1' + b'}' * 70,
])
def test_json_decoder_rejects_ambiguous_unbounded_or_nonjson_records(raw):
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.decode_json(raw, "synthetic")


def test_json_decoder_bounds_bytes_before_decoding(monkeypatch):
    monkeypatch.setattr(consumer, "MAX_JSON_BYTES", 4)
    with pytest.raises(consumer.ConsumerCheckError, match="limit"):
        consumer.decode_json(b'{"a":1}', "synthetic")


@pytest.fixture
def pack(tmp_path):
    """A small synthetic pack; no upstream or private source is vendored."""
    for name in consumer.SOURCE_DIRECTORIES:
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    contents = {name: b"synthetic covered data\n" for name in consumer.SOURCE_FILES}
    contents.update({
        "schemas/synthetic.json": encoded(schema("synthetic")),
        "reference/agent_trust/sentinel.py": b"raise RuntimeError('upstream code executed')\n",
        "schemas/__init__.py": b"raise RuntimeError('schema package imported')\n",
    })
    for name, raw in contents.items():
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    manifest = {**consumer.MANIFEST_CONSTANTS, "files": [
        {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}
        for name, raw in sorted(contents.items())
    ]}
    raw = encoded(manifest)
    (tmp_path / consumer.MANIFEST_PATH).write_bytes(raw)
    return SimpleNamespace(root=tmp_path, contents=contents, manifest=manifest,
                           protocol={"manifest_sha256": hashlib.sha256(raw).hexdigest()})


@pytest.fixture
def no_network_or_process(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("source inspection attempted network access or execution")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def test_integrity_and_schema_checks_read_code_as_data(pack, no_network_or_process):
    snapshot = consumer.verify_source_pack(pack.root, pack.protocol)
    assert snapshot == pack.contents
    schemas, registry = consumer.schema_registry(snapshot, selected_paths=("schemas/synthetic.json",))
    assert set(schemas) == {"schemas/synthetic.json"}
    assert not consumer._errors(schemas["schemas/synthetic.json"], {"value": "ok"}, registry)
    assert consumer._errors(schemas["schemas/synthetic.json"], {"value": "ok", "trusted": True}, registry)
    assert "reference.agent_trust.sentinel" not in __import__("sys").modules


@pytest.mark.parametrize("mutation", ["tampered", "deleted", "new", "symlink-file", "symlink-directory", "symlink-cache"])
def test_source_substitution_and_coverage_changes_are_rejected(pack, mutation):
    target = pack.root / "schemas/synthetic.json"
    if mutation == "tampered":
        target.write_bytes(target.read_bytes() + b"\n")
    elif mutation == "deleted":
        target.unlink()
    elif mutation == "new":
        (target.parent / "unlisted.json").write_text("{}")
    elif mutation == "symlink-file":
        actual = pack.root / "actual.json"
        target.rename(actual)
        target.symlink_to(actual)
    elif mutation == "symlink-directory":
        (target.parent / "linked").symlink_to(pack.root / "protocol", target_is_directory=True)
    else:
        (target.parent / "__pycache__").symlink_to(pack.root / "protocol", target_is_directory=True)
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.verify_source_pack(pack.root, pack.protocol)


def test_unreadable_new_directory_cannot_be_omitted_from_coverage(pack, monkeypatch):
    hidden = pack.root / "schemas/unreadable"
    hidden.mkdir()
    (hidden / "new.json").write_text("{}")
    original = os.scandir

    def denied(path):
        if os.fspath(path) == str(hidden):
            raise PermissionError("synthetic inaccessible directory")
        return original(path)

    monkeypatch.setattr(os, "scandir", denied)
    with pytest.raises(consumer.ConsumerCheckError, match="unreadable source directory"):
        consumer.verify_source_pack(pack.root, pack.protocol)


def test_only_real_cache_directories_are_excluded(pack):
    cache = pack.root / "schemas/__pycache__"
    cache.mkdir()
    (cache / "ignored.pyc").write_bytes(b"not imported or executed")
    assert consumer.verify_source_pack(pack.root, pack.protocol) == pack.contents


def test_nonregular_files_fail_without_opening_a_fifo(pack):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO test requires POSIX")
    os.mkfifo(pack.root / "schemas/pipe")
    with pytest.raises(consumer.ConsumerCheckError, match="file type"):
        consumer.verify_source_pack(pack.root, pack.protocol)


@pytest.mark.parametrize("value", [".", "../outside", "/etc/passwd", "schemas/../SPECIFICATION.md", "./SPECIFICATION.md", "schemas//synthetic.json", "schemas\\synthetic.json", "https://example.test/schema"])
def test_source_paths_cannot_traverse_or_change_interpretation(pack, value):
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.local_path(pack.root, value)


def rewrite_manifest(pack, *, repin):
    raw = encoded(pack.manifest)
    (pack.root / consumer.MANIFEST_PATH).write_bytes(raw)
    if repin:
        pack.protocol["manifest_sha256"] = hashlib.sha256(raw).hexdigest()


def test_recomputed_upstream_manifest_cannot_replace_independent_pin(pack):
    path = "schemas/synthetic.json"
    (pack.root / path).write_text("{}")
    next(entry for entry in pack.manifest["files"] if entry["path"] == path)["sha256"] = hashlib.sha256(b"{}").hexdigest()
    rewrite_manifest(pack, repin=False)
    with pytest.raises(consumer.ConsumerCheckError, match="independent consumer pin"):
        consumer.verify_source_pack(pack.root, pack.protocol)


@pytest.mark.parametrize("mutation", ["omitted", "duplicate", "reordered", "extra", "escape", "self-inclusion", "qualification", "boolean-version", "integer-discovery"])
def test_even_reviewed_manifest_bytes_must_satisfy_fixed_coverage_and_metadata(pack, mutation):
    entries = pack.manifest["files"]
    if mutation == "omitted":
        entries.pop()
    elif mutation == "duplicate":
        entries.append(copy.deepcopy(entries[0]))
    elif mutation == "reordered":
        entries.reverse()
    elif mutation == "extra":
        entries[0]["execute"] = True
    elif mutation == "escape":
        entries[0]["path"] = "../../outside"
    elif mutation == "self-inclusion":
        entries.append({"path": consumer.MANIFEST_PATH, "sha256": "0" * 64})
    elif mutation == "qualification":
        pack.manifest["runtime_qualification"] = "QUALIFIED"
    elif mutation == "boolean-version":
        pack.manifest["manifest_version"] = True
    else:
        pack.manifest["public_discovery"] = 0
    rewrite_manifest(pack, repin=True)  # Explicit test trust input, never learned by the checker.
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.verify_source_pack(pack.root, pack.protocol)


def test_source_local_lock_is_not_used_for_trust(pack, monkeypatch):
    malicious = lock()
    malicious["protocol"].update(pack.protocol)
    path = pack.root / "contracts/agent-trust-protocol-consumer.json"
    path.parent.mkdir()
    path.write_bytes(encoded(malicious))
    monkeypatch.setattr(consumer, "verify_revision", lambda *args: None)
    with pytest.raises(consumer.ConsumerCheckError, match="independent consumer pin"):
        consumer.check_consumer(pack.root)


def schema(name, **changes):
    return {"$schema": consumer.DRAFT, "$id": f"https://protocol.elevenid.io/schemas/{name}.json",
            "type": "object", "additionalProperties": False, "required": ["value"],
            "properties": {"value": {"type": "string"}}, **changes}


@pytest.mark.parametrize("reference", ["https://untrusted.example/schema.json", "file:///etc/passwd", "../outside.json", "#/missing"])
def test_unknown_references_fail_without_network_even_in_unexercised_branches(reference, no_network_or_process):
    value = schema("synthetic", properties={"unused": {"$ref": reference}})
    with pytest.raises(consumer.ConsumerCheckError, match="schema or reference"):
        consumer.schema_registry({"schemas/synthetic.json": encoded(value)}, selected_paths=("schemas/synthetic.json",))


def test_selected_transitive_schema_is_checked_but_unrelated_source_is_not_claimed(no_network_or_process):
    root = schema("root", properties={"child": {"$ref": "child.json"}})
    child = schema("child")
    unrelated = schema("legacy-enum", **{"$defs": {"metadata": ["non-schema metadata"]}})
    snapshot = {"schemas/root.json": encoded(root), "schemas/child.json": encoded(child),
                "enums/legacy.json": encoded(unrelated)}
    checked, _ = consumer.schema_registry(snapshot, selected_paths=("schemas/root.json",))
    assert set(checked) == {"schemas/root.json", "schemas/child.json"}
    child["properties"]["unused"] = {"$ref": "https://untrusted.example/schema"}
    snapshot["schemas/child.json"] = encoded(child)
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.schema_registry(snapshot, selected_paths=("schemas/root.json",))


@pytest.mark.parametrize("mutation", ["duplicate-id", "wrong-dialect", "invalid-dependency", "missing-selection"])
def test_schema_identity_and_dependency_failures_are_not_silenced(mutation):
    root, child = schema("root", properties={"child": {"$ref": "child.json"}}), schema("child")
    selected = "schemas/root.json"
    if mutation == "duplicate-id":
        child["$id"] = root["$id"]
    elif mutation == "wrong-dialect":
        child["$schema"] = "http://json-schema.org/draft-07/schema#"
    elif mutation == "invalid-dependency":
        child["type"] = "not-a-type"
    else:
        selected = "schemas/absent.json"
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.schema_registry({"schemas/root.json": encoded(root), "schemas/child.json": encoded(child)},
                                 selected_paths=(selected,))


def test_resolution_error_is_not_an_expected_negative_fixture_rejection(no_network_or_process):
    with pytest.raises(consumer.ConsumerCheckError, match="not an expected fixture rejection"):
        consumer._errors({"$ref": "https://untrusted.example/schema"}, {},
                         Registry(retrieve=consumer._deny_retrieval))


def test_revision_query_is_fixed_local_and_sanitizes_git_overrides(tmp_path, monkeypatch):
    captured = []
    revision = lock()["protocol"]["revision"]
    monkeypatch.setenv("GIT_DIR", "/untrusted")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.sshCommand")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "untrusted-program")
    monkeypatch.setattr(consumer.shutil, "which", lambda name: "/usr/bin/git")

    def run(args, **kwargs):
        captured.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=revision + "\n")

    monkeypatch.setattr(consumer.subprocess, "run", run)
    consumer.verify_revision(tmp_path, revision)
    args, kwargs = captured[0]
    assert args == ["/usr/bin/git", "--no-replace-objects", "-c", f"core.hooksPath={os.devnull}",
                    "-c", "core.fsmonitor=false", "-C", str(tmp_path), "rev-parse", "--verify", "HEAD"]
    assert "GIT_DIR" not in kwargs["env"]
    assert "GIT_CONFIG_COUNT" not in kwargs["env"]
    assert kwargs["env"]["GIT_CONFIG_GLOBAL"] == os.devnull
    assert kwargs["timeout"] == 10
    assert "shell" not in kwargs


@pytest.mark.parametrize("result", [(0, "0" * 40), (1, ""), (0, "main")])
def test_revision_substitution_or_query_failure_denies(tmp_path, monkeypatch, result):
    monkeypatch.setattr(consumer.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(consumer.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=result[0], stdout=result[1]))
    with pytest.raises(consumer.ConsumerCheckError, match="pinned revision"):
        consumer.verify_revision(tmp_path, lock()["protocol"]["revision"])


def shape_corpus():
    """Small synthetic corpus for reporting/negative-result logic only."""
    snapshot, schemas = {"protocol/synthetic.md": b"Synthetic specification"}, {}
    registry = Registry(retrieve=consumer._deny_retrieval)
    for paths in consumer.SELECTED_SCHEMAS.values():
        for path in paths:
            schemas[path] = schema(Path(path).stem)
    schemas["schemas/machine-identity.json"] = schema("machine-identity")
    good, bad = {"value": "ok"}, {"value": "ok", "caller_trusted": True}

    def add(path, value, error=None):
        snapshot[path] = encoded(value)
        if error:
            snapshot[path.removesuffix(".json") + ".expected.json"] = encoded({
                "error_type": error, "field_path": "/caller_trusted",
                "spec_reference": "protocol/synthetic.md#rejection",
            })

    for path in schemas:
        if path.startswith("schemas/agent-trust/v1/"):
            name = Path(path).stem
            add(f"conformance/agent-trust/v1/valid/{name}-synthetic.json", good)
            add(f"conformance/agent-trust/v1/invalid/{name}-synthetic.json", bad, "schema")
    prefix = "conformance/delegated-authority/v1/commands"
    add(f"{prefix}/valid/synthetic.json", good)
    add(f"{prefix}/responses/synthetic.json", good)
    add(f"{prefix}/invalid/synthetic.json", bad, "schema_violation")
    prefix = "conformance/principal-runtime-binding/v1"
    add(f"{prefix}/valid/synthetic.json", {"record": good, "configuration": good})
    add(f"{prefix}/invalid/shape.json", {"record": bad, "configuration": good}, "SCHEMA_INVALID")
    add(f"{prefix}/invalid/binding.json", {"record": good, "configuration": {"value": "other"}}, "TENANT_MISMATCH")
    snapshot[f"{prefix}/manifest.json"] = encoded({
        "profile": "urn:marty:principal-runtime-binding:v1", "status": "REFERENCE_ONLY_NOT_RUNTIME_QUALIFIED",
        "valid": ["valid/synthetic.json"], "invalid": ["invalid/binding.json", "invalid/shape.json"], "vectors": [],
    })
    return snapshot, schemas, registry


def test_fixture_report_keeps_shape_and_semantic_coverage_distinct(no_network_or_process):
    report = consumer.check_fixture_shapes(*shape_corpus())
    assert report == {"positive_schema_fixtures": 9, "negative_schema_fixtures": 8,
                      "semantic_fixture_shapes_only": 1, "semantic_conformance": "NOT_EXECUTED"}


@pytest.mark.parametrize("mutation", ["negative-accepted", "positive-rejected", "missing-sidecar", "unknown-semantic-error", "invalid-semantic-shape", "orphan-sidecar"])
def test_fixture_coverage_cannot_turn_an_unexpected_result_into_a_pass(mutation):
    snapshot, schemas, registry = shape_corpus()
    agent = "conformance/agent-trust/v1/"
    principal = "conformance/principal-runtime-binding/v1/invalid/binding"
    if mutation == "negative-accepted":
        snapshot[agent + "invalid/oauth-context-synthetic.json"] = encoded({"value": "ok"})
    elif mutation == "positive-rejected":
        snapshot[agent + "valid/oauth-context-synthetic.json"] = encoded({"unexpected": True})
    elif mutation == "missing-sidecar":
        del snapshot[agent + "invalid/oauth-context-synthetic.expected.json"]
    elif mutation == "unknown-semantic-error":
        value = json.loads(snapshot[principal + ".expected.json"])
        value["error_type"] = "UNKNOWN_CHECK"
        snapshot[principal + ".expected.json"] = encoded(value)
    elif mutation == "invalid-semantic-shape":
        value = json.loads(snapshot[principal + ".json"])
        value["record"] = {"caller_trusted": True}
        snapshot[principal + ".json"] = encoded(value)
    else:
        snapshot[agent + "invalid/orphan.expected.json"] = encoded({})
    with pytest.raises(consumer.ConsumerCheckError):
        consumer.check_fixture_shapes(snapshot, schemas, registry)


def test_exact_protocol_checkout_when_explicitly_supplied():
    source = os.environ.get("MARTY_AGENT_TRUST_PROTOCOL_ROOT")
    if not source:
        pytest.skip("set MARTY_AGENT_TRUST_PROTOCOL_ROOT to exercise the independently pinned Protocol checkout")
    report = consumer.check_consumer(Path(source))
    assert report["verified_source_files"] == 355
    assert report["verified_schema_documents"] == 14
    assert report["selected_profiles"] == 6
    assert report["positive_schema_fixtures"] == 26
    assert report["negative_schema_fixtures"] == 26
    assert report["semantic_fixture_shapes_only"] == 27
    assert report["semantic_conformance"] == "NOT_EXECUTED"
    assert report["runtime_qualification"] == "NOT_ASSESSED"
    assert report["public_discovery"] is False
