"""Synthetic source contracts only; no canonical receipt or cutover proof."""
from copy import deepcopy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_passport_successor as successor
import scoped_beta_binary_overlay as overlay
from scoped_native_build import build_scope
from scoped_native_runtime import selected_sources


def fixture():
    prepared = dict(buildProfile="oid4vc-all-services", uiRevision=successor.SOURCE,
                    coreRevision=successor.CORE, runId="synthetic-control-only",
                    roleBinaries=dict(successor.OFFICIAL_ALL_SERVICES.roles))
    receipt = prepared | dict(state="PASSED", exitCode=0, oomKilled=False,
        canonicalAllServices=True, source=successor.SOURCE,
        preparationSha256=successor.PREPARED_SHA256, imagesBuilt=False,
        releaseQualified=False, recordingQualified=False,
        binaries={key: {} for key in prepared["roleBinaries"]})
    return prepared, receipt


def test_terminal_all29_contract_cannot_be_replaced_by_three_successes():
    prepared, receipt = fixture()
    successor.terminal_build(receipt, prepared, successor.PREPARED_SHA256)
    for change in (dict(state="BUILD_RUNNING"), dict(exitCode=1), dict(exitCode=False),
                   dict(oomKilled=True), dict(canonicalAllServices=False),
                   dict(uiRevision="a" * 40), dict(coreRevision="a" * 40),
                   dict(releaseQualified=True), dict(recordingQualified=True),
                   dict(binaries={key: {} for key in successor.ROLE_BINARIES.values()})):
        with pytest.raises(ValueError):
            successor.terminal_build(receipt | change, prepared, successor.PREPARED_SHA256)


def test_rollout_is_not_another_build_scope_and_only_creates_before_inspection():
    plan = dict(rolloutProfile=successor.PROFILE, uiRevision=successor.SOURCE,
                coreRevision=successor.CORE, roleBinaries=successor.ROLE_BINARIES,
                releaseQualified=False, recordingQualified=False)
    selected_sources(plan, successor.PROFILE)
    with pytest.raises(ValueError):
        build_scope(successor.PROFILE)
    for roles in (["gateway"], ["gateway", "gateway", "flow"], []):
        with pytest.raises(ValueError):
            overlay.overlay_roles(successor.PROFILE, roles)
    args = ["docker", "compose", "-p", "elevenid-beta", "--project-directory", "/owned", "-f", "/owned/base.yml"]
    result = overlay.compose_recreate_arguments(args, "/owned/subset.yml", successor.PROFILE, no_start=True)
    assert "--no-start" in result and "--detach" not in result
    assert set(result[-3:]) == set(successor.ROLE_BINARIES)
    with pytest.raises(ValueError):
        overlay.compose_recreate_arguments(args, "/owned/subset.yml", successor.PROFILE)


def test_new_schema_cli_is_not_attributed_to_frozen_all29_binary():
    required = successor.migration_requirements()
    assert required["flowCliAvailableInD2de"] is False
    assert required["separateSourceBoundMigrationToolBuildRequired"] is True
    assert required["matchingMigrationSqlAndSchemaHashesRequired"] is True
    assert required["applyEnabled"] is False
    assert required["historicalSqlHandoffPermitted"] is False


def test_no_local_receipt_or_unbound_reader_substitutes_for_original_journal(tmp_path, monkeypatch):
    prepared, receipt = fixture()
    prepared["journalBackend"] = {"backend": "CONTROL_ONLY"}
    a, b = tmp_path / "prepared.json", tmp_path / "receipt.json"
    a.write_text(json.dumps(prepared))
    b.write_text(json.dumps(receipt))
    # Isolate the authority check with synthetic bytes. The production read_ref
    # is never replaced outside this source test; these are not real receipts.
    monkeypatch.setattr(successor, "read_ref", lambda bound, *args: a if bound["path"] == str(a) else b)
    class LocalMirror:
        def invoke(self, *args):
            pytest.fail("An unbound local reader must not be invoked")
    with pytest.raises(ValueError, match="ORIGINAL_SHARED_BUILD_JOURNAL_REQUIRED"):
        successor.select_canonical_binaries({"path": str(a), "sha256": successor.PREPARED_SHA256},
                                            {"path": str(b), "sha256": "a" * 64}, LocalMirror())


def test_python_v2_context_preserves_markers_and_rejects_drift(tmp_path, monkeypatch):
    from scripts import beta_passport_functional_audit as audit
    from types import SimpleNamespace
    import hashlib
    path = tmp_path / "observation.json"
    value = dict(schema="marty.canvas-functional-runtime-observation/v2",
                 scope="FUNCTIONAL_ONLY", profileSha256="c" * 64,
                 releaseQualified=False, recordingQualified=False)
    path.write_bytes(json.dumps(value).encode())
    context = dict(kind="FUNCTIONAL_RUNTIME_V2", profileSha256="c" * 64,
                   receiptSha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                   scope="FUNCTIONAL_ONLY", releaseQualified=False, recordingQualified=False)
    monkeypatch.delenv("DEMO_LOCAL_NATIVE_OVERLAY_RECEIPT", raising=False)
    monkeypatch.setenv("DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT", str(path))
    monkeypatch.setenv("DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256", context["receiptSha256"])
    monkeypatch.setenv("RECORD_VIDEO", "0")
    capture = SimpleNamespace(native_runtime_binding=None, functional_runtime_binding=context)
    assert audit.local_native_overlay_binding(capture, "b" * 40) == context
    for change in ({"profileSha256": "d" * 64}, {"receiptSha256": "d" * 64},
                   {"releaseQualified": True}, {"recordingQualified": 0}, {"extra": True}):
        bad = deepcopy(capture)
        bad.functional_runtime_binding = context | change
        with pytest.raises(ValueError):
            audit.local_native_overlay_binding(bad, "b" * 40)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        audit.local_native_overlay_binding(capture, "b" * 40)
