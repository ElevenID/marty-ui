import copy
import json
import os
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from repair_beta_release_metadata import (
    rendered_delta,
    retire_failed_lock,
    process_identity,
)
from beta_release_metadata import gateway_metadata_model, ui_metadata_model
from scoped_native_runtime import ref


def test_rendered_delta_reuses_model_generators_and_refuses_nonmetadata():
    marker = dict(
        component_revisions={"marty-ui": "a" * 40},
        image_digests={"gateway": "sha256:" + "b" * 64},
    )
    for role in ("gateway", "ui-prod"):
        old = dict(
            services={
                role: dict(
                    image="same",
                    environment={
                        "ELEVENID_COMPONENT_REVISIONS_JSON": "old",
                        "ELEVENID_IMAGE_DIGESTS_JSON": "old",
                    },
                    volumes=[],
                )
            }
        )
        new = (
            gateway_metadata_model(old, marker)
            if role == "gateway"
            else ui_metadata_model(old, "C:/public.json")
        )
        rendered_delta(role, old, new, marker, "C:/public.json")
        bad = copy.deepcopy(new)
        bad["services"][role]["image"] = "changed"
        with pytest.raises(ValueError, match="RENDER_CHANGED_OUTSIDE_METADATA_DELTA"):
            rendered_delta(role, old, bad, marker, "C:/public.json")


def recovery(tmp_path):
    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf8")
        return ref(path)

    source = "a" * 64
    original = save("input.json", dict(sourceSha256=source))
    lock = save(
        "lock.json",
        dict(
            pid=12345,
            creation=100,
            purpose="BETA_GATEWAY_UI_METADATA",
            runId="owned",
            sourceSha256=source,
        ),
    )
    invocation = save("invocation.json", dict(sourceSha256=source, input=original))
    failure = save("failure.json", dict(sourceSha256=source))
    return dict(
        runId="owned",
        sourceSha256=source,
        failedLock=dict(lock=lock, invocation=invocation, failure=failure),
    )


def test_live_original_owner_cannot_retire_lock(tmp_path):
    config = recovery(tmp_path)
    with pytest.raises(ValueError, match="FAILED_OPERATOR_STILL_LIVE"):
        retire_failed_lock(config, lambda pid: dict(pid=pid, creation=100, live=True))
    assert (tmp_path / "lock.json").exists()


def test_exited_original_lock_retirement_preserves_failure(tmp_path):
    config = recovery(tmp_path)
    result = retire_failed_lock(config, lambda pid: None)
    assert result["state"] == "OWNED_FAILED_METADATA_LOCK_RETIRED"
    assert not (tmp_path / "lock.json").exists()
    assert (tmp_path / "failure.json").exists()


def test_actual_process_creation_reader_is_read_only():
    if os.name != "nt":
        pytest.skip("Windows process API")
    row = process_identity(os.getpid())
    assert row["pid"] == os.getpid() and row["live"] and row["creation"] > 0


def test_recovery_context_is_disabled_and_refuses_unknown_create():
    from repair_beta_release_metadata import recovery_context

    original = dict(
        runId="same",
        sourceSha256="a" * 64,
        oldCids={"ui-prod": "b" * 64, "gateway": "c" * 64},
        executeAuthorized=True,
    )
    failed = dict(
        **{k: original[k] for k in ("runId", "sourceSha256", "oldCids")},
        newCids={},
        before={"path": "before"},
        pending="apply-stop-ui-prod",
    )
    result = recovery_context(
        original,
        failed,
        {"path": "state"},
        {"path": "failure"},
        {"path": "invocation"},
        {"path": "lock"},
        "fresh-root",
    )
    assert result["recoveryMode"] == "rollback"
    assert all(
        result[key] is False
        for key in (
            "executeAuthorized",
            "preflightAuthorized",
            "rollbackAuthorized",
            "helperCleanupAuthorized",
            "lockRetirementAuthorized",
        )
    )
    assert result["failedLock"]["failure"] == {"path": "failure"}
    assert original["executeAuthorized"] is True
    failed["pending"] = "apply-create-ui-prod"
    with pytest.raises(
        ValueError, match="UNKNOWN_CREATE_REQUIRES_READONLY_RECONCILIATION"
    ):
        recovery_context(original, failed, {}, {}, {}, {}, "fresh-root")
