"""Pure comparison of independently approved VM identity and observations."""
from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_approval as approval
import installer_release as release


def sample():
    installation_id = str(uuid.uuid4())
    vm_id = str(uuid.uuid4())
    boot_id = str(uuid.uuid4())
    context = dict(source_sha="a" * 40, release_tag="v1.2.3",
                   operator_sha256="b" * 64, phase="staged", nonce="c" * 64,
                   harness_source_sha="d" * 40, run_id=42, run_attempt=1)
    authorization = b"authenticated authorization\n"
    receipt = b"authenticated creation receipt\n"
    observed = dict(
        schema="elevenid.installer-qemu-trial-observation/v2",
        target=dict(guest_id=vm_id, disk_id="e" * 64, engine_id="engine-1",
                    installation_id=installation_id),
        observation_phase="initial-empty", vm_boot_id=boot_id,
        vm_config_sha256="f" * 64, vm_executable_sha256="1" * 64,
        controller_key_sha256="2" * 64, known_hosts_sha256="3" * 64,
        vm_dir_path="/trusted/vm", vm_dir_device=11, vm_dir_inode=12,
        vm_uid=1001, vm_gid=1001, vm_disk_path="/trusted/vm/disk.qcow2",
        ssh_port=49000, guest_user="installer", guest_uid=1000,
        observed_at=1985, vm_pid=1234, vm_start_ticks="12345",
        vm_disk_device=11, vm_disk_inode=13, vm_disk_fd=4,
        vm_memory_mib=4096, vm_cpus=2, initial_docker_clean=True,
        capacity_qualified=False, clean_host_qualified=False,
        dispatch_authorized=False)
    record = dict(
        schema=approval.SCHEMA, purpose="candidate-acceptance",
        approval_id=str(uuid.uuid4()), installation_id=installation_id,
        approved_at=1990, expires_at=2590, controller_boot_id=boot_id,
        vm_id=vm_id, vm_uid=1001, vm_gid=1001, vm_dir_path="/trusted/vm",
        vm_dir_device=11, vm_dir_inode=12, vm_config_sha256="f" * 64,
        vm_executable_sha256="1" * 64, vm_pid=1234, vm_start_ticks="12345",
        disk_path="/trusted/vm/disk.qcow2", disk_device=11, disk_inode=13,
        disk_id="e" * 64, base_image_sha256="4" * 64,
        base_manifest_sha256="5" * 64,
        overlay_creation_receipt_sha256=release.digest(receipt),
        ssh_port=49000, guest_user="installer", guest_uid=1000,
        known_hosts_sha256="3" * 64, controller_key_sha256="2" * 64,
        engine_id="engine-1",
        candidate_context_sha256=release.candidate_context_sha256(context),
        authorization_sha256=release.digest(authorization), nonce="c" * 64)
    return record, observed, context, authorization, receipt


def bind(record, observed, context, authorization, receipt, *, now=2000):
    return approval.bind_observation(release.encode(record), observed,
                                     context=context, authorization=authorization,
                                     creation_receipt=receipt, now=now)


def test_matching_approval_binds_exact_bytes_without_dispatch():
    record, observed, context, authorization, receipt = sample()
    assert bind(record, observed, context, authorization, receipt) == release.digest(
        release.encode(record))
    assert observed["dispatch_authorized"] is False
    with pytest.raises(ValueError, match="not canonical"):
        approval.bind_observation(release.encode(record).replace(b":", b": ", 1),
                                  observed, context=context, authorization=authorization,
                                  creation_receipt=receipt, now=2000)


@pytest.mark.parametrize("observed_at,now", [
    (1939, 2000), (1985, 2046), (2001, 2000), (True, 2000),
    ("1985", 2000), (0, 2000),
])
def test_observation_must_be_recent_and_typed(observed_at, now):
    record, observed, context, authorization, receipt = sample()
    observed["observed_at"] = observed_at
    with pytest.raises(ValueError, match="not fresh"):
        bind(record, observed, context, authorization, receipt, now=now)


def test_approval_scope_and_expiry_are_not_inferred_from_vm():
    record, observed, context, authorization, receipt = sample()
    record["purpose"] = "engineering-trial"
    with pytest.raises(ValueError, match="unavailable"):
        bind(record, observed, context, authorization, receipt)
    record["purpose"] = "candidate-acceptance"
    with pytest.raises(ValueError, match="unavailable"):
        bind(record, observed, context, authorization, receipt, now=2590)


@pytest.mark.parametrize("field,replacement", [
    ("vm_boot_id", str(uuid.uuid4())), ("vm_dir_path", "/trusted/other"),
    ("vm_dir_inode", 14), ("vm_uid", 1002), ("vm_pid", 1235),
    ("vm_start_ticks", "12346"), ("vm_executable_sha256", "9" * 64),
    ("vm_config_sha256", "9" * 64), ("vm_disk_inode", 14),
    ("vm_disk_device", 14), ("ssh_port", 49001),
    ("guest_user", "other"), ("guest_uid", 1001),
    ("known_hosts_sha256", "9" * 64), ("controller_key_sha256", "9" * 64),
])
def test_observed_identity_substitution_rejected(field, replacement):
    record, observed, context, authorization, receipt = sample()
    observed[field] = replacement
    with pytest.raises(ValueError, match="differs|invalid"):
        bind(record, observed, context, authorization, receipt)


@pytest.mark.parametrize("field,replacement", [
    ("guest_id", str(uuid.uuid4())), ("disk_id", "9" * 64),
    ("engine_id", "engine-2"), ("installation_id", str(uuid.uuid4())),
])
def test_target_substitution_rejected(field, replacement):
    record, observed, context, authorization, receipt = sample()
    observed["target"][field] = replacement
    with pytest.raises(ValueError):
        bind(record, observed, context, authorization, receipt)


def test_candidate_and_creation_substitutions_rejected():
    record, observed, context, authorization, receipt = sample()
    for changed_context, changed_auth, changed_receipt in (
        (dict(context, source_sha="f" * 40), authorization, receipt),
        (dict(context, nonce="f" * 64), authorization, receipt),
        (context, b"different authorization", receipt),
        (context, authorization, b"different creation receipt"),
    ):
        with pytest.raises(ValueError, match="candidate or creation differs"):
            bind(record, observed, changed_context, changed_auth, changed_receipt)


@pytest.mark.parametrize("mutation", [
    lambda record: record.update(extra=True),
    lambda record: record.update(vm_uid=True),
    lambda record: record.update(approval_id="invalid"),
    lambda record: record.update(base_image_sha256="invalid"),
    lambda record: record.update(disk_path="/trusted/other/disk.qcow2"),
])
def test_malformed_approval_rejected(mutation):
    record, observed, context, authorization, receipt = sample()
    mutation(record)
    with pytest.raises(ValueError):
        bind(record, observed, context, authorization, receipt)
