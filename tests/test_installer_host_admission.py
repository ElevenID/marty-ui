"""Host policy boundaries, independent of Linux controller/SSH transport."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_host_admission as admission
import installer_release as release

ENGINE = "test-engine-12345678"


def host(gib=4):
    return dict(
        schema="elevenid.installer-host-observation/v1", acceptance=False,
        engine_id=ENGINE, docker_memory_bytes=gib * 1024**3,
        guest_memory_bytes=gib * 1024**3,
        docker_data_filesystem=dict(free_bytes=20 * 1024**3),
        predicates=dict(capacity=gib >= 32, initial_docker_clean=True),
        resource_counts=dict(containers=0, images=0, volumes=0, networks=3),
        credential_environment_names=[],
        credential_file_presence=dict(docker_config=False, containers_auth=False,
                                      runtime_containers_auth=False),
        development_tool_presence=dict.fromkeys(admission.DEVTOOLS, False),
    )


def test_small_host_admits_only_engineering_and_retains_raw_measurement():
    value = host()
    raw = release.encode(value)
    with pytest.raises(ValueError, match="qualification RAM unavailable"):
        admission.host_admission(raw, ENGINE)
    assert admission.engineering_host_admission(raw, ENGINE) == value
    assert raw == release.encode(value)
    assert value["acceptance"] is False
    assert value["predicates"]["capacity"] is False


def test_qualification_capacity_still_admits_production():
    value = host(32)
    assert admission.host_admission(release.encode(value), ENGINE) == value


@pytest.mark.parametrize("policy", [admission.host_admission,
                                   admission.engineering_host_admission])
@pytest.mark.parametrize("change", ["engine", "dirty", "credential", "disk",
                                    "capacity", "acceptance", "tools"])
def test_admission_keeps_identity_cleanliness_and_disk_guards(policy, change):
    value = host(32)
    if change == "engine":
        value["engine_id"] = "wrong-engine"
    elif change == "dirty":
        value["resource_counts"]["containers"] = 1
    elif change == "credential":
        value["credential_file_presence"]["docker_config"] = True
    elif change == "disk":
        value["docker_data_filesystem"]["free_bytes"] = 1
    elif change == "acceptance":
        value["acceptance"] = True
    elif change == "tools":
        value["development_tool_presence"]["git"] = True
    else:
        value["predicates"]["capacity"] = False
    with pytest.raises(ValueError):
        policy(release.encode(value), ENGINE)


@pytest.mark.parametrize("memory", [True, 0, -1, "4294967296"])
def test_engineering_requires_real_positive_memory_measurement(memory):
    value = host()
    value["guest_memory_bytes"] = memory
    with pytest.raises(ValueError, match="RAM measurement unavailable"):
        admission.engineering_host_admission(release.encode(value), ENGINE)
