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


def rootless_host():
    value = host(8)
    value["schema"] = "elevenid.installer-host-observation/v2"
    value["runtime"] = dict(profile="rootless", uid=1000,
                            docker_host="unix:///run/user/1000/docker.sock",
                            socket_device=1, socket_inode=7)
    value["rootless_resource_controls"] = dict(cgroup_version="2",
                                              cgroup_driver="systemd", memory_limit=True)
    return value


def observed_rootless_host_with_neighbors():
    value = rootless_host()
    value['resources'] = dict(containers=['a'*64], images=['sha256:'+'b'*64], volumes=['neighbor-data'],
        networks=[dict(id=str(index)*64, name=name, driver=driver, attached_count=0)
                  for index, (name,driver) in enumerate([('bridge','bridge'),('host','host'),('none','null')],1)])
    value['resource_counts'] = dict(containers=1,images=1,volumes=1,networks=3)
    value['predicates']['initial_docker_clean'] = False
    value['development_tool_presence']['git'] = True
    value['credential_file_presence']['docker_config'] = True
    value.update(docker_version='29.1.3',compose_version='5.6.1',limitations=['not an atomic resource snapshot'])
    value['docker_data_filesystem']['device']=1
    return value


@pytest.mark.parametrize('profile', sorted(admission.ROOTLESS_PROFILES))
def test_versioned_rootless_profiles_record_reused_host_without_inventing_cleanliness(profile):
    value = observed_rootless_host_with_neighbors()
    raw = release.encode(value)
    assert admission.host_admission(raw,ENGINE,profile=profile) == value
    assert value['predicates'] == dict(capacity=False,initial_docker_clean=False)
    assert admission.RESOURCE_PROFILES[profile] == 7*1024**3
    with pytest.raises(ValueError):
        admission.host_admission(raw,ENGINE,profile=admission.LEGACY_PROFILE)


@pytest.mark.parametrize('mutation',['count','duplicate','missing','clean','rootful','memory','disk','socket'])
def test_versioned_rootless_profiles_keep_exact_census_identity_and_capacity(mutation):
    value = observed_rootless_host_with_neighbors()
    if mutation=='count': value['resource_counts']['images']=0
    elif mutation=='duplicate': value['resources']['images']*=2
    elif mutation=='missing': value.pop('resources')
    elif mutation=='clean': value['predicates']['initial_docker_clean']=True
    elif mutation=='rootful': value['schema']='elevenid.installer-host-observation/v1'
    elif mutation=='memory': value['docker_memory_bytes']=7*1024**3-1
    elif mutation=='disk': value['docker_data_filesystem']['free_bytes']=20*1024**3-1
    elif mutation=='socket': value['runtime']['docker_host']='unix:///run/user/1001/docker.sock'
    with pytest.raises(ValueError):
        admission.host_admission(release.encode(value),ENGINE,profile=admission.ROOTLESS_STARTUP_PROFILE)


def test_rootless_observation_preserves_selected_socket_and_kernel_resource_controls():
    value = rootless_host()
    assert admission.host_admission(release.encode(value), ENGINE,
                                    profile=admission.STARTUP_PROFILE) == value


@pytest.mark.parametrize("field,value", [
    ("uid", 0), ("uid", True), ("uid", 1001), ("profile", "rootful"),
    ("docker_host", "unix:///var/run/docker.sock"), ("socket_inode", True),
    ("cgroup_version", "1"), ("cgroup_driver", "cgroupfs"),
    ("memory_limit", False), ("memory_limit", 1),
])
def test_rootless_observation_refuses_unbound_or_ineffective_runtime(field, value):
    record = rootless_host()
    target = record["runtime"] if field in record["runtime"] else record["rootless_resource_controls"]
    target[field] = value
    with pytest.raises(ValueError, match="rootless"):
        admission.host_admission(release.encode(record), ENGINE,
                                 profile=admission.STARTUP_PROFILE)


def test_nominal_8gib_startup_profile_preserves_measured_memory_and_legacy_predicate():
    value=host(8)
    value['guest_memory_bytes']-=256*1024**2
    raw=release.encode(value)
    assert admission.host_admission(raw,ENGINE,profile=admission.STARTUP_PROFILE)==value
    assert raw==release.encode(value)
    assert value['predicates']['capacity'] is False
    assert value['acceptance'] is False
    with pytest.raises(ValueError,match='RAM unavailable'):
        admission.host_admission(raw,ENGINE)


@pytest.mark.parametrize('memory',[True,0,-1,'8589934592',7*1024**3-1])
def test_startup_profile_requires_reviewed_guest_visible_floor(memory):
    value=host(8)
    value['guest_memory_bytes']=memory
    with pytest.raises(ValueError,match='RAM unavailable'):
        admission.host_admission(release.encode(value),ENGINE,profile=admission.STARTUP_PROFILE)


@pytest.mark.parametrize('profile',['load','startup',None,{},'production-capacity'])
def test_unreviewed_profile_cannot_bypass_preflight(profile):
    with pytest.raises(ValueError,match='resource profile unsupported'):
        admission.host_admission(release.encode(host(8)),ENGINE,profile=profile)


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
