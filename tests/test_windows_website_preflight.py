"""Managed website inspection uses held ownership and read-only transports."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import deploy_website as deploy
import selfhost_windows_website as website
import website_host_owner as owner
from test_selfhost_windows_renewal import PROJECT, model as renewal_model, states


PRIVATE = "PRIVATE_VALUE_MUST_NEVER_APPEAR_IN_DIAGNOSTICS"
OWNER_ROOT = PureWindowsPath(r"C:\Marty\production")
TEMPLATE_SOURCE = OWNER_ROOT / "config" / "edge.template"
TEMPLATE_BODY = b"include /etc/nginx/marty-website/*.conf;\nlocation = /edge-healthz {\n}\n"


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    old_root, new_root = tmp_path / "old", tmp_path / "new"
    models = {}
    for side, root in (("old", old_root), ("new", new_root)):
        model = renewal_model(root)
        model["services"]["ui"] = {"image": website.ui.COMMERCE_IMAGE + "@sha256:" + "2" * 64,
                                    "environment": {"APPLICATION_PASSWORD": PRIVATE}}
        model["services"]["edge"] = {"image": "nginx@sha256:" + "4" * 64,
            "healthcheck": {"test": ["CMD", "wget", "http://127.0.0.1/edge-healthz"]}}
        for role in website.product.PROVIDER_ROLES:
            model["services"][role]["image"] = "ghcr.io/elevenid/openbao-didcomm@sha256:" + "3" * 64
        models[side] = model
    config = {"project": PROJECT, "docker_host": "npipe:////./pipe/dockerDesktopLinuxEngine",
              "engine_id": "PUBLIC_SYNTHETIC_ENGINE", "compose_file": str(tmp_path / "model.json"),
              "compose_sha256": "c" * 64, "current_env": str(tmp_path / "old.env"),
              "renewed_env": str(tmp_path / "new.env"), "current_secrets": str(old_root),
              "renewed_secrets": str(new_root)}
    selected = models["new"]
    hashes = {role: f"{index + 1:064x}" for index, role in enumerate(selected["services"])}
    ids = {spec["image"]: "sha256:" + hashlib.sha256(spec["image"].encode()).hexdigest()
           for spec in selected["services"].values()}
    items = []
    for index, row in enumerate(states(selected)):
        role = row["Service"]
        spec = selected["services"][role]
        image = spec["image"]
        item = {"Id": f"{index + 1:064x}", "Image": ids[image],
                "Config": {"Image": image, "Env": ["PRIVATE=" + PRIVATE],
                           "Labels": {"com.docker.compose.project": PROJECT,
                                      "com.docker.compose.service": role,
                                      "com.docker.compose.config-hash": hashes[role]}},
                "State": {"Status": row["State"], "ExitCode": row["ExitCode"]},
                "Mounts": [{"Type": "bind", "Source": str(new_root / entry["source"]),
                            "Destination": entry["target"], "RW": False}
                           for entry in spec.get("secrets", [])]}
        if role == "openbao-tls-init":
            item["Image"] = "sha256:" + "9" * 64
            item["Config"]["Image"] = "historical.invalid/initializer@sha256:" + "9" * 64
            config["tls_init_receipt"] = {"id": item["Id"], "image": item["Image"], "config_hash": hashes[role]}
        if role == "gateway":
            item["State"]["Status"] = "restarting"  # Inspection makes no readiness claim.
        items.append(item)
    record = {"sequence": 9, "data_sha256": website.selection.digest(website.selection.packed(website.renewal.data_mounts(items)))}
    manifest = {"composition_id": "sha256:" + "a" * 64,
                "website": {"revision": "a" * 40 + "-" + "b" * 40},
                "backend": {"release_tag": "v1.1.274"}, "production_pages": "full",
                "images": {role: spec["image"] for role, spec in selected["services"].items()
                           if role not in website.product.PROVIDER_ROLES},
                "openbao_didcomm_image": selected["services"]["openbao"]["image"]}
    values = {"old": {name: PRIVATE.encode() for name in models["old"]["secrets"]}}
    events = []
    live = {"held": False, "reads": 0, "after": None, "exit_error": False, "proof_error": False,
            "late_input_error": False, "inputs": {}}
    proof = tmp_path / "payload" / "website" / "website-release.json"
    proof.parent.mkdir(parents=True)
    proof.write_text('{"schema":"marty.website-release/v1"}', encoding="utf-8")

    class Docker:
        prefix = ["docker", "--host", config["docker_host"]]

        def __init__(self, host, engine):
            assert live["held"] and host == config["docker_host"] and engine == config["engine_id"]
            events.append("info")

        def compose(self, project, env, source):
            assert project == PROJECT and source == Path(config["compose_file"])
            return [*self.prefix, "compose", "--project-name", project, "--env-file", str(env), "-f", str(source)]

        def json(self, args):
            assert live["held"]
            events.append(tuple(args))
            if args[:2] == ["image", "inspect"]:
                assert len(args) == 3
                return [{"Id": ids[args[2]]}]
            assert args[0] == "compose" and args[-5:] == ["--profile", "*", "config", "--format", "json"]
            side = "old" if config["current_env"] in args else "new"
            return deepcopy(models[side])

        def containers(self):
            assert live["held"]
            events.append("inspect-containers")
            live["reads"] += 1
            result = deepcopy(items)
            if live["after"] and live["reads"] == 2:
                live["after"](result)
            return result

        def hashes(self, _command):
            assert live["held"]
            events.append("compose-config-hashes")
            return hashes

        def native_witnesses(self, *_args):
            pytest.fail("read-only website preflight must never create kernel-witness containers")

        def volumes(self):
            pytest.fail("preflight does not claim a foreign-storage custody proof")

    @contextmanager
    def verified(assets, **kwargs):
        assert live["held"] and assets == tmp_path / "composition"
        assert kwargs == {"gh": tmp_path / "gh", "cosign": tmp_path / "cosign", "registry_config": tmp_path / "registry.json"}
        events.append("proof-enter")
        if live["proof_error"]:
            raise ValueError(PRIVATE)
        yield deepcopy(manifest), tmp_path / "payload"
        events.append("proof-exit")

    @contextmanager
    def selected_inputs(path):
        assert path == tmp_path / "selection.json"
        live["held"] = True
        events.append("lease-enter")
        try:
            with ExitStack() as held:
                yield SimpleNamespace(generation_sequence=33, selected_sha256="d" * 64,
                    check_website_composition=lambda assets, **kwargs: website.inspect_composition(
                        config, "new", values, record, assets, owner_root=OWNER_ROOT, held=held, **kwargs))
        finally:
            live["held"] = False
            events.append("lease-exit")
            if live["exit_error"]:
                raise ValueError(PRIVATE)

    @contextmanager
    def hold_input(path, *, max_bytes):
        assert live["held"]
        value = live["inputs"][path]
        assert len(value) <= max_bytes
        events.append(("hold-input", path))
        yield value
        events.append(("release-input", path))
        if path == Path(str(TEMPLATE_SOURCE)) and live["late_input_error"]:
            raise ValueError(PRIVATE)

    monkeypatch.setattr(website.renewal, "Docker", Docker)
    monkeypatch.setattr(website.renewal, "hold_private_input", hold_input)
    monkeypatch.setattr(website.renewal, "windows_mount_path_equal", lambda left, right: left == right)
    monkeypatch.setattr(website.composition, "verified_package", verified)
    monkeypatch.setattr(website.selection, "selected_inputs", selected_inputs)
    kwargs = {"gh": tmp_path / "gh", "cosign": tmp_path / "cosign", "registry_config": tmp_path / "registry.json"}
    return SimpleNamespace(config=config, manifest=manifest, models=models, items=items, record=record,
                           live=live, events=events, kwargs=kwargs, root=tmp_path, proof=proof)


def run(runtime):
    return website.check(runtime.root / "selection.json", runtime.root / "composition", **runtime.kwargs)


def prepare_full_standalone(runtime, *, fault=None):
    runtime.proof.write_text(json.dumps({"schema": website.web.STANDALONE_FULL_RELEASE_SCHEMA}), encoding="utf-8")
    declared = {"source": TEMPLATE_SOURCE.as_posix(), "target": website.TEMPLATE_TARGET,
                "type": "bind", "read_only": True}
    for model in runtime.models.values():
        model["services"]["edge"]["volumes"] = [deepcopy(declared)]
    source = deepcopy(runtime.models["new"])
    mounted = {"Type": "bind", "Source": "/run/desktop/mnt/host/c/Marty/production/config/edge.template",
               "Destination": website.TEMPLATE_TARGET, "RW": False}
    edge = next(item for item in runtime.items if website.renewal._service(item) == "edge")
    edge["Mounts"] = [mounted]
    template = TEMPLATE_BODY
    if fault == "source-render-mismatch":
        source["services"]["edge"]["volumes"][0]["source"] = "C:/Marty/production/config/other.template"
    elif fault == "aliased-route-target":
        source["services"]["edge"]["volumes"].append(
            {**declared, "target": "/etc/nginx//marty-website"})
    elif fault == "route-overmount":
        edge["Mounts"].append({"Type": "bind", "Destination": "/etc/nginx", "Source": mounted["Source"], "RW": False})
    elif fault == "writable-template":
        mounted["RW"] = True
    elif fault == "missing-include":
        template = template.replace(b"include ", b"# include ")
    runtime.record["data_sha256"] = website.selection.digest(website.selection.packed(website.renewal.data_mounts(runtime.items)))
    body = website.selection.packed(source)
    runtime.config["compose_sha256"] = website.selection.digest(body)
    runtime.live["inputs"] = {Path(runtime.config["compose_file"]): body, Path(str(TEMPLATE_SOURCE)): template}
    return mounted


def test_full_cutover_preflight_holds_exact_combined_edge_through_final_readback(runtime):
    mounted = prepare_full_standalone(runtime)
    result = run(runtime)
    assert result["mounted_edge_template_checked"] and result["combined_edge_template"] == {
        "sha256": website.selection.digest(TEMPLATE_BODY), "bytes": len(TEMPLATE_BODY),
        "runtime_mount_sha256": website.selection.digest(website.selection.packed(mounted))}
    assert not result["activation_supported"] and not result["public_ingress_checked"]
    template = Path(str(TEMPLATE_SOURCE))
    assert runtime.events.index(("hold-input", template)) < len(runtime.events) - 4
    assert runtime.events[-5:] == ["inspect-containers", "proof-exit",
        ("release-input", template), ("release-input", Path(runtime.config["compose_file"])), "lease-exit"]
    assert str(TEMPLATE_SOURCE) not in json.dumps(result)


@pytest.mark.parametrize("fault", [
    "source-render-mismatch", "aliased-route-target", "route-overmount", "writable-template", "missing-include",
])
def test_combined_edge_preflight_refuses_unsafe_source_mount_or_content(runtime, fault):
    prepare_full_standalone(runtime, fault=fault)
    with pytest.raises(ValueError):
        run(runtime)
    assert (("hold-input", Path(str(TEMPLATE_SOURCE))) in runtime.events) == (fault == "missing-include")


def test_combined_edge_preflight_withholds_result_on_late_input_failure(runtime):
    prepare_full_standalone(runtime)
    runtime.live["late_input_error"] = True
    with pytest.raises(ValueError, match=PRIVATE):
        run(runtime)


def test_authenticated_preflight_preserves_historical_initializer_and_never_claims_activation(runtime):
    result = run(runtime)
    assert result["inspection_completed"] and result["composition_authenticated"]
    assert result["composition_matches_selected_product"] and result["compatibility_blockers"] == []
    assert result["selection_sequence"] == 9 and result["generation_sequence"] == 33
    assert result["historical_tls_initializer_preserved"] and result["installed_image_bytes_verified"]
    assert not result["activation_supported"] and not result["production_admission"]
    assert not any(result[name] for name in ("runtime_readiness_checked", "native_custody_checked",
        "foreign_storage_custody_checked", "mounted_edge_template_checked", "public_ingress_checked"))
    assert result["combined_edge_template"] is None
    assert runtime.events[0] == "lease-enter" and runtime.events[-2:] == ["proof-exit", "lease-exit"]
    assert PRIVATE not in json.dumps(result)
    assert str(runtime.root) not in json.dumps(result)


def test_public_v273_selection_reports_original_full_application_and_pin_mismatches(runtime):
    runtime.manifest["production_pages"] = "public"
    runtime.manifest["backend"]["release_tag"] = "v1.1.273"
    runtime.manifest["images"]["ui"] = website.ui.PUBLIC_IMAGE + "@sha256:" + "8" * 64
    result = run(runtime)
    assert not result["composition_matches_selected_product"]
    assert result["installed_application_audience"] == "full"
    assert result["compatibility_blockers"] == ["product_image_pins_differ", "website_audience_differs"]
    assert result["product_image_mismatch_roles"] == ["ui"]


@pytest.mark.parametrize("change, blocker", [
    ("product-pin", "product_image_pins_differ"),
    ("provider-pin", "openbao_image_pins_differ"),
    ("extra-receipt-role", "product_role_closure_differs"),
    ("edge-dependency", "edge_configuration_is_not_independent"),
])
def test_comparison_does_not_adopt_incompatible_product_or_edge(runtime, change, blocker):
    model, manifest = deepcopy(runtime.models["new"]), deepcopy(runtime.manifest)
    if change == "product-pin":
        manifest["images"]["gateway"] = "example.invalid/other@sha256:" + "5" * 64
    elif change == "provider-pin":
        manifest["openbao_didcomm_image"] = "example.invalid/other@sha256:" + "5" * 64
    elif change == "extra-receipt-role":
        manifest["images"]["unexpected"] = manifest["images"]["gateway"]
    else:
        model["services"]["edge"]["depends_on"] = {"gateway": {"condition": "service_healthy"}}
    result = website.compatibility(model, manifest)
    assert blocker in result["compatibility_blockers"] and not result["composition_matches_selected_product"]


@pytest.mark.parametrize("change", ["container-image", "container-config", "data-mounts", "tls-running", "late-identity"])
def test_changed_managed_identity_refuses_without_returning_a_report(runtime, change):
    gateway = next(item for item in runtime.items if website.renewal._service(item) == "gateway")
    if change == "container-image":
        gateway["Image"] = "sha256:" + "0" * 64
    elif change == "container-config":
        gateway["Config"]["Labels"]["com.docker.compose.config-hash"] = "0" * 64
    elif change == "data-mounts":
        runtime.record["data_sha256"] = "0" * 64
    elif change == "tls-running":
        next(item for item in runtime.items if website.renewal._service(item) == "openbao-tls-init")["State"]["Status"] = "running"
    else:
        runtime.live["after"] = lambda items: items[0].update(Id="f" * 64)
    with pytest.raises(ValueError):
        run(runtime)
    assert runtime.events[-1] == "lease-exit"


@pytest.mark.parametrize("failure", ["proof_error", "exit_error"])
def test_cli_withholds_private_errors_and_uncommitted_results(runtime, capsys, failure):
    runtime.live[failure] = True
    args = ["--check-only", "--selection-file", str(runtime.root / "selection.json"),
            "--composition-dir", str(runtime.root / "composition")]
    for name, path in runtime.kwargs.items():
        args += ["--" + name.replace("_", "-"), str(path)]
    assert website.main(args) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err == website.ERROR + "\n"
    assert PRIVATE not in output.err
    if failure == "proof_error":
        assert "info" not in runtime.events


def ordinary_host(root):
    checkout = root / "checkout"
    checkout.mkdir(exist_ok=True)
    generation = root / "managed-root" / "generation" / "activation"
    generation.mkdir(parents=True, exist_ok=True)
    paths = [generation / name for name in ("compose.yml", "env", "bao.yml", "bao.env")]
    for path in paths:
        path.write_text("nonempty fixture")
    return dict(stack=checkout, project=PROJECT, compose_files=[paths[0]], env_file=paths[1],
                openbao_file=paths[2], openbao_env_file=paths[3], openbao_project="test-bao",
                public_origin="https://example.org"), root / "managed-root"


@pytest.mark.parametrize("marker", owner.MARKERS)
def test_ordinary_owner_refuses_retained_managed_ancestors_before_state_or_docker(tmp_path, monkeypatch, marker):
    kwargs, managed_root = ordinary_host(tmp_path)
    (managed_root / ("." + PROJECT + "." + marker)).mkdir()
    monkeypatch.setattr(deploy.subprocess, "run", lambda *_a, **_k: pytest.fail("no Docker command allowed"))
    with pytest.raises(ValueError, match="Managed Windows generation ownership"):
        deploy.DockerHost(**kwargs)
    assert not (kwargs["stack"] / ".marty-website").exists()


def test_owner_guard_rechecks_before_docker_and_preserves_v1_identity(tmp_path, monkeypatch):
    kwargs, managed_root = ordinary_host(tmp_path)
    host = deploy.DockerHost(**kwargs)
    assert host.identity() == {"stack_directory": str(kwargs["stack"]), "project": PROJECT,
        "compose_files": [str(path) for path in kwargs["compose_files"]], "env_file": str(kwargs["env_file"]),
        "openbao_compose_file": str(kwargs["openbao_file"]), "openbao_env_file": str(kwargs["openbao_env_file"]),
        "openbao_project": "test-bao", "public_origin": "https://example.org", "ca_file": None}
    (managed_root / ("." + PROJECT + ".renewal.lock")).write_bytes(b"")
    monkeypatch.setattr(deploy.subprocess, "run", lambda *_a, **_k: pytest.fail("no Docker command allowed"))
    with pytest.raises(ValueError, match="Managed Windows generation ownership"):
        host.run(["docker", "compose", "up", "-d", "edge"])


def test_owner_guard_refuses_dangling_entries_and_unknown_metadata(tmp_path, monkeypatch):
    marker = tmp_path / ("." + PROJECT + ".generation-selection")
    try:
        marker.symlink_to(tmp_path / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="Managed Windows generation ownership"):
        owner.require_ordinary_owner(PROJECT, [tmp_path])
    marker.unlink()
    original = Path.lstat
    def unavailable(path, *_args, **_kwargs):
        if path == marker:
            raise PermissionError(PRIVATE)
        return original(path)
    monkeypatch.setattr(Path, "lstat", unavailable)
    with pytest.raises(ValueError, match="owner metadata is unavailable") as error:
        owner.require_ordinary_owner(PROJECT, [tmp_path])
    assert PRIVATE not in str(error.value)


def test_owner_guard_refuses_symlink_that_hides_the_managed_root(tmp_path):
    managed = tmp_path / "managed"
    generation = managed / "generation"
    generation.mkdir(parents=True)
    (managed / ("." + PROJECT + ".generation-selection")).mkdir()
    alias = tmp_path / "unmanaged-looking-alias"
    try:
        alias.symlink_to(generation, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="reparse points or symlink ancestors"):
        owner.require_ordinary_owner(PROJECT, [alias])


def test_owner_guard_refuses_windows_junction_metadata_before_following_children(tmp_path, monkeypatch):
    junction = tmp_path / "junction"
    child = junction / "config"
    child.mkdir(parents=True)
    original = Path.lstat
    def metadata(path, *_args, **_kwargs):
        assert path != child, "junction children must not be traversed"
        info = original(path)
        if path == junction:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=owner.stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return info
    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(ValueError, match="reparse points or symlink ancestors"):
        owner.require_ordinary_owner(PROJECT, [child])
