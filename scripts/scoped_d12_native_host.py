"""Read-only D12 host preflight bindings over reviewed source and transport.

The caller supplies an already pinned Docker reader and Compose config reader.
This module has no process launcher, mutating Docker command, SQL or authority
writer. It cannot serve the effectful D12CurrentExecution.run context.
"""
from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path

import scoped_native_runtime as shared
import scoped_native_profiles as profiles
import scoped_passport_successor as successor
import scoped_beta_binary_overlay as overlay
import scoped_passport_maintenance as maintenance
from scoped_native_runtime import read_ref, require, sha
from scoped_passport_successor import CURRENT_PROFILE

# Reuse the existing source-closure receipt shape. The Git object reader is
# supplied by the maintained source exporter; it performs read-only Git calls.
ORIGIN = "https://github.com/ElevenID/marty-ui.git"
MANDATORY = frozenset("scripts/" + name for name in (
    "scoped_native_runtime.py", "scoped_native_profiles.py",
    "scoped_passport_successor.py", "scoped_passport_maintenance.py",
    "scoped_beta_binary_overlay.py", "scoped_d12_native_execution.py",
    "scoped_d12_native_host.py", "scoped_d12_native_effect_host.py"))

PROJECTS = ("elevenid-beta", "elevenid-beta-ui")

def _json(raw):
    return json.loads(raw if isinstance(raw, (bytes, str)) else raw.decode("utf-8"))

class D12ReadOnlyHost:
    def __init__(self, inputs, *, docker_read, compose_read, git_read):
        require(inputs.get("schema") == "marty.d12-readonly-host-input/v1"
                and inputs.get("dispatchEnabled") is False, "D12_READONLY_SCOPE_REQUIRED")
        self._docker, self._compose = docker_read, compose_read
        require(all(callable(fn) for fn in (docker_read, compose_read, git_read)),
                "D12_READ_TRANSPORT_REQUIRED")
        root = Path(inputs["sourceRoot"]).resolve()
        receipt_path = read_ref(inputs["sourceClosure"]).resolve()
        require(root.is_dir() and not root.is_symlink(),
                "D12_EXACT_SOURCE_CLOSURE_REQUIRED")
        receipt = _json(receipt_path.read_bytes())
        revision, tree = receipt.get("operatorRevision"), receipt.get("operatorTree")
        files = receipt.get("files")
        require(receipt.get("schema") == "marty.d12-db-preview-source-closure/v2"
                and receipt.get("applyAuthorized") is False
                and receipt.get("runtimeDeployed") is False
                and isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision)
                and isinstance(tree, str) and re.fullmatch(r"[a-f0-9]{40}", tree)
                and isinstance(files, dict) and MANDATORY <= set(files)
                and len(files) <= 128, "D12_REVIEWED_SOURCE_RECEIPT_REQUIRED")
        repo = Path(inputs["sourceRepository"]).resolve()
        require(repo.is_dir() and git_read(repo, "remote", "get-url", "origin").decode().strip() == ORIGIN
                and git_read(repo, "cat-file", "-t", revision).decode().strip() == "commit"
                and git_read(repo, "rev-parse", revision + "^{tree}").decode().strip() == tree,
                "D12_GIT_SOURCE_IDENTITY_CHANGED")
        for name, row in files.items():
            relative = Path(name)
            require(not relative.is_absolute() and ".." not in relative.parts
                    and (name.startswith("scripts/") or name.startswith("tests/scripts/")
                         or name.startswith("rust/services/"))
                    and isinstance(row, dict) and isinstance(row.get("gitBlob"), str)
                    and re.fullmatch(r"[a-f0-9]{40}", row["gitBlob"]), "D12_SOURCE_FILE_SCOPE_CHANGED")
            source = root / relative
            require(source.resolve() == source and source.is_file() and not source.is_symlink()
                    and source.stat().st_size == row.get("bytes")
                    and sha(source) == row.get("sha256")
                    and git_read(repo, "rev-parse", revision + ":" + name).decode().strip() == row["gitBlob"]
                    and git_read(repo, "show", revision + ":" + name) == source.read_bytes(),
                    "D12_GIT_EXPORTED_SOURCE_CHANGED:" + name)
        for module, name in ((shared, "scoped_native_runtime.py"),
                             (profiles, "scoped_native_profiles.py"),
                             (successor, "scoped_passport_successor.py"),
                             (maintenance, "scoped_passport_maintenance.py"),
                             (overlay, "scoped_beta_binary_overlay.py")):
            source = root / "scripts" / name
            require(Path(module.__file__).resolve() == source
                    and sha(module.__file__) == files["scripts/" + name]["sha256"],
                    "D12_LOADED_SOURCE_CHANGED:" + name)
        host = read_ref(inputs["hostSource"]).resolve()
        require(host == Path(__file__).resolve() == root / "scripts" / "scoped_d12_native_host.py"
                and sha(host) == files["scripts/scoped_d12_native_host.py"]["sha256"],
                "D12_HOST_SOURCE_CHANGED")
        self.source_provenance = {"operatorRevision": revision, "operatorTree": tree,
            "executorSourceSha256": files["scripts/scoped_d12_native_execution.py"]["sha256"],
            "hostSourceSha256": files["scripts/scoped_d12_native_host.py"]["sha256"]}
        self._root = root
        self._source_closure_ref = deepcopy(inputs["sourceClosure"])
        self._source_files = deepcopy(files)
        self._host_ref = deepcopy(inputs["hostSource"])
        before = _json(read_ref(inputs["runtimeBefore"]).read_bytes())
        self.before = maintenance.exact_roles(before, CURRENT_PROFILE)
        self.binding = before
        require(set(inputs["composeArguments"]) == set(PROJECTS), "D12_TWO_PROJECT_ARGUMENTS_REQUIRED")
        require(set(inputs["composeSources"]) == set(PROJECTS)
                and set(inputs["plannedModels"]) == set(PROJECTS), "D12_TWO_PROJECT_SOURCES_REQUIRED")
        self._planned_refs = deepcopy(inputs["plannedModels"])
        self.planned = {project: _json(read_ref(self._planned_refs[project]).read_bytes())
                        for project in PROJECTS}
        self._compose_sources = deepcopy(inputs["composeSources"])
        self._compose_arguments = {}
        require(all(self.planned[project].get("name") == project for project in PROJECTS),
                "D12_PLANNED_PROJECT_NAME_CHANGED")
        for project in PROJECTS:
            args = inputs["composeArguments"][project]
            require(isinstance(args, list) and args[:4] in (["docker", "compose", "-p", project],
                    ["docker", "compose", "--project-name", project]), "D12_COMPOSE_PROJECT_CHANGED")
            require(len(args) >= 8 and len(args[4:]) % 2 == 0, "D12_COMPOSE_ARGUMENT_SHAPE_CHANGED")
            paths = []
            counts = {"-f": 0, "--env-file": 0, "--project-directory": 0}
            for flag, value in zip(args[4::2], args[5::2]):
                require(flag in counts and isinstance(value, str) and Path(value).is_absolute(),
                        "D12_COMPOSE_INPUT_CHANGED")
                counts[flag] += 1
                if flag != "--project-directory":
                    paths.append(value)
            require(counts["-f"] >= 1 and counts["--project-directory"] == 1, "D12_COMPOSE_SOURCE_REQUIRED")
            refs = self._compose_sources[project]
            require(set(refs) == set(paths), "D12_COMPOSE_SOURCE_SET_CHANGED")
            for value in paths:
                require(read_ref(refs[value]).resolve() == Path(value).resolve(), "D12_COMPOSE_SOURCE_CHANGED")
            self._compose_arguments[project] = tuple(args)
        self.engine_id = inputs["engineId"]
        require(isinstance(self.engine_id, str) and len(self.engine_id) == 36, "D12_ENGINE_ID_REQUIRED")

    def docker_read(self, args):
        if args == ["info", "--format", "{{.ID}}"]:
            return self._docker(args)
        ids = {row["containerId"] for row in self.before.values()}
        full = isinstance(args, list) and len(args) == 23 and args[0] == "inspect" \
            and len(set(args[1:])) == 22 and set(args[1:]) == ids
        one = isinstance(args, list) and len(args) == 2 and args[0] == "inspect" and args[1] in ids
        require(full or one,
                "D12_READONLY_DOCKER_COMMAND_REQUIRED")
        return self._docker(args)

    def observe22(self):
        self._recheck_source()
        engine = self.docker_read(["info", "--format", "{{.ID}}"])
        if isinstance(engine, bytes):
            engine = engine.decode("utf-8", "strict")
        require(isinstance(engine, str) and engine.strip() == self.engine_id, "D12_ENGINE_CHANGED")
        ids = [self.before[role]["containerId"] for role in sorted(self.before)]
        actual = _json(self.docker_read(["inspect", *ids]))
        require(isinstance(actual, list) and len(actual) == 22
                and {row.get("Id") for row in actual} == set(ids), "D12_ROLE_CID_SET_CHANGED")
        for row in actual:
            expected = next(value for value in self.before.values() if value["containerId"] == row["Id"])
            labels = row.get("Config", {}).get("Labels", {})
            require(row.get("Image") == expected["imageId"]
                    and labels.get("com.docker.compose.project") == expected["project"]
                    and labels.get("com.docker.compose.service") == expected["role"],
                    "D12_ROLE_IDENTITY_CHANGED:" + expected["role"])
        return self.project_inspections(self.binding, actual)

    @staticmethod
    def project_inspections(binding, actual):
        # Source/ELF fields are copied from a prior reviewed binding, not
        # rediscovered from a stopped or newly created process.
        projected = maintenance.with_observed_state(binding, actual)
        maintenance.exact_roles(projected, CURRENT_PROFILE)
        require(projected["sourceFactsBoundToPriorReceiptNotNewElfProbe"] is True,
                "D12_SOURCE_FACTS_NOT_NEW_ELF_PROOF")
        return projected

    def inspect_role(self, role):
        require(role in self.before, "D12_UNOWNED_ROLE_REFUSED")
        self._recheck_source()
        engine = self.docker_read(["info", "--format", "{{.ID}}"])
        if isinstance(engine, bytes):
            engine = engine.decode("utf-8", "strict")
        require(isinstance(engine, str) and engine.strip() == self.engine_id, "D12_ENGINE_CHANGED")
        bound = self.before[role]
        actual = _json(self.docker_read(["inspect", bound["containerId"]]))
        require(isinstance(actual, list) and len(actual) == 1, "D12_SINGLE_ROLE_INSPECT_REQUIRED")
        row = actual[0]
        labels = row.get("Config", {}).get("Labels", {})
        require(row.get("Id") == bound["containerId"] and row.get("Image") == bound["imageId"]
                and labels.get("com.docker.compose.project") == bound["project"]
                and labels.get("com.docker.compose.service") == role,
                "D12_ROLE_IDENTITY_CHANGED:" + role)
        return maintenance.observed_role_state(bound, row)

    def _recheck_source(self):
        read_ref(self._source_closure_ref)
        read_ref(self._host_ref)
        for name, row in self._source_files.items():
            file = self._root / name
            require(file.stat().st_size == row["bytes"]
                    and read_ref({"path": str(file), "sha256": row["sha256"]}) == file,
                    "D12_SOURCE_CHANGED_BEFORE_RENDER:" + name)

    def _recheck_render_inputs(self, project):
        self._recheck_source()
        for value, bound in self._compose_sources[project].items():
            require(read_ref(bound).resolve() == Path(value).resolve(),
                    "D12_COMPOSE_SOURCE_CHANGED_BEFORE_RENDER")
        require(_json(read_ref(self._planned_refs[project]).read_bytes()) == self.planned[project],
                "D12_PLANNED_MODEL_CHANGED_BEFORE_RENDER")

    def compose_model(self, arguments, overlay_ref=None):
        project = arguments[3] if isinstance(arguments, (list, tuple)) and len(arguments) >= 4 else None
        require(project in PROJECTS and tuple(arguments) == self._compose_arguments[project],
                "D12_FROZEN_COMPOSE_ARGUMENTS_REQUIRED")
        self._recheck_render_inputs(project)
        extra = []
        if overlay_ref is not None:
            require(project == "elevenid-beta", "D12_UI_OVERLAY_REFUSED")
            path = read_ref(overlay_ref).resolve()
            require(path.suffix.lower() in (".json", ".yaml", ".yml"), "D12_BOUNDED_OVERLAY_REQUIRED")
            extra = ["-f", str(path)]
        argv = [*self._compose_arguments[project], *extra, "config", "--format", "json"]
        model = _json(self._compose(argv))
        require(isinstance(model, dict) and model.get("name") == project
                and isinstance(model.get("services"), dict), "D12_RENDERED_MODEL_CHANGED")
        if overlay_ref is None:
            require(model == self.planned[project], "D12_PLANNED_MODEL_DRIFT:" + project)
        return model

    def render_two_project_baseline(self):
        return {project: self.compose_model(self._compose_arguments[project])
                for project in PROJECTS}

    def read_only_context(self):
        # This checks CID/image/labels/mounts and observed State only. Fresh
        # 28-role Env/capability/resource proof remains a separate prerequisite.
        # No effect command, authority, lock or DB binding is provided here.
        return {"dispatch_enabled": False, "observe22": self.observe22,
                "inspect_all22": self.observe22, "inspect_role": self.inspect_role,
                "compose_model": self.compose_model}
