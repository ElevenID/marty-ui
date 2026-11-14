"""Authenticate and retain completed legacy recovery predecessors.

This adapter never infers authority from live Secret bytes or rewrites original
bootstrap state. The signed native owner admits the historical plans and the
observed live publication before the producer can issue another generation.
"""
from __future__ import annotations

import ast
import io
from pathlib import Path
import stat
import subprocess
import tarfile
import zipfile

import bootstrap_kubernetes_openbao as bootstrap
import inspect_kubernetes_legacy_credentials as inspection
import stage_kubernetes_application_credentials as private


SCHEMA = "marty.kubernetes-legacy-recovery-lineage/v1"
MAX_STEPS = 8
MAX_BYTES = 64 * 1024 * 1024
REMOTE = "/tmp/marty-legacy-predecessors"


def historical_sources(assets: Path, identity: dict, raw: bytes) -> None:
    """Verify an old helper closure against its authenticated archive, not HEAD.

    The historical SOURCE_FILES tuple is parsed as data, never imported or run.
    The current interpreter and already-authenticated prepare() remain the same
    trust boundary used by ordinary recovery.
    """
    try:
        _historical_sources(assets, identity, raw)
    except (zipfile.BadZipFile, SyntaxError) as error:
        raise bootstrap.BootstrapError("authenticated predecessor source archive is invalid") from error


def _historical_sources(assets: Path, identity: dict, raw: bytes) -> None:
    import kubernetes_legacy_recovery_sources as sources

    receipt = inspection.decode(raw, 1024 * 1024, "predecessor source authentication")
    inventory_raw = bootstrap.read_record(assets / "installer-inventory.json")
    bootstrap.require(sources.digest(inventory_raw) == identity["inventorySha256"],
                      "authenticated predecessor inventory changed")
    inventory = bootstrap.release.decode(inventory_raw)
    name = "prepared-selfhost-bundle.zip"
    entries = [entry for entry in inventory["artifacts"] if entry["name"] == name]
    bootstrap.require(len(entries) == 1, "predecessor bundle inventory is ambiguous")
    maximum = bootstrap.release.ARTIFACT_MAX_BYTES[name]
    with (assets / name).open("rb") as stream:
        payload = stream.read(maximum + 1)
    bootstrap.require(len(payload) <= maximum and sources.digest(payload) == entries[0]["sha256"],
                      "authenticated predecessor bundle changed")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.infolist()

        def read(source: str) -> bytes:
            matches = [member for member in members if member.filename == "selfhost-prepared/" + source]
            bootstrap.require(len(matches) == 1, "predecessor source is absent or duplicated")
            member = matches[0]
            bootstrap.require(not member.is_dir() and member.file_size <= sources.FILE_LIMIT
                and not member.flag_bits & 1 and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
                and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                "predecessor source has an unsupported type or size")
            return archive.read(member)

        module = ast.parse(read("scripts/kubernetes_legacy_recovery_sources.py"))
        declarations = [node for node in module.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "SOURCE_FILES" for target in node.targets)]
        bootstrap.require(len(declarations) == 1, "predecessor source closure declaration is ambiguous")
        names = ast.literal_eval(declarations[0].value)
        bootstrap.require(isinstance(names, tuple) and 1 <= len(names) <= 256
            and all(isinstance(name, str) and (name.startswith("scripts/") or name.startswith("deploy-config/"))
                    and str(Path(name)) == name and ".." not in Path(name).parts for name in names)
            and len(set(names)) == len(names)
            and {"scripts/recover_kubernetes_legacy_credentials.py", "scripts/inspect_kubernetes_legacy_credentials.py",
                 "scripts/kubernetes_legacy_recovery_sources.py"} <= set(names),
            "predecessor authenticated helper closure differs")
        expected = {name: sources.digest(read(name)) for name in names}
    inspection.same(receipt, {"schema": sources.SCHEMA, "recoveryRuntime": identity, "files": expected},
                    "predecessor source receipt differs from its signed bundle")


class Predecessors:
    def __init__(self, args, original: dict, original_snapshot: dict, binding: dict):
        import recover_kubernetes_legacy_credentials as recovery

        self.args, self.binding = args, binding
        self.root = args.operation_dir / "predecessors"
        self.files: dict[str, tuple[bytes, int]] = {}
        self.inputs: dict[Path, tuple[bytes, int]] = {}
        self.generations: dict[Path, dict] = {}
        self.summary = None
        bootstrap.private_directory(self.root)
        self.write_generation("original", original_snapshot)
        previous = original_snapshot
        manifest = {"schema": SCHEMA, "binding": binding, "originalRuntime": original["release"], "steps": []}
        _, original_initializer = bootstrap.authenticated_bootstrap_inputs(args.original_assets, original["release"])
        for index, (directory, assets) in enumerate(zip(args.previous_recovery_dir, args.previous_recovery_assets, strict=True)):
            private.existing_private_directory(directory)
            bootstrap.require(not directory.is_relative_to(args.state_dir) and not args.state_dir.is_relative_to(directory)
                and not directory.is_relative_to(args.operation_dir) and not args.operation_dir.is_relative_to(directory),
                "predecessor, new operation and original state directories must be separate")
            bootstrap.require(not (directory / "recovery-stopped.json").exists()
                and not (directory / "recovery-stopped.json").is_symlink(),
                "incomplete predecessor cannot select a successor generation")
            completion_raw = self.read(directory / "recovery-complete.json")
            completion = inspection.decode(completion_raw, recovery.REPORT_LIMIT + 1, "predecessor completion")
            identity = completion.get("recoveryRuntime", {})
            values, _ = bootstrap.prepare(assets=assets, runtime_source_sha=identity.get("runtimeSourceSha"),
                release_tag=identity.get("tag"), build_run_id=identity.get("buildRunId"),
                build_run_attempt=identity.get("buildRunAttempt"), chart_source_sha=args.chart_source_sha,
                gh=args.gh, cosign=args.cosign, output=args.operation_dir / f"predecessor-{index:02}-images.json",
                openbao_output=args.operation_dir / f"predecessor-{index:02}-openbao-images.json")
            inspection.same(values["release"], identity, "predecessor completion names another signed release")
            operator, initializer = bootstrap.authenticated_bootstrap_inputs(assets, identity)
            bootstrap.require(initializer == original_initializer
                and self.read(directory / "marty-deploy", private.OPERATOR_LIMIT, {0o700}) == operator,
                "predecessor operator or original initializer custody differs")
            source_raw = self.read(directory / "source-authenticated.json", 1024 * 1024)
            historical_sources(assets, identity, source_raw)
            prefix = f"step-{index:02}"
            self.put(prefix + "/recovery-complete.json", completion_raw)
            self.put(prefix + "/recovery-requested.json", self.read(directory / "recovery-requested.json"))
            self.put(prefix + "/source-authenticated.json", source_raw)
            payload = self.read(directory / "native-qualified-evidence.tar", private.NATIVE_EVIDENCE_LIMIT)
            members = recovery.evidence_members(payload, previous)
            # The native owner reconstructs the historical plan, journal and all
            # response hashes. First bind the durable local copies to that export.
            candidate = private.current_snapshot(directory / "candidate")
            self.generations[directory / "candidate"] = candidate
            bootstrap.require(set(candidate) == set(previous)
                and all(members.get("stage/candidate/" + name) == value for name, value in candidate.items()),
                "predecessor candidate differs from exported native evidence")
            for retained, exported in (("qualified-plan.json", "qualification/plan.json"),
                                       ("stage-complete.json", "stage/complete.json"),
                                       ("inspection.json", "inspection.json"),
                                       ("secret-preimages/all-secrets.json", "secrets.json")):
                bootstrap.require(members.get(exported) == (self.read(directory / retained), 0o600),
                                  "predecessor local evidence differs from its native export")
            for name, (value, mode) in members.items():
                self.put(prefix + "/evidence/" + name, value, mode)
            self.put(prefix + "/activation/activation-requested.json",
                     self.read(directory / "activation/activation-requested.json"))
            for secret in range(34):
                for kind in ("intent", "response", "verified"):
                    name = f"activation/{kind}-{secret:02}.json"
                    self.put(prefix + "/" + name, self.read(directory / name))
            manifest["steps"].append({"recoveryRuntime": identity,
                "completionSha256": recovery.sha256(completion_raw),
                "sourceAuthenticationSha256": recovery.sha256(source_raw)})
            previous = candidate
        self.snapshot = previous
        self.current = self.root / f"step-{len(manifest['steps']) - 1:02}/evidence/stage/candidate"
        self.put("manifest.json", bootstrap.encoded(manifest))
        last = inspection.decode(self.files[f"step-{len(manifest['steps']) - 1:02}/evidence/qualification/plan.json"][0],
                                 recovery.REPORT_LIMIT + 1, "predecessor private plan")
        names = [entry["name"] for entry in last["nativePlan"]["secrets"]]
        self.names = recovery.target_names(bootstrap.encoded({"schema": recovery.TARGETS_SCHEMA,
            "namespace": binding["namespace"], "names": names, "replacementCount": 51}), binding["namespace"])

    def read(self, path: Path, maximum: int = 8 * 1024 * 1024 + 1, modes: set[int] | None = None) -> bytes:
        item = private.private_bytes(path, maximum, modes or {0o600})
        bootstrap.require(path not in self.inputs or self.inputs[path] == item,
                          "predecessor evidence changed while reading")
        self.inputs[path] = item
        return item[0]

    def put(self, name: str, raw: bytes, mode: int = 0o600) -> None:
        bootstrap.require(name not in self.files and sum(len(value[0]) for value in self.files.values()) + len(raw) <= MAX_BYTES,
                          "predecessor transport evidence is repeated or exceeds its bound")
        path = self.root / name
        missing = []
        parent = path.parent
        while parent != self.root and not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            bootstrap.private_directory(directory)
        private.write_preserved(path, raw, mode)
        self.files[name] = raw, mode

    def write_generation(self, name: str, snapshot: dict) -> None:
        for file, (raw, mode) in snapshot.items():
            self.put(name + "/" + file, raw, mode)

    def check(self) -> None:
        for path, item in self.inputs.items():
            bootstrap.require(private.private_bytes(path, max(len(item[0]), 1), {item[1]}) == item,
                              "completed predecessor evidence changed")
        for path, snapshot in self.generations.items():
            bootstrap.require(private.current_snapshot(path) == snapshot, "completed predecessor generation changed")
        for name, item in self.files.items():
            bootstrap.require(private.private_bytes(self.root / name, max(len(item[0]), 1), {item[1]}) == item,
                              "private predecessor transport evidence changed")

    def admit(self, operator: Path, context: dict, observed: dict, raw: bytes) -> dict:
        self.put("live-secrets.json", raw)
        self.observed = observed
        request = {**context, "current": str(self.current), "predecessors": str(self.root)}
        result = subprocess.run([str(operator), "operator", "kubernetes-legacy-recovery-predecessors"],
            input=bootstrap.encoded(request), capture_output=True, check=False, timeout=120, env={})
        bootstrap.require(result.returncode == 0 and 0 < len(result.stdout) <= 1024 * 1024,
                          "signed native owner refused the completed predecessor chain or live preimages")
        self.summary = inspection.decode(result.stdout, 1024 * 1024, "native predecessor admission")
        bootstrap.require(self.summary.get("schema") == SCHEMA and self.summary.get("binding") == self.binding,
                          "native predecessor admission identifies another installation")
        self.check()
        return self.summary

    def same_publication(self, observed: dict) -> None:
        before = {item["metadata"]["name"]: item for item in self.observed["items"]}
        after = {item["metadata"]["name"]: item for item in observed["items"]}
        bootstrap.require(before.keys() == after.keys() and all(
            after[name]["metadata"]["uid"] == old["metadata"]["uid"] and after[name]["data"] == old["data"]
            for name, old in before.items()), "live predecessor publication changed before credential issuance")

    def archive(self) -> bytes:
        self.check()
        output = io.BytesIO()
        directories = set()
        for name in self.files:
            directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name in sorted(directories, key=lambda item: (len(Path(item).parts), item)):
                member = tarfile.TarInfo(name)
                member.type, member.mode = tarfile.DIRTYPE, 0o700
                archive.addfile(member)
            for name, (raw, mode) in sorted(self.files.items()):
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(raw), mode
                archive.addfile(member, io.BytesIO(raw))
        raw = output.getvalue()
        bootstrap.require(len(raw) <= MAX_BYTES + 4 * 1024 * 1024, "predecessor archive exceeds its transport bound")
        return raw


def selected(args, original: dict, original_snapshot: dict, binding: dict) -> Predecessors | None:
    directories = getattr(args, "previous_recovery_dir", [])
    assets = getattr(args, "previous_recovery_assets", [])
    bootstrap.require(isinstance(directories, list) and isinstance(assets, list)
        and len(directories) == len(assets) <= MAX_STEPS
        and len(set(directories)) == len(directories),
        "supply one authenticated assets directory per ordered completed predecessor, at most eight")
    if not directories:
        return None
    return Predecessors(args, original, original_snapshot, binding)
