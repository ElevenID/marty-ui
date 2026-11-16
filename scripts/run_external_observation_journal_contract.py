#!/usr/bin/env python3
"""Compile the exact core journal against disposable PostgreSQL, without core forks.

Dependencies are selected from the production workspace and seeded by its lock.
The resolved registry versions/checksums must already exist in that lock before
compilation. No fixture credentials or network routes are production defaults.
"""
import argparse
import difflib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
STORE = "rust/services/issuance/src/external_observation_postgres.rs"
AUTHORITY = "rust/services/issuance/src/external_observation_authority_postgres.rs"
AUTHORITY_TEST = "tests/rust/external-observation-journal/authority_tests.rs"
TEST = "tests/rust/external-observation-journal/tests.rs"
WIRE = "rust/services/issuance/src/external_observation_wire.rs"
WIRE_TEST = "rust/services/issuance/src/external_observation_wire_tests.rs"
INGRESS = "rust/services/issuance/src/external_observation_ingress.rs"
INGRESS_TEST = "tests/rust/external-observation-journal/ingress_tests.rs"
HTTP = "rust/services/issuance/src/external_observation_http.rs"
HTTP_TEST = "tests/rust/external-observation-journal/http_tests.rs"
GATEWAY = "rust/services/gateway/src/external_observation.rs"
STARTUP = "rust/services/issuance/src/external_observation_startup.rs"
ADMIN = "rust/services/issuance/src/external_observation_admin.rs"
ADMIN_TEST = "tests/rust/external-observation-journal/admin_tests.rs"
LIFECYCLE = "rust/services/issuance/src/external_observation_grant_lifecycle.rs"
LIFECYCLE_TEST = "tests/rust/external-observation-journal/grant_lifecycle_tests.rs"
ADMIN_HTTP = "rust/services/issuance/src/external_observation_admin_http.rs"
ADMIN_HTTP_TEST = "tests/rust/external-observation-journal/admin_http_tests.rs"
GRANT_EDIT = "rust/services/issuance/src/external_observation_grant_edit.rs"
GRANT_EDIT_TEST = "tests/rust/external-observation-journal/grant_edit_tests.rs"
MEMBERSHIP = "rust/services/issuance/src/external_observation_membership_admin.rs"
MEMBERSHIP_TEST = "tests/rust/external-observation-journal/membership_admin_tests.rs"
BINDING_ADMIN = "rust/services/issuance/src/external_observation_binding_admin.rs"
BINDING_ADMIN_TEST = "tests/rust/external-observation-journal/binding_admin_tests.rs"
BINDING_EDIT_TEST = "tests/rust/external-observation-journal/binding_edit_tests.rs"
ADMIN_READ = "rust/services/issuance/src/external_observation_admin_read.rs"
ADMIN_READ_TEST = "tests/rust/external-observation-journal/admin_read_tests.rs"
SCHEMA = "rust/services/issuance/src/external_observation_schema.rs"
SCHEMA_TEST = "tests/rust/external-observation-journal/schema_owner_tests.rs"
ROLE_TEST = "tests/rust/external-observation-journal/runtime_role_tests.rs"
MATERIALIZATION = "rust/services/issuance/src/external_observation_materialization.rs"
MATERIALIZATION_TEST = "tests/rust/external-observation-journal/materialization_tests.rs"
FORMAT_FILES = (MATERIALIZATION,MATERIALIZATION_TEST,SCHEMA, SCHEMA_TEST,ROLE_TEST,ADMIN_READ, ADMIN_READ_TEST,BINDING_EDIT_TEST,BINDING_ADMIN, BINDING_ADMIN_TEST,MEMBERSHIP, MEMBERSHIP_TEST,GRANT_EDIT, GRANT_EDIT_TEST,LIFECYCLE, LIFECYCLE_TEST,ADMIN_HTTP, ADMIN_HTTP_TEST, ADMIN, ADMIN_TEST, STARTUP, GATEWAY, HTTP, HTTP_TEST, STORE, AUTHORITY, TEST, AUTHORITY_TEST, WIRE, WIRE_TEST, INGRESS, INGRESS_TEST)


def toml_value(value):
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key} = {toml_value(item)}" for key, item in value.items()) + " }"
    raise ValueError("unsupported workspace dependency declaration")


def run(command, *, cwd, log, environment):
    result = subprocess.run(command, cwd=cwd, env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    log.write(result.stdout)
    log.flush()
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed with exit code {result.returncode}")


def compile_contract(artifacts):
    workspace = tomllib.loads((ROOT / "rust/Cargo.toml").read_text())
    service = tomllib.loads((ROOT / "rust/services/issuance/Cargo.toml").read_text())
    names = ("axum", "subtle", "tower", "async-trait", "chrono", "http", "serde", "serde_json", "sha2", "sqlx", "tokio", "uuid")
    declarations = []
    for name in names:
        value = workspace["workspace"]["dependencies"][name]
        if isinstance(value, str):
            value = {"version": value}
        else:
            value = dict(value)
        if set(value) - {"version", "features", "default-features", "package"}:
            raise ValueError("journal harness accepts registry dependencies only")
        override = service["dependencies"].get(name, {})
        if isinstance(override, dict):
            value["features"] = sorted(set(value.get("features", [])) | set(override.get("features", [])))
        declarations.append(f"{name} = {toml_value(value)}")
    declarations.append('marty-key-material-policy = { path = ' + json.dumps(str(ROOT / "rust/crates/key-material-policy")) + ' }')
    with tempfile.TemporaryDirectory(prefix="observation-journal-") as temporary:
        directory = Path(temporary)
        manifest = ('[package]\nname = "external-observation-journal-contract"\nversion = "0.0.0"\n'
                    'edition = "2021"\npublish = false\n[workspace]\n[lib]\npath = "lib.rs"\n'
                    '[dependencies]\n' + "\n".join(declarations) + "\n")
        (directory / "Cargo.toml").write_text(manifest)
        shutil.copyfile(ROOT / "rust/Cargo.lock", directory / "Cargo.lock")
        # Reuse the unchanged journal fixture and all baseline tests. Appending
        # a child test module gives it access to that private fixture without
        # copying the authority adapter or altering production source bytes.
        fixture = directory / "journal_fixture.rs"
        fixture.write_bytes((ROOT / TEST).read_bytes() + (
            f"\n#[path = {json.dumps(str(ROOT / MATERIALIZATION_TEST))}]\nmod materialization_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / ROLE_TEST))}]\nmod runtime_role_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / SCHEMA_TEST))}]\nmod schema_owner_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / ADMIN_READ_TEST))}]\nmod admin_read_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / BINDING_EDIT_TEST))}]\nmod binding_edit_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / BINDING_ADMIN_TEST))}]\nmod binding_admin_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / MEMBERSHIP_TEST))}]\nmod membership_admin_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / GRANT_EDIT_TEST))}]\nmod grant_edit_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / LIFECYCLE_TEST))}]\nmod grant_lifecycle_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / ADMIN_HTTP_TEST))}]\nmod admin_http_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / ADMIN_TEST))}]\nmod admin_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / HTTP_TEST))}]\nmod http_tests;\n"
            f"\n#[path = {json.dumps(str(ROOT / INGRESS_TEST))}]\nmod ingress_tests;\n"
            f"#[path = {json.dumps(str(ROOT / AUTHORITY_TEST))}]\nmod authority_tests;\n"
        ).encode())
        modules = [("external_observation_materialization", ROOT / MATERIALIZATION),("external_observation_schema", ROOT / SCHEMA), ("external_observation_admin_read", ROOT / ADMIN_READ), ("external_observation_binding_admin", ROOT / BINDING_ADMIN), ("external_observation_membership_admin", ROOT / MEMBERSHIP), ("external_observation_grant_edit", ROOT / GRANT_EDIT), ("external_observation_grant_lifecycle", ROOT / LIFECYCLE), ("external_observation_admin_http", ROOT / ADMIN_HTTP), ("external_observation_admin", ROOT / ADMIN), ("external_observation_startup", ROOT / STARTUP), ("gateway_observation", ROOT / GATEWAY), ("external_observation_http", ROOT / HTTP),
            ("external_observation_admission", ROOT / "rust/services/issuance/src/external_observation_admission.rs"),
            ("external_observation_postgres", ROOT / STORE),
            ("external_observation_authority_postgres", ROOT / AUTHORITY),
            ("external_observation_wire", ROOT / WIRE),
            ("external_observation_ingress", ROOT / INGRESS),
            ("postgres_contract", fixture),
        ]
        (directory / "lib.rs").write_text("\n".join(
            f"#[path = {json.dumps(str(path))}]\npub mod {name};" for name, path in modules
        ) + "\n")
        environment = dict(os.environ)
        environment["CARGO_TARGET_DIR"] = str(directory / "target")
        environment["RUSTFLAGS"] = "-D warnings"
        metadata = subprocess.run(["cargo", "metadata", "--format-version", "1"], cwd=directory,
                                  env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                  text=True, check=False)
        if metadata.returncode:
            raise RuntimeError("isolated dependency resolution failed: " + metadata.stderr)
        baseline = tomllib.loads((ROOT / "rust/Cargo.lock").read_text())
        resolved = tomllib.loads((directory / "Cargo.lock").read_text())
        allowed = {(p["name"], p["version"], p.get("source"), p.get("checksum")) for p in baseline["package"]}
        for package in resolved["package"]:
            if "source" not in package:
                continue
            identity = (package["name"], package["version"], package.get("source"), package.get("checksum"))
            if not package["source"].startswith("registry+") or identity not in allowed:
                raise RuntimeError(f"dependency is not in the production lock: {package['name']} {package['version']}")
        shutil.copyfile(directory / "Cargo.lock", artifacts / "journal-contract.Cargo.lock")
        (artifacts / "journal-contract.Cargo.toml").write_text(manifest)
        with (artifacts / "journal-contract-tests.log").open("w") as log:
            run(["cargo", "test", "--locked", "--lib", "--", "--test-threads=1"],
                cwd=directory, log=log, environment=environment)


def require_format(artifacts):
    # Check root module ordering without recursively formatting unrelated files.
    subprocess.run(["rustfmt", "--edition", "2021", "--config", "skip_children=true", "--check",
                    str(ROOT / "rust/services/issuance/src/lib.rs")], check=True)
    original = {name: (ROOT / name).read_bytes() for name in FORMAT_FILES}
    try:
        subprocess.run(["rustfmt", "--edition", "2021", *(str(ROOT / name) for name in original)], check=True)
        patch = "".join("".join(difflib.unified_diff(
            data.decode().splitlines(keepends=True), (ROOT / name).read_text().splitlines(keepends=True),
            fromfile="a/" + name, tofile="b/" + name,
        )) for name, data in original.items())
        (artifacts / "journal-format.patch").write_text(patch)
        if patch:
            raise RuntimeError("checked-in formatting differs; apply the journal-format.patch artifact")
    finally:
        for name, data in original.items():
            (ROOT / name).write_bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    try:
        compile_contract(args.artifacts)
    finally:
        require_format(args.artifacts)


if __name__ == "__main__":
    main()
