"""Prove the exact test-only Rust leaves omitted from release Docker contexts.

This is a bounded source/recipe guard, not a general Rust macro or Dockerignore
interpreter. The normal checkout Rust test lane still compiles these modules.
"""

from __future__ import annotations

import re
import subprocess
import sys
from fnmatch import fnmatchcase
from importlib import import_module
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_without_rust_comments = import_module(
    "scripts.check_gateway_public_protocol_contract"
)._without_rust_comments

ISSUANCE_SRC = "rust/services/issuance/src/"
TEST_LEAVES = {
    "canvas_operation_http_prepared_tests.rs": "canvas_operation_http.rs",
    "canvas_sync_provider_http_tests.rs": "canvas_sync_provider_http.rs",
    "canvas_sync_processor_tests.rs": "canvas_sync_processor.rs",
    "canvas_sync_worker_retry_tests.rs": "canvas_sync_worker.rs",
    "passport_http_reconciliation_tests.rs": "passport_http.rs",
    "python_format_tests.rs": "python_format.rs",
    "signing_http_projection_tests.rs": "http.rs",
    "signing_http_response_tests.rs": "signing_http_response.rs",
    "token_rate_limit_http_tests.rs": "http.rs",
}
DOCKER_CONTEXTS = {
    "services/Dockerfile": "services/Dockerfile.dockerignore",
    "rust/services/Dockerfile.ci": "rust/services/Dockerfile.ci.dockerignore",
    "services/Dockerfile.migrations": ".dockerignore",
    "rust/services/event-stream/Dockerfile": ".dockerignore",
    "rust/services/revocation-profile/Dockerfile": ".dockerignore",
    "rust/services/signing-keys/Dockerfile": ".dockerignore",
}
PRODUCTION_INPUTS = (
    "rust/Cargo.toml",
    "rust/Cargo.lock",
    "rust/services/issuance/Cargo.toml",
    "rust/services/issuance/src/canvas_sync_worker.rs",
    "rust/services/issuance/src/canvas_sync_processor_contract.md",
    "rust/services/issuance/src/http.rs",
    "rust/services/issuance/src/signing_http_response.rs",
    "proto/v1/issuance_service.proto",
    "contracts/auth-executable-behavior.json",
)


def _tracked_paths(root: Path, pattern: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--", pattern],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def _copying_rust_contexts(root: Path, candidates: list[str] | None = None) -> set[str]:
    if candidates is None:
        candidates = _tracked_paths(root, "*Dockerfile*")
    return {
        path
        for path in candidates
        if (root / path).is_file()
        and (
            Path(path).name == "Dockerfile" or Path(path).name.startswith("Dockerfile.")
        )
        and re.search(
            r"(?m)^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*rust(?:/|\s)",
            (root / path).read_text(encoding="utf-8"),
        )
    }


def _is_ignored(path: str, lines: list[str]) -> bool:
    """Apply only the simple patterns present in these three owned ignore files."""
    ignored = False
    for raw in lines:
        rule = raw.strip()
        if not rule or rule.startswith("#"):
            continue
        included = rule.startswith("!")
        pattern = rule[1:] if included else rule
        if pattern.endswith("/"):
            matches = path.startswith(pattern)
        elif pattern == "**":
            matches = True
        elif "*" not in pattern:
            matches = path == pattern or path.startswith(pattern + "/")
        else:
            matches = fnmatchcase(path, pattern)
        if matches:
            ignored = not included
    return ignored


def _active_owner_spans(text: str, name: str) -> list[tuple[int, int]]:
    clean = _without_rust_comments(text)
    # The shared comment lexer retains strings; its optional string mask does
    # not handle Rust character literals in these owners. Bound raw-string
    # detection here and reject syntax beyond the supported hash delimiter.
    if re.search(r'(?<![A-Za-z0-9_])(?:b)?r#{17,}"', clean):
        return []
    raw_spans = []
    position = 0
    while opener := re.search(r'(?<![A-Za-z0-9_])(?:b)?r(#{1,16})"', clean[position:]):
        start = position + opener.start()
        body_start = position + opener.end()
        end_marker = '"' + opener.group(1)
        end_at = clean.find(end_marker, body_start)
        end = len(clean) if end_at == -1 else end_at + len(end_marker)
        raw_spans.append((start, end))
        position = end
    pattern = (
        r"(?m)^\s*#\[cfg\(test\)\]\s*\n\s*"
        + r'#\[path\s*=\s*"'
        + re.escape(name)
        + r'"\]\s*\n\s*(?:pub(?:\([^\n)]*\))?\s+)?mod\s+\w+\s*;'
    )
    return [
        (match.start(), match.end())
        for match in re.finditer(pattern, clean)
        if not any(start <= match.start() < end for start, end in raw_spans)
    ]


def _assert_test_only_owner(root: Path, name: str, owner: str) -> None:
    assert (root / ISSUANCE_SRC / name).is_file()
    references = []
    for path in _tracked_paths(root, "rust/**/*.rs"):
        source = (root / path).read_text(encoding="utf-8")
        if name not in source:
            continue
        clean = _without_rust_comments(source)
        start = 0
        while (position := clean.find(name, start)) != -1:
            references.append((path, position, _active_owner_spans(source, name)))
            start = position + len(name)
    expected_path = ISSUANCE_SRC + owner
    assert len(references) == 1, f"Review additional Rust consumer of {name}"
    path, position, spans = references[0]
    assert path == expected_path and len(spans) == 1
    assert spans[0][0] <= position < spans[0][1], f"Non-test owner of {name}"


def test_exact_test_only_leaves_do_not_invalidate_release_docker_copy() -> None:
    assert _copying_rust_contexts(ROOT) == set(DOCKER_CONTEXTS), (
        "Review new/removed Dockerfile that copies Rust before excluding a source leaf"
    )
    for dockerfile in DOCKER_CONTEXTS:
        recipe = (ROOT / dockerfile).read_text(encoding="utf-8")
        assert "--cfg test" not in recipe and "--all-targets" not in recipe
    build_script = (ROOT / "scripts/build-rust-service-binaries.sh").read_text(
        encoding="utf-8"
    )
    assert "cargo build --locked --release" in build_script
    assert "--cfg test" not in build_script and "--all-targets" not in build_script

    manifests = [ROOT / path for path in _tracked_paths(ROOT, "rust/**/Cargo.toml")]
    for name, owner in TEST_LEAVES.items():
        _assert_test_only_owner(ROOT, name, owner)
    for manifest in manifests:
        parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
        targets = [
            target
            for kind in ("bin", "test", "example", "bench")
            for target in parsed.get(kind, [])
        ]
        if "lib" in parsed:
            targets.append(parsed["lib"])
        assert all(
            name not in target.get("path", "")
            for target in targets
            for name in TEST_LEAVES
        )

    for ignore_path in set(DOCKER_CONTEXTS.values()):
        lines = (ROOT / ignore_path).read_text(encoding="utf-8").splitlines()
        for name in TEST_LEAVES:
            path = ISSUANCE_SRC + name
            assert lines.count(path) == 1, (
                f"Exact exclusion missing: {ignore_path}: {path}"
            )
            assert _is_ignored(path, lines), f"Later rule re-includes {path}"
        assert all(not _is_ignored(path, lines) for path in PRODUCTION_INPUTS)
    public_lines = (
        (ROOT / "services/Dockerfile.dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert not _is_ignored("services/auth/assets/credential-login.js", public_lines)


def test_source_ownership_guard_rejects_inert_and_feature_gated_wiring() -> None:
    name = "canvas_sync_worker_retry_tests.rs"
    valid = f'#[cfg(test)]\n#[path = "{name}"]\nmod retry_handoff_tests;'
    assert len(_active_owner_spans(valid, name)) == 1
    for source in (
        "// " + valid,
        f'r#"{valid}"#',
        f'r#"\n{valid}\n"#',
        f'br#"\n{valid}\n"#',
        "r" + "#" * 17 + f'"prefix"\n{valid}\n"' + "#" * 17,
        valid.replace("cfg(test)", 'cfg(feature = "test")'),
        valid.replace("cfg(test)", 'cfg(all(test, feature = "slow"))'),
        valid.replace("#[cfg(test)]\n", ""),
    ):
        assert not _active_owner_spans(source, name)


def test_dockerignore_guard_rejects_reincluded_leaf_and_excluded_runtime() -> None:
    leaf = ISSUANCE_SRC + "canvas_sync_worker_retry_tests.rs"
    assert not _is_ignored(leaf, [leaf, "!" + leaf])
    assert _is_ignored(ISSUANCE_SRC + "canvas_sync_worker.rs", ["rust/**"])
    assert _is_ignored(leaf, ["**", "!rust/**", leaf])


def test_new_copying_dockerfile_requires_context_review(tmp_path: Path) -> None:
    candidate = tmp_path / "new" / "Dockerfile"
    candidate.parent.mkdir()
    candidate.write_text("FROM rust:1\nCOPY rust /build/rust\n", encoding="utf-8")
    assert _copying_rust_contexts(tmp_path, ["new/Dockerfile"]) == {"new/Dockerfile"}
    assert "new/Dockerfile" not in DOCKER_CONTEXTS
