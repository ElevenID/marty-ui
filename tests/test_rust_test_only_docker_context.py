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
    "initiation_didcomm/tests/initiation_didcomm_renewal_tests.rs": "initiation_didcomm.rs",
    "passport_http_reconciliation_tests.rs": "passport_http.rs",
    "python_format_tests.rs": "python_format.rs",
    "signing_http_projection_tests.rs": "http.rs",
    "signing_http_response_tests.rs": "signing_http_response.rs",
    "token_rate_limit_http_tests.rs": "http.rs",
}
OID4VP_TEST_TARGETS = (
    "contract_vectors.rs",
    "transport_metadata.rs",
)
OID4VP_TEST_ROOT = "rust/crates/oid4vp-contract/tests/"
OID4VP_CORPUS = "contracts/oid4vp-authenticated-contract-v1.json"
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
    "rust/services/issuance/src/initiation_didcomm.rs",
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
    return _active_owner_spans_from_clean(_without_rust_comments(text), name)


def _active_owner_spans_from_clean(clean: str, name: str) -> list[tuple[int, int]]:
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


def _nested_renewal_owner_is_direct_cfg_test(text: str, name: str) -> bool:
    """Bind Rust's `initiation_didcomm::tests` path resolution, not a glob."""
    clean = _without_rust_comments(text)
    pattern = (
        r"(?m)^#\[cfg\(test\)\]\s*\nmod tests \{\s*\n\s*use super::\*;\s*\n"
        + r"\s*#\[cfg\(test\)\]\s*\n\s*#\[path\s*=\s*\""
        + re.escape(name)
        + r"\"\]\s*\n\s*mod renewal_graph;"
    )
    match = re.search(pattern, clean)
    if match is None:
        return False
    preceding = clean[: match.start()].rstrip().splitlines()
    return not preceding or not preceding[-1].lstrip().startswith("#[")


def _ownership_sources(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    """Read one fresh tracked-source snapshot per proof, without persistent caching."""
    sources = {}
    for path in _tracked_paths(root, "rust/**/*.rs"):
        source = (root / path).read_text(encoding="utf-8")
        if any(name in source for name in names):
            sources[path] = _without_rust_comments(source)
    return sources


def _assert_test_only_owner(
    root: Path,
    leaf: str,
    owner: str,
    sources: dict[str, str] | None = None,
) -> None:
    name = Path(leaf).name
    assert (root / ISSUANCE_SRC / leaf).is_file()
    references = []
    if sources is None:
        sources = _ownership_sources(root, (name,))
    for path, clean in sources.items():
        if name not in clean:
            continue
        start = 0
        while (position := clean.find(name, start)) != -1:
            references.append(
                (path, position, _active_owner_spans_from_clean(clean, name))
            )
            start = position + len(name)
    expected_path = ISSUANCE_SRC + owner
    assert len(references) == 1, f"Review additional Rust consumer of {name}"
    path, position, spans = references[0]
    assert path == expected_path and len(spans) == 1
    assert spans[0][0] <= position < spans[0][1], f"Non-test owner of {name}"
    if "/" in leaf:
        assert leaf == "initiation_didcomm/tests/initiation_didcomm_renewal_tests.rs"
        assert _nested_renewal_owner_is_direct_cfg_test(
            (root / expected_path).read_text(encoding="utf-8"), name
        ), f"Nested Rust module no longer resolves exact test-only leaf: {leaf}"


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
    # Rust's nested #[path] declaration names only the basename; the separate
    # nested-owner proof binds it to the exact resolved checkout path.
    sources = _ownership_sources(ROOT, tuple(Path(leaf).name for leaf in TEST_LEAVES))
    for leaf, owner in TEST_LEAVES.items():
        _assert_test_only_owner(ROOT, leaf, owner, sources)
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
        for leaf in TEST_LEAVES:
            path = ISSUANCE_SRC + leaf
            assert lines.count(path) == 1, (
                f"Exact exclusion missing: {ignore_path}: {path}"
            )
            assert _is_ignored(path, lines), f"Later rule re-includes {path}"
        assert all(not _is_ignored(path, lines) for path in PRODUCTION_INPUTS)
        assert not _is_ignored(
            ISSUANCE_SRC + "initiation_didcomm/tests/unreviewed.rs", lines
        ), "Review broad nested test-directory exclusion"
    public_lines = (
        (ROOT / "services/Dockerfile.dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert not _is_ignored("services/auth/assets/credential-login.js", public_lines)
    for path in (
        "services/common/__init__.py",
        "services/common/events.py",
        "services/common/grpc_event_bus.py",
    ):
        assert _is_ignored(path, public_lines), path


def test_oid4vp_auto_test_targets_stay_out_of_production_rust_contexts() -> None:
    # These are Cargo auto-discovered integration targets, not cfg(test)
    # modules. Keep their ownership proof separate from TEST_LEAVES.
    manifest = tomllib.loads(
        (ROOT / "rust/crates/oid4vp-contract/Cargo.toml").read_text(encoding="utf-8")
    )
    assert manifest["package"]["name"] == "marty-oid4vp-contract"
    assert manifest["package"].get("autotests", True) is True
    assert "build" not in manifest["package"]
    assert not (ROOT / "rust/crates/oid4vp-contract/build.rs").exists()
    assert not any(kind in manifest for kind in ("test", "bin", "example", "bench"))
    assert _tracked_paths(ROOT, OID4VP_TEST_ROOT + "*.rs") == [
        OID4VP_TEST_ROOT + name for name in OID4VP_TEST_TARGETS
    ]
    assert not _ownership_sources(ROOT, OID4VP_TEST_TARGETS), (
        "Review new Rust source consumer of the auto-discovered test targets"
    )

    vectors = (ROOT / (OID4VP_TEST_ROOT + "contract_vectors.rs")).read_text(
        encoding="utf-8"
    )
    transport = (ROOT / (OID4VP_TEST_ROOT + "transport_metadata.rs")).read_text(
        encoding="utf-8"
    )
    expected_corpus_include = 'include_str!(\n        "../../../../contracts/oid4vp-authenticated-contract-v1.json"\n    )'
    assert vectors.count(expected_corpus_include) == 1
    assert vectors.count("include_str!") == 1
    for source in (vectors, transport):
        assert not re.search(r"#\[path\s*=|\binclude(?:_bytes)?!", source)
    assert "include_str!" not in transport

    assert _copying_rust_contexts(ROOT) == set(DOCKER_CONTEXTS)
    for ignore_path in set(DOCKER_CONTEXTS.values()):
        lines = (ROOT / ignore_path).read_text(encoding="utf-8").splitlines()
        for name in OID4VP_TEST_TARGETS:
            path = OID4VP_TEST_ROOT + name
            assert _is_ignored(path, lines), (
                f"Docker COPY still includes {ignore_path}: {path}"
            )
            if ignore_path == ".dockerignore":
                assert lines.count(path) == 1, f"Root exclusion must be exact: {path}"
        assert not _is_ignored(OID4VP_CORPUS, lines)
    root_lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert not _is_ignored(OID4VP_TEST_ROOT + "unreviewed.rs", root_lines)


def test_public_context_rejects_reincluded_python_event_adapter() -> None:
    lines = (
        (ROOT / "services/Dockerfile.dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    path = "services/common/grpc_event_bus.py"
    assert _is_ignored(path, lines)
    assert not _is_ignored(path, [*lines, "!**"])
    assert not _is_ignored(path, [*lines, "!services/common/**"])


def test_ownership_snapshot_reads_and_lexes_shared_source_once(monkeypatch) -> None:
    names = ("first_tests.rs", "second_tests.rs")
    contents = {
        "owner.rs": "\n".join(f'#[path = "{name}"] mod owned;' for name in names),
        "other.rs": "fn unrelated() {}",
    }
    reads = []
    lexed = []
    original_lexer = _without_rust_comments

    def read_source(path: Path, **kwargs) -> str:
        assert kwargs == {"encoding": "utf-8"}
        reads.append(path.name)
        return contents[path.name]

    def lex_source(source: str) -> str:
        lexed.append(source)
        return original_lexer(source)

    monkeypatch.setattr(
        sys.modules[__name__], "_tracked_paths", lambda *args: list(contents)
    )
    monkeypatch.setattr(Path, "read_text", read_source)
    monkeypatch.setattr(sys.modules[__name__], "_without_rust_comments", lex_source)
    first = _ownership_sources(Path("synthetic"), names)
    assert reads == ["owner.rs", "other.rs"]
    assert lexed == [contents["owner.rs"]]
    assert first == {"owner.rs": original_lexer(contents["owner.rs"])}
    # A later invocation reads again and observes an added consumer: there is
    # no persistent cache which could conceal source drift.
    contents["other.rs"] = '#[path = "first_tests.rs"] mod unexpected;'
    second = _ownership_sources(Path("synthetic"), names)
    assert reads == ["owner.rs", "other.rs", "owner.rs", "other.rs"]
    assert "other.rs" in second and "other.rs" not in first


def test_snapshot_owner_proof_rejects_additional_and_non_test_consumers() -> None:
    import pytest

    name = "canvas_sync_worker_retry_tests.rs"
    owner = "canvas_sync_worker.rs"
    path = ISSUANCE_SRC + owner
    valid = f'#[cfg(test)]\n#[path = "{name}"]\nmod retry_handoff_tests;'
    _assert_test_only_owner(ROOT, name, owner, {path: valid})
    with pytest.raises(AssertionError, match="additional Rust consumer"):
        _assert_test_only_owner(
            ROOT, name, owner, {path: valid, "rust/extra.rs": f'include!("{name}");'}
        )
    with pytest.raises(AssertionError):
        _assert_test_only_owner(
            ROOT, name, owner, {path: valid.replace("#[cfg(test)]\n", "")}
        )


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

    nested = "initiation_didcomm_renewal_tests.rs"
    owned = (
        "#[cfg(test)]\nmod tests {\n    use super::*;\n"
        f'    #[cfg(test)]\n    #[path = "{nested}"]\n    mod renewal_graph;'
    )
    assert _nested_renewal_owner_is_direct_cfg_test(owned, nested)
    for source in (
        owned.replace("mod tests {", "mod other_tests {"),
        owned.replace("#[cfg(test)]\nmod tests", "mod tests"),
        owned.replace("#[cfg(test)]\nmod tests", '#[cfg(feature = "test")]\nmod tests'),
        '#[cfg(feature = "slow")]\n' + owned,
        owned.replace("mod renewal_graph;", "mod other_graph;"),
        owned.replace(f'#[path = "{nested}"]', '#[path = "other.rs"]'),
    ):
        assert not _nested_renewal_owner_is_direct_cfg_test(source, nested)


def test_dockerignore_guard_rejects_reincluded_leaf_and_excluded_runtime() -> None:
    leaf = ISSUANCE_SRC + "canvas_sync_worker_retry_tests.rs"
    assert not _is_ignored(leaf, [leaf, "!" + leaf])
    assert _is_ignored(ISSUANCE_SRC + "canvas_sync_worker.rs", ["rust/**"])
    assert _is_ignored(leaf, ["**", "!rust/**", leaf])
    nested = (
        ISSUANCE_SRC + "initiation_didcomm/tests/initiation_didcomm_renewal_tests.rs"
    )
    sibling = ISSUANCE_SRC + "initiation_didcomm/tests/unreviewed.rs"
    assert not _is_ignored(nested, [nested, "!" + nested])
    assert _is_ignored(sibling, [ISSUANCE_SRC + "initiation_didcomm/tests/"])


def test_new_copying_dockerfile_requires_context_review(tmp_path: Path) -> None:
    candidate = tmp_path / "new" / "Dockerfile"
    candidate.parent.mkdir()
    candidate.write_text("FROM rust:1\nCOPY rust /build/rust\n", encoding="utf-8")
    assert _copying_rust_contexts(tmp_path, ["new/Dockerfile"]) == {"new/Dockerfile"}
    assert "new/Dockerfile" not in DOCKER_CONTEXTS


if __name__ == "__main__":
    if sys.argv != [sys.argv[0], "--emit-verified-leaves"]:
        raise SystemExit(
            "Usage: test_rust_test_only_docker_context.py --emit-verified-leaves"
        )
    # CI may narrow only when the exact owner, target and image-context proof
    # still holds. The release pytest lane runs the same assertion separately.
    test_exact_test_only_leaves_do_not_invalidate_release_docker_copy()
    for leaf in TEST_LEAVES:
        sys.stdout.buffer.write((ISSUANCE_SRC + leaf).encode("utf-8") + b"\0")
