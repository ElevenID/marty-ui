"""Synthetic, data-only checkpoint contract tests; no crypto acceptance claim."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import release_transaction as transaction
import stable_publication_checkpoint as checkpoint

SOURCE = "a" * 40
REVIEW_MAIN = "b" * 40
RUN = 123456789
CLAIM = "123456700"
TAG = "v1.2.3"
NOW = datetime(2026, 11, 4, 1, 2, 3, tzinfo=timezone.utc)


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class CheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.assets = self.base / "workspace"
        self.assets.mkdir(mode=0o700)
        self.control = self.base / "control"
        self.control.mkdir(mode=0o700)
        self.output = self.base / "checkpoint"
        self.environment = {
            "GITHUB_REPOSITORY": checkpoint.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SOURCE, "GITHUB_RUN_ID": str(RUN),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": checkpoint.REPOSITORY + "/.github/workflows/cd.yml@refs/heads/main",
        }
        self.make_fixture()

    def make_fixture(self, *, reviewed: bool = False) -> None:
        lock = self.control / "stack-lock.json"
        lock.write_bytes(encoded({"schema": "marty.stack-lock/v1", "release": "marty-ui@1.2.3",
                                  "release_state": "eligible", "components": []}))
        claim = transaction.create_claim(repository=checkpoint.REPOSITORY, tag=TAG, source_sha=SOURCE,
            stack_lock=lock, claim_run_id=CLAIM, image_uris=transaction.IMAGE_URIS,
            tag_absent=True, release_absent=True,
            version_tags_absent={role: True for role in transaction.REQUIRED_IMAGE_ROLES})
        digests = {role: "sha256:" + str(index) * 64 for index, role in enumerate(transaction.REQUIRED_IMAGE_ROLES, 1)}
        claim = transaction.record_digests(claim, digests, build_run_id=str(RUN))
        artifacts = []
        for role in transaction.REQUIRED_IMAGE_ROLES:
            suffix = "" if role == "ui" else "-" + role.replace("_", "-")
            artifacts.append({"type": "oci", "uri": transaction.IMAGE_URIS[role], "digest": digests[role],
                "sbom": f"https://github.com/ElevenID/marty-ui/releases/download/{TAG}/marty-ui{suffix}-sbom.cdx.json",
                "provenance": "https://github.com/ElevenID/marty-ui/attestations"})
        manifest = {"schema": "marty.stack/v1", "release": "marty-ui@1.2.3", "generated_at": "2026-11-04T00:00:00Z",
                    "components": [{"name": "marty-ui", "repository": checkpoint.REPOSITORY,
                                    "version": "1.2.3", "commit": SOURCE, "artifacts": artifacts}]}
        manifest_bytes = encoded(manifest)
        gate = {"schema": "marty.official-release-gate/v2", "source_sha": SOURCE, "harness_sha": "c" * 40,
                "manifest_sha256": digest(manifest_bytes), "run_id": RUN,
                "qualification_context": "PRE_PUBLICATION_CANDIDATE",
                "lanes": [{"lane": lane, "summary_sha256": "sha256:" + "d" * 64}
                          for lane in ("oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi")],
                "automated_qualification": {
                    "schema": "marty.automated-official-qualification/v1",
                    "policy": "marty.official-verifier-outcome/v1", "evidence_run_attempt": 1,
                    "request_sha256": "sha256:" + "f" * 64, "automated_cases": 2,
                    "original_official_results_unchanged": True,
                }}
        if reviewed:
            gate["schema"] = "marty.official-release-gate/v1"
            gate.pop("automated_qualification")
            gate["review_disposition"] = {"schema": "marty.accepted-official-review/v1", "protected_main_commit": REVIEW_MAIN,
                "record_sha256": "sha256:" + "e" * 64, "request_sha256": "sha256:" + "f" * 64,
                "evidence_run_attempt": 1, "reviewer": {"kind": "human", "github_login": "fixture-reviewer"},
                "reviewed_cases": 2, "original_official_results_unchanged": True}
        gate_bytes = encoded(gate)
        self.gate_path = self.control / "official-interoperability.json"
        self.gate_path.write_bytes(gate_bytes)
        gates = {role: {"run_id": str(RUN), "evidence_sha256": "sha256:" + "9" * 64}
                 for role in transaction.REQUIRED_GATE_ROLES}
        gates["official_interoperability"]["evidence_sha256"] = digest(gate_bytes)
        claim = transaction.qualify(claim, gates)
        for role in transaction.REQUIRED_IMAGE_ROLES:
            claim = transaction.record_promotion(claim, role=role, digest=digests[role])
        self.transaction_path = self.control / "release-transaction.json"
        self.transaction_path.write_bytes(encoded(claim))
        for name in checkpoint.ASSET_NAMES:
            (self.assets / name).write_bytes(encoded({"synthetic_unverified_fixture": name}))
        (self.assets / "stack-manifest.json").write_bytes(manifest_bytes)
        (self.assets / "release-transaction.json").write_bytes(encoded(claim))
        images = {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@1.2.3",
                  "services": {"api": "ghcr.io/elevenid/example@sha256:" + "1" * 64},
                  "openbao_didcomm_image": transaction.IMAGE_URIS["openbao_didcomm"] + "@" + digests["openbao_didcomm"]}
        (self.assets / "prepared-selfhost-images.json").write_bytes(encoded(images))
        inventory = {"schema": "elevenid.installer-inventory/v1", "repository": checkpoint.REPOSITORY,
            "source_sha": SOURCE, "release_tag": TAG, "platform": "linux/amd64", "build_run_id": RUN,
            "build_run_attempt": 1, "artifacts": [{"name": name, "size": (self.assets / name).stat().st_size,
                "sha256": hashlib.sha256((self.assets / name).read_bytes()).hexdigest()} for name in (
                    "install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json")],
            "images": dict(images["services"], openbao_didcomm_image=images["openbao_didcomm_image"])}
        (self.assets / "installer-inventory.json").write_bytes(encoded(inventory))
        self.checksums(self.assets)
        (self.assets / "unrelated-workspace-file.txt").write_text("Not a publication asset.\n")

    def checksums(self, directory: Path) -> None:
        raw = "".join(hashlib.sha256((directory / name).read_bytes()).hexdigest() + "  " + name + "\n"
                      for name in sorted(checkpoint.CHECKSUM_NAMES))
        (directory / "SHA256SUMS").write_text(raw)

    def prepare(self, **updates: object) -> dict:
        arguments = dict(source_sha=SOURCE, tag=TAG, claim_run_id=CLAIM,
                         output=self.output, environment=self.environment, now=NOW)
        arguments.update(updates)
        return checkpoint.prepare_checkpoint(self.assets, self.transaction_path, self.gate_path, **arguments)

    def request(self) -> dict:
        return json.loads((self.output / "request.json").read_bytes())

    def save_request(self, value: dict) -> None:
        (self.output / "request.json").write_bytes(encoded(value))

    def reindex(self) -> dict:
        """Model an adversary editing an unsigned index; semantic gates remain."""
        self.checksums(self.output / "assets")
        value = self.request()
        for name in checkpoint.ASSET_NAMES:
            raw = (self.output / "assets" / name).read_bytes()
            value["assets"][name] = {"size": len(raw), "sha256": digest(raw)}
        value["manifest_sha256"] = value["assets"]["stack-manifest.json"]["sha256"]
        value["transaction_sha256"] = value["assets"]["release-transaction.json"]["sha256"]
        self.save_request(value)
        return value

    def rejected(self) -> None:
        with self.assertRaises(checkpoint.CheckpointError):
            checkpoint.load_checkpoint(self.output, now=NOW)

    def test_exact_allowlist_matches_existing_publisher(self) -> None:
        # Independent literal contract: optional hosting files cannot silently join it.
        subjects = {"stack-manifest.json", "release-transaction.json", "marty-ui-sbom.cdx.json",
            "marty-ui-services-sbom.cdx.json", "marty-ui-migrations-sbom.cdx.json",
            "marty-ui-openbao-didcomm-sbom.cdx.json", "marty-ui-keycloak-sbom.cdx.json",
            "marty-deploy-linux-amd64", "marty-deploy-linux-arm64", "install.sh", "installer-inventory.json",
            "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json"}
        sidecars = {name + ".provenance.jsonl" for name in ("install.sh", "marty-deploy-linux-amd64",
                    "installer-inventory.json", "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json")}
        expected = subjects | {name + ".sigstore.json" for name in subjects} | sidecars | {"SHA256SUMS"}
        self.assertEqual(checkpoint.ASSET_NAMES, expected)
        self.assertEqual(len(expected), 32)
        self.assertEqual(checkpoint.CHECKPOINT_FILES, {"assets/" + name for name in expected}
                         | {"request.json", "official-interoperability.json"})

    def test_roundtrip_preserves_every_signed_byte_and_exact_34_entries(self) -> None:
        value = self.prepare()
        self.assertEqual(checkpoint.load_checkpoint(self.output, now=NOW), value)
        files = {str(path.relative_to(self.output)) for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(files, checkpoint.CHECKPOINT_FILES)
        self.assertEqual(checkpoint.request_digest(self.output), digest((self.output / "request.json").read_bytes()))
        for name in checkpoint.ASSET_NAMES:
            self.assertEqual((self.output / "assets" / name).read_bytes(), (self.assets / name).read_bytes())
            self.assertEqual(stat.S_IMODE((self.output / "assets" / name).stat().st_mode), 0o600)
        self.assertEqual(value["not_after"], "2026-11-04T01:17:03Z")
        self.assertFalse(value["authority"]["review_required"])
        self.assertEqual(value["schema"], "elevenid.stable-publication-checkpoint/v2")
        self.assertEqual(value["tag_handoff_contract"], "marty.create-only-annotated-tag/v1")

    def test_prior_atomic_checkpoint_cannot_be_reinterpreted_as_reservation_authority(self) -> None:
        original = self.prepare()
        for mutation in ("prior-schema", "missing-contract", "foreign-contract"):
            changed = copy.deepcopy(original)
            if mutation == "prior-schema":
                changed["schema"] = "elevenid.stable-publication-checkpoint/v1"
            elif mutation == "missing-contract":
                changed.pop("tag_handoff_contract")
            else:
                changed["tag_handoff_contract"] = "marty.atomic-main-tag/v1"
            with self.subTest(mutation=mutation):
                with self.assertRaises(checkpoint.CheckpointError):
                    checkpoint.validate_request_identity(changed)
                self.save_request(changed)
                self.rejected()

    def test_historical_manual_review_cannot_authorize_a_new_checkpoint(self) -> None:
        self.make_fixture(reviewed=True)
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_no_payload_or_network_execution(self) -> None:
        sentinel = self.base / "payload-was-executed"
        payload = b"#!/bin/sh\ntouch " + os.fsencode(sentinel) + b"\n"
        (self.assets / "marty-deploy-linux-arm64").write_bytes(payload)
        (self.assets / "marty-deploy-linux-arm64").chmod(0o755)
        self.checksums(self.assets)
        with patch("subprocess.run", side_effect=AssertionError("execution forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.prepare()
            checkpoint.load_checkpoint(self.output, now=NOW)
        self.assertFalse(sentinel.exists())

    def test_producer_context_is_exact_before_output_creation(self) -> None:
        cases = {"GITHUB_REPOSITORY": "someone/else", "GITHUB_EVENT_NAME": "pull_request",
                 "GITHUB_REF": "refs/tags/v1.2.3", "GITHUB_SHA": REVIEW_MAIN, "GITHUB_RUN_ID": "01",
                 "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKFLOW_REF": "ElevenID/marty-ui/.github/workflows/other.yml@refs/heads/main",
                 "RESUME_RUN_ID": "22", "RESUME_ARTIFACT": "old-checkpoint"}
        for field, replacement in cases.items():
            with self.subTest(field=field), self.assertRaises(checkpoint.CheckpointError):
                self.prepare(environment=dict(self.environment, **{field: replacement}))
            self.assertFalse(self.output.exists())

    def test_existing_output_cannot_refresh_or_replace_deadline(self) -> None:
        self.prepare()
        before = (self.output / "request.json").read_bytes()
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare(now=NOW + timedelta(seconds=30))
        self.assertEqual((self.output / "request.json").read_bytes(), before)

    def test_partial_output_is_preserved_and_never_resumed(self) -> None:
        (self.assets / "install.sh.provenance.jsonl").unlink()
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare()
        self.assertTrue(self.output.is_dir())
        self.assertFalse((self.output / "request.json").exists())
        (self.assets / "install.sh.provenance.jsonl").write_bytes(b"fixed later")
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare(now=NOW + timedelta(seconds=10))

    def test_expired_future_and_extended_deadlines_refused(self) -> None:
        value = self.prepare()
        for now in (NOW - timedelta(microseconds=1), NOW + timedelta(seconds=900)):
            with self.subTest(now=now), self.assertRaises(checkpoint.CheckpointError):
                checkpoint.load_checkpoint(self.output, now=now)
        with self.assertRaises(checkpoint.CheckpointError):
            checkpoint.validate_request(dict(value, not_after="2026-11-04T01:17:04Z"), now=NOW)
        self.assertEqual(checkpoint.load_checkpoint(self.output, now=NOW + timedelta(seconds=899)), value)

    def test_noncanonical_timestamps_and_truthy_numeric_fields_refused(self) -> None:
        value = self.prepare()
        for key, replacement in (("created_at", "2026-11-04T01:02:03+00:00"), ("run_id", True),
                                 ("run_attempt", True), ("origin_attempt", True), ("claim_run_id", RUN),
                                 ("transaction_id", "sha256:" + "a" * 64)):
            with self.subTest(key=key), self.assertRaises(checkpoint.CheckpointError):
                checkpoint.validate_request(dict(value, **{key: replacement}), now=NOW)
        for key in ("size", "sha256"):
            changed = copy.deepcopy(value)
            changed["assets"]["install.sh"][key] = True
            with self.subTest(asset_key=key), self.assertRaises(checkpoint.CheckpointError):
                checkpoint.validate_request(changed, now=NOW)

    def test_request_extra_missing_duplicate_and_nonfinite_json_refused(self) -> None:
        self.prepare()
        original = (self.output / "request.json").read_bytes()
        for raw in (original.replace(b"{", b'{"run_id":123456789,', 1),
                    original.replace(b'"run_id":123456789', b'"run_id":NaN'),
                    encoded(dict(self.request(), ignored="anything"))):
            (self.output / "request.json").write_bytes(raw)
            self.rejected()
            (self.output / "request.json").write_bytes(original)
        value = self.request()
        del value["transaction_id"]
        self.save_request(value)
        self.rejected()

    def test_wrong_original_identity_refused_even_with_valid_shapes(self) -> None:
        original = self.prepare()
        for key, replacement in (("source_sha", REVIEW_MAIN), ("run_id", RUN + 1),
                                 ("claim_run_id", "123456701"), ("tag", "v1.2.4"),
                                 ("run_attempt", 2), ("origin_attempt", 2),
                                 ("manifest_sha256", "sha256:" + "1" * 64)):
            self.save_request(dict(original, **{key: replacement}))
            with self.subTest(key=key):
                self.rejected()
        self.save_request(original)

    def test_authority_cannot_be_edited_into_review_or_another_main(self) -> None:
        original = self.prepare()
        for key, replacement in (("review_required", 1), ("protected_main_commit", REVIEW_MAIN),
                                 ("gate_sha256", "sha256:" + "f" * 64), ("origin_attempt", True)):
            value = copy.deepcopy(original)
            value["authority"][key] = replacement
            self.save_request(value)
            with self.subTest(key=key):
                self.rejected()

    def test_changed_subject_signature_or_provenance_bytes_refused(self) -> None:
        self.prepare()
        for name in ("install.sh", "marty-deploy-linux-amd64.sigstore.json", "prepared-selfhost-bundle.zip.provenance.jsonl"):
            path = self.output / "assets" / name
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(name=name):
                self.rejected()
            path.write_bytes(original)

    def test_absent_renamed_extra_and_nested_assets_refused(self) -> None:
        self.prepare()
        path = self.output / "assets" / "install.sh"
        renamed = path.with_name("install-renamed.sh")
        path.rename(renamed)
        self.rejected()
        renamed.rename(path)
        extra = self.output / "assets" / "selfhost-cloudflare-addon.zip"
        extra.write_bytes(b"optional outside core")
        self.rejected()
        extra.unlink()
        extra.mkdir()
        (extra / "nested").write_bytes(b"unexpected")
        self.rejected()

    def test_extra_top_level_file_or_directory_refused(self) -> None:
        self.prepare()
        extra = self.output / "extra"
        extra.write_bytes(b"unused")
        self.rejected()
        extra.unlink()
        extra.mkdir()
        self.rejected()

    def test_symlink_and_hardlink_assets_refused(self) -> None:
        self.prepare()
        name = self.output / "assets" / "install.sh"
        original = name.read_bytes()
        name.unlink()
        name.symlink_to(self.assets / "install.sh")
        self.rejected()
        name.unlink()
        os.link(self.assets / "install.sh", name)
        self.rejected()
        name.unlink()
        name.write_bytes(original)

    def test_symlink_parent_and_assets_directory_refused(self) -> None:
        self.prepare()
        alias = self.base / "alias"
        alias.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(checkpoint.CheckpointError):
            checkpoint.load_checkpoint(alias, now=NOW)
        held = self.output / "assets-held"
        (self.output / "assets").rename(held)
        (self.output / "assets").symlink_to(held, target_is_directory=True)
        self.rejected()

    def test_group_writable_or_special_file_refused(self) -> None:
        self.prepare()
        path = self.output / "assets" / "install.sh"
        path.chmod(0o620)
        self.rejected()
        path.unlink()
        os.mkfifo(path, 0o600)
        self.rejected()

    def test_oversized_source_and_request_refused_without_unbounded_read(self) -> None:
        path = self.assets / "install.sh.provenance.jsonl"
        with path.open("wb") as stream:
            stream.truncate(checkpoint.MAX_FILE_BYTES["assets/install.sh.provenance.jsonl"] + 1)
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare()
        self.assertFalse((self.output / "request.json").exists())

    def test_original_inventory_run_attempt_and_image_lock_remain_binding(self) -> None:
        self.prepare()
        path = self.output / "assets" / "installer-inventory.json"
        original = path.read_bytes()
        for key, replacement in (("build_run_id", RUN + 1), ("build_run_attempt", 2),
                                 ("source_sha", REVIEW_MAIN), ("build_run_attempt", True),
                                 ("images", {"fake": "ghcr.io/fake/image:latest"})):
            inventory = json.loads(original)
            inventory[key] = replacement
            path.write_bytes(encoded(inventory))
            self.reindex()
            with self.subTest(key=key, replacement=replacement):
                self.rejected()
        path.write_bytes(original)

    def test_reindexed_operator_cannot_escape_inventory_digest(self) -> None:
        self.prepare()
        (self.output / "assets" / "marty-deploy-linux-amd64").write_bytes(b"foreign operator")
        self.reindex()
        self.rejected()

    def test_reindexed_checksum_closure_still_cannot_omit_or_duplicate(self) -> None:
        self.prepare()
        path = self.output / "assets" / "SHA256SUMS"
        original = path.read_bytes()
        original_request = self.request()
        for raw in (original.split(b"\n", 1)[1], original + original.splitlines(keepends=True)[0]):
            path.write_bytes(raw)
            value = copy.deepcopy(original_request)
            value["assets"]["SHA256SUMS"] = {"size": len(raw), "sha256": digest(raw)}
            self.save_request(value)
            self.rejected()

    def test_promoted_transaction_cannot_mix_runs_or_partial_promotion(self) -> None:
        self.prepare()
        path = self.output / "assets" / "release-transaction.json"
        original = path.read_bytes()
        changes = [lambda value: value["images"]["ui"].update(build_run_id=str(RUN + 1)),
                   lambda value: value["gates"]["public_stack"].update(run_id=str(RUN + 1)),
                   lambda value: value.update(state="promoting", promoted_roles=list(transaction.REQUIRED_IMAGE_ROLES[:-1]))]
        for change in changes:
            value = json.loads(original)
            change(value)
            path.write_bytes(encoded(value))
            self.reindex()
            self.rejected()

    def test_unsigned_promoted_transaction_copy_must_equal_signed_asset(self) -> None:
        value = json.loads(self.transaction_path.read_bytes())
        value["gates"]["public_stack"]["evidence_sha256"] = "sha256:" + "f" * 64
        self.transaction_path.write_bytes(encoded(value))
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare()
        self.assertFalse((self.output / "request.json").exists())

    def test_gate_bytes_and_manifest_are_bound_to_transaction_and_request(self) -> None:
        self.prepare()
        gate = self.output / "official-interoperability.json"
        gate.write_bytes(gate.read_bytes() + b"\n")
        value = self.request()
        value["official_gate_sha256"] = digest(gate.read_bytes())
        value["authority"]["gate_sha256"] = value["official_gate_sha256"]
        self.save_request(value)
        self.rejected()

    def test_deeply_nested_gate_is_rejected_with_contract_error_before_output(self) -> None:
        raw = b"[" * 2000 + b"0" + b"]" * 2000
        self.gate_path.write_bytes(raw)
        value = json.loads(self.transaction_path.read_bytes())
        value["gates"]["official_interoperability"]["evidence_sha256"] = digest(raw)
        self.transaction_path.write_bytes(encoded(value))
        (self.assets / "release-transaction.json").write_bytes(encoded(value))
        self.checksums(self.assets)
        with self.assertRaises(checkpoint.CheckpointError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_same_size_mutation_during_read_is_refused(self) -> None:
        self.prepare()
        target = self.output / "assets" / "install.sh"
        real_read = os.read
        changed = False
        def racing_read(fd: int, length: int) -> bytes:
            nonlocal changed
            raw = real_read(fd, length)
            if not changed and os.fstat(fd).st_ino == target.stat().st_ino and raw:
                changed = True
                target.write_bytes(b"x" * target.stat().st_size)
            return raw
        with patch.object(checkpoint.os, "read", side_effect=racing_read):
            self.rejected()
        self.assertTrue(changed)

    def test_visible_path_swap_after_read_is_refused(self) -> None:
        self.prepare()
        target = self.output / "assets" / "install.sh"
        real_payload_check = checkpoint._validate_payloads
        def swap_after_read(*args: object) -> None:
            real_payload_check(*args)
            raw = target.read_bytes()
            target.unlink()
            target.write_bytes(raw)
        with patch.object(checkpoint, "_validate_payloads", side_effect=swap_after_read):
            self.rejected()

    def test_deadline_is_rechecked_after_read_not_only_on_entry(self) -> None:
        self.prepare()
        original = checkpoint._validate_payloads
        current = NOW
        def expire_after_read(*args: object) -> None:
            nonlocal current
            original(*args)
            current = NOW + timedelta(seconds=900)
        with patch.object(checkpoint, "_clock", side_effect=lambda _now: current), \
             patch.object(checkpoint, "_validate_payloads", side_effect=expire_after_read):
            self.rejected()

    def test_cli_verify_rereads_preserve_original_expiry_and_bytes(self) -> None:
        self.prepare()
        path = self.output / "request.json"
        before = path.read_bytes()
        metadata = path.stat()
        argv = ["stable_publication_checkpoint.py", "verify", "--checkpoint", str(self.output)]
        for elapsed, expected in ((10, 0), (899, 0), (900, 1)):
            with self.subTest(elapsed=elapsed), patch.object(sys, "argv", argv), \
                 patch.object(checkpoint, "_clock", return_value=NOW + timedelta(seconds=elapsed)), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(checkpoint.main(), expected)
                if expected:
                    self.assertEqual(errors.getvalue(),
                        "Stable publication checkpoint refused; original evidence was preserved.\n")
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.stat().st_mtime_ns, metadata.st_mtime_ns)
            self.assertEqual(self.request()["not_after"], "2026-11-04T01:17:03Z")


if __name__ == "__main__":
    unittest.main()
