"""Source-only producer identity controls; no compiler/Docker qualification."""
import sys
import os
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import prepare_local_official_native_build as prepare


class LatestPreparationTests(unittest.TestCase):
    def test_historical_selection_remains_frozen(self):
        self.assertEqual(prepare.selected_sources(prepare.build.OFFICIAL_PROFILE),
                         (prepare.PRODUCT, prepare.CORE, prepare.FREEZE_SHA256))
        self.assertEqual(prepare.PRODUCT, "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f")

    def test_latest_selection_is_exact_closed_source(self):
        self.assertEqual(prepare.selected_sources(prepare.LATEST_PROFILE),
                         ("852dbb5cc0cca79cfe0bbbed5cb8fb94cda0ad34", prepare.CORE,
                          "075a9bafaf27bd31acfe8372c3172e04cf584120882018ff327e71044b69a5c1"))
        with self.assertRaisesRegex(ValueError, "UNKNOWN_REVIEWED_BUILD_PROFILE"):
            prepare.selected_sources("caller-supplied-target")

    def test_explicit_producer_requires_complete_latest_binding(self):
        for profile, repository, revision in [
            (prepare.build.OFFICIAL_PROFILE, Path("."), "a" * 40),
            (prepare.LATEST_PROFILE, Path("."), None),
            (prepare.LATEST_PROFILE, None, "a" * 40),
        ]:
            with self.subTest(profile=profile, repository=repository), mock.patch.object(prepare, "git") as git:
                with self.assertRaisesRegex(ValueError, "EXPLICIT_PRODUCER_REQUIRES_LATEST_PROFILE"):
                    prepare.producer_identity(Path("."), profile, repository, revision)
                git.assert_not_called()

    def test_git_object_producer_never_reads_primary_head_or_user_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository, directory = root / "user-repository", root / "operator"
            repository.mkdir()
            expected = {}
            for name in prepare.OPERATOR_NAMES:
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                expected[name] = ("source-only-" + name).encode()
                path.write_bytes(expected[name])
            def git(_repo, *args):
                if args == ("remote", "get-url", "origin"):
                    return prepare.ORIGINS["ui"].encode()
                if args == ("cat-file", "-t", "a" * 40):
                    return b"commit"
                if len(args) == 2 and args[0] == "show":
                    return expected[args[1].split(":scripts/", 1)[1]]
                self.fail("Primary HEAD/worktree must not enter an explicit Git-object source export")
            with mock.patch.object(prepare, "git", side_effect=git):
                self.assertEqual(prepare.producer_identity(directory, prepare.LATEST_PROFILE,
                                 repository, "a" * 40), (repository.resolve(), "a" * 40))
                (directory / "scoped_native_build.py").write_bytes(b"unreviewed local bytes")
                with self.assertRaisesRegex(ValueError, "REVIEWED_BUILD_TOOL_SOURCE_CHANGED"):
                    prepare.producer_identity(directory, prepare.LATEST_PROFILE, repository, "a" * 40)

    def test_foreign_producer_origin_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(prepare, "git", return_value=b"https://example.com/foreign.git"):
            with self.assertRaisesRegex(ValueError, "CANONICAL_PRODUCER_COMMIT_REQUIRED"):
                prepare.producer_identity(Path(tmp), prepare.LATEST_PROFILE, Path(tmp), "a" * 40)



    def test_matching_git_blob_reuses_only_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cached, destination = root / "old.rs", root / "new.rs"
            cached.write_bytes(b"same Git blob")
            destination.write_bytes(cached.read_bytes())
            os.utime(cached, ns=(1_000_000_000, 1_000_000_000))
            digest = hashlib.sha256(cached.read_bytes()).hexdigest()
            prior = {"directory": root, "files": {"old.rs": {"bytes": cached.stat().st_size, "sha256": digest, "mode": 0o100644}}}
            self.assertTrue(prepare.reuse_timestamp(destination, "old.rs", cached.stat().st_size, digest, prior, 0o100644))
            self.assertEqual(destination.stat().st_mtime_ns, cached.stat().st_mtime_ns)
            self.assertEqual(destination.read_bytes(), b"same Git blob")

    def test_changed_git_blob_keeps_fresh_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "new.rs"
            destination.write_bytes(b"new implementation")
            os.utime(destination, ns=(2_000_000_000, 2_000_000_000))
            prior = {"directory": root, "files": {"old.rs": {"bytes": 3, "sha256": "a" * 64, "mode": 0o100644}}}
            self.assertFalse(prepare.reuse_timestamp(destination, "old.rs", destination.stat().st_size,
                             hashlib.sha256(destination.read_bytes()).hexdigest(), prior, 0o100644))
            self.assertEqual(destination.stat().st_mtime_ns, 2_000_000_000)

    def test_modified_prior_source_is_not_accepted_as_cache_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.rs").write_bytes(b"modified")
            destination = root / "new.rs"
            destination.write_bytes(b"original")
            prior = {"directory": root, "files": {"old.rs": {"bytes": 8, "sha256": hashlib.sha256(b"original").hexdigest(), "mode": 0o100644}}}
            with self.assertRaisesRegex(ValueError, "PRIOR_SOURCE_BYTES_CHANGED"):
                prepare.reuse_timestamp(destination, "old.rs", 8, hashlib.sha256(b"original").hexdigest(), prior, 0o100644)


    def test_git_mode_change_keeps_fresh_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "script.sh"
            destination.write_bytes(b"same bytes")
            os.utime(destination, ns=(3_000_000_000, 3_000_000_000))
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            prior = {"directory": root, "files": {"script.sh": {"bytes": 10, "sha256": digest, "mode": 0o100644}}}
            self.assertFalse(prepare.reuse_timestamp(destination, "script.sh", 10, digest, prior, 0o100755))
            self.assertEqual(destination.stat().st_mtime_ns, 3_000_000_000)


    def test_primary_linux_worktree_setting_does_not_block_git_object_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "core.autocrlf", "false"], check=True)
            (repository / "code.rs").write_bytes(b"// source-only fixture\n")
            subprocess.run(["git", "-C", str(repository), "add", "code.rs"], check=True)
            tree = subprocess.check_output(["git", "-C", str(repository), "write-tree"]).decode().strip()
            revision = subprocess.check_output(["git", "-C", str(repository),
                "-c", "user.name=SourceTest", "-c", "user.email=source@example.invalid",
                "-c", "commit.gpgsign=false", "commit-tree", tree, "-m", "source fixture"]).decode().strip()
            subprocess.run(["git", "--git-dir=" + str(repository / ".git"),
                            "--work-tree=" + str(repository), "config", "core.worktree", "/mnt/unavailable"], check=True)
            self.assertEqual(prepare.git(repository, "config", "--get", "core.worktree").strip(), b"/mnt/unavailable")
            result = prepare.export(repository, revision, repository / "export")
            self.assertEqual(result["fileCount"], 1)
            self.assertEqual((repository / "export/code.rs").read_bytes(), b"// source-only fixture\n")
            self.assertEqual(prepare.git(repository, "config", "--get", "core.worktree").strip(), b"/mnt/unavailable")


    def test_launcher_uses_separate_producer_git_objects_and_preserves_old_receipts(self):
        import run_local_official_native_build as launcher
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            product, producer_repo = root / "product", root / "producer"
            for repo in (product, producer_repo):
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator = root / "export/operator"
            operator.mkdir(parents=True)
            names = ["run_local_official_native_build.py", "scoped_native_build.py", "scoped_native_profiles.py"]
            for name in names:
                data = ("# reviewed fixture " + name + "\n").encode()
                (operator / name).write_bytes(data)
                path = producer_repo / "scripts" / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(data)
            tool = producer_repo / "scripts/build-rust-service-binaries.sh"
            tool.write_bytes(b"# reviewed build tool\n")
            subprocess.run(["git", "-C", str(producer_repo), "-c", "core.autocrlf=false", "add", "scripts"], check=True)
            tree = subprocess.check_output(["git", "-C", str(producer_repo), "write-tree"]).decode().strip()
            commit = subprocess.check_output(["git", "-C", str(producer_repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit-tree", tree, "-m", "producer only"]).decode().strip()
            subprocess.run(["git", "--git-dir=" + str(producer_repo / ".git"), "--work-tree=" + str(producer_repo), "config", "core.worktree", "/mnt/unavailable"], check=True)
            packet = {"state": "SOURCE_EXPORTED_NO_COMPILER", "buildProfile": launcher.LATEST_PROFILE,
                      "freeze": {"sha256": prepare.build.LATEST_FREEZE_SHA256}, "producerRevision": commit,
                      "producerRepository": str(producer_repo), "producerTree": tree,
                      "buildTool": {"path": str(tool)}, "sources": {"ui": {"repository": str(product)}},
                      "operatorFiles": {name: {"path": str(operator / name), "bytes": (operator / name).stat().st_size,
                                              "sha256": launcher.sha(operator / name)} for name in names}}
            packet_path = operator.parent / "source-export.json"
            with mock.patch.object(launcher, "__file__", str(operator / names[0])), mock.patch.object(prepare.build, "__file__", str(operator / names[1])), mock.patch.object(launcher.profiles, "__file__", str(operator / names[2])):
                def check():
                    packet_path.write_text(json.dumps(packet), encoding="utf-8")
                    return launcher.source_export(packet_path, launcher.sha(packet_path))
                self.assertEqual(check()["producerRepository"], str(producer_repo))
                self.assertEqual(prepare.git(producer_repo, "config", "--get", "core.worktree").strip(), b"/mnt/unavailable")
                # Existing immutable receipts resolve their producer in the product repository.
                del packet["producerRepository"]
                packet["sources"]["ui"]["repository"] = str(producer_repo)
                self.assertEqual(check()["producerRevision"], commit)


if __name__ == "__main__":
    unittest.main()
