import hashlib
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from record_selfhost_bundle_preparation import record


class BundlePreparationTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        root = Path(self.scratch.name)
        self.archive = root / "bundle.zip"
        self.lock = root / "images.json"
        self.transaction = root / "transaction.json"
        self.image = "example.org/app@sha256:" + "a" * 64
        self.lock.write_text(json.dumps({"schema": "marty.selfhost-image-lock/v1",
                                         "release": "marty-ui@1.2.3",
                                         "services": {"app": self.image}}))
        self.transaction.write_text("{}")
        self.contents = {
            ".marty-selfhost-images.json": self.lock.read_bytes(),
            "docker-compose.yml": f"services:\n  app:\n    image: {self.image}\n".encode(),
            "README.md": b"unqualified\n",
        }
        self.write_archive()

    def write_archive(self):
        marker = {"schema": "marty.selfhost-bundle-files/v1",
                  "files": {name: hashlib.sha256(data).hexdigest()
                            for name, data in self.contents.items()},
                  "directories": [""]}
        with zipfile.ZipFile(self.archive, "w") as bundle:
            bundle.writestr("bundle/", b"")
            for name, data in self.contents.items():
                bundle.writestr("bundle/" + name, data)
            bundle.writestr("bundle/.marty-selfhost-bundle.json", json.dumps(marker))

    def check(self):
        return record(self.archive, self.lock, self.transaction, "b" * 40, "123")

    def test_records_exact_archive_and_embedded_lock(self):
        receipt = self.check()
        self.assertEqual(receipt["qualification"], "unqualified")
        self.assertEqual(receipt["images"], {"app": self.image})
        self.assertEqual(receipt["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(receipt["image_lock_sha256"], hashlib.sha256(self.lock.read_bytes()).hexdigest())

    def test_rejects_embedded_lock_mismatch(self):
        self.contents[".marty-selfhost-images.json"] = b"{}"
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "embedded image lock"):
            self.check()

    def test_rejects_compose_image_mismatch(self):
        self.contents["docker-compose.yml"] = b"services:\n  app:\n    image: other\n"
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "Compose image closure"):
            self.check()

    def test_rejects_owned_file_mutation(self):
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr("bundle/README.md", b"changed")
        with self.assertRaisesRegex(ValueError, "duplicate ZIP member"):
            self.check()

    def test_rejects_uninventoried_file(self):
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr("bundle/extra.txt", b"unexpected")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.check()

    def test_rejects_uninventoried_empty_directory(self):
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr("bundle/extra/", b"")
        with self.assertRaisesRegex(ValueError, "directories differ"):
            self.check()

    def test_rejects_special_file_member(self):
        member = zipfile.ZipInfo("bundle/fifo")
        member.create_system = 3
        member.external_attr = (stat.S_IFIFO | 0o644) << 16
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr(member, b"")
        with self.assertRaisesRegex(ValueError, "special ZIP member"):
            self.check()

    def test_rejects_path_traversal(self):
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr("bundle/../escape", b"bad")
        with self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
            self.check()


if __name__ == "__main__":
    unittest.main()
