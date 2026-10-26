"""Offline guards for the exact legacy revocation source transform."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "maintenance" / "transform_legacy_revocation_bootstrap.py"
spec = importlib.util.spec_from_file_location("legacy_revocation_transform", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


MAIN = '''async def lifespan():
    default_profile = object()
    await _repo.save(default_profile)
    logger.info(f"Created default RevocationProfile: {default_profile.id}")
'''.replace("\n", "\r\n").encode()

ADAPTER = '''from sqlalchemy import delete, select
class PostgresRevocationProfileRepository:
    async def save(self, profile: "RevocationProfile") -> None:
        row_data = {
            "organization_id": profile.organization_id,
        }

        async with self._session_factory() as session:
            await session.execute(row_data)
            await session.commit()

    async def get(self, profile_id: str) -> "RevocationProfile | None":
        return None
'''.replace("\n", "\r\n").encode()


class TransformTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {"main.py": MAIN, "postgres_adapter.py": ADAPTER}
        patcher = patch.object(tool, "INPUT_HASHES", {name: hashlib.sha256(payload).hexdigest()
                                                       for name, payload in self.inputs.items()})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_transform_preserves_line_endings_and_scoped_transaction(self):
        result = tool.transform(tool.IMAGE, self.inputs)
        self.assertEqual(set(result), set(self.inputs))
        for payload in result.values():
            self.assertEqual(payload.count(b"\n"), payload.count(b"\r\n"))
        adapter = result["postgres_adapter.py"].decode()
        self.assertIn("async with session.begin():", adapter)
        self.assertIn("SET LOCAL lock_timeout = '10s'", adapter)
        self.assertIn("pg_advisory_xact_lock", adapter)
        self.assertIn('revocation_profiles_table.c.organization_id == "system"', adapter)
        self.assertIn('revocation_profiles_table.c.name == "Auto Revocation (Default)"', adapter)
        self.assertIn("await session.execute(revocation_profiles_table.insert()", adapter)
        self.assertEqual(adapter.count("def _profile_row_data"), 1)
        self.assertIn("row_data = self._profile_row_data(profile)", adapter)

    def test_wrong_image_or_source_or_anchor_fails_before_output(self):
        with self.assertRaisesRegex(tool.GuardError, "IMAGE_OR_SOURCE_SET_MISMATCH"):
            tool.transform("sha256:foreign", self.inputs)
        with self.assertRaisesRegex(tool.GuardError, "DEPLOYED_SOURCE_HASH_MISMATCH"):
            tool.transform(tool.IMAGE, {**self.inputs, "main.py": MAIN + b"x"})
        modified = ADAPTER.replace(b"from sqlalchemy import delete, select", b"from sqlalchemy import select")
        with patch.object(tool, "INPUT_HASHES", {"main.py": hashlib.sha256(MAIN).hexdigest(),
                                                 "postgres_adapter.py": hashlib.sha256(modified).hexdigest()}):
            with self.assertRaisesRegex(tool.GuardError, "SOURCE_ANCHOR_MISMATCH"):
                tool.transform(tool.IMAGE, {**self.inputs, "postgres_adapter.py": modified})

    def test_stage_refuses_reuse_and_hash_mismatch_without_writing(self):
        with tempfile.TemporaryDirectory() as root, patch.object(tool, "check_local_image"):
            source, output = Path(root) / "source", Path(root) / "out"
            source.mkdir()
            for name, payload in self.inputs.items():
                (source / name).write_bytes(payload)
            receipt = tool.stage(source, output)
            self.assertEqual(receipt["productionMutation"], False)
            self.assertTrue((output / "receipt.json").is_file())
            with self.assertRaisesRegex(tool.GuardError, "OUTPUT_ALREADY_EXISTS"):
                tool.stage(source, output)
            (source / "main.py").write_bytes(MAIN + b"x")
            another = Path(root) / "another"
            with self.assertRaisesRegex(tool.GuardError, "DEPLOYED_SOURCE_HASH_MISMATCH"):
                tool.stage(source, another)
            self.assertFalse(another.exists())


if __name__ == "__main__":
    unittest.main()
