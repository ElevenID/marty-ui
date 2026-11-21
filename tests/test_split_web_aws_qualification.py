"""Focused source-input admission coverage for the AWS diagnostic runner."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("split_web_aws", ROOT / "scripts/qualify_split_web_aws.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class DotenvAdmissionTests(unittest.TestCase):
    def test_exact_baseline_is_admitted_and_other_dotenv_inputs_are_refused(self):
        # The real tracked b109 inputs previously made every AWS preflight fail.
        runner.validate_dotenv_inputs(ROOT, runner.MARTY_REVIEWED_DOTENV)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ui").mkdir()
            for relative in runner.MARTY_REVIEWED_DOTENV:
                shutil.copyfile(ROOT / relative, root / relative)
            runner.validate_dotenv_inputs(root, runner.MARTY_REVIEWED_DOTENV)
            for relative in (".env", ".env.local", "ui/.env.local", "ui/.env.production"):
                with self.subTest(unreviewed=relative):
                    candidate = root / relative
                    candidate.write_text("VITE_API_URL=https://unreviewed.invalid\n")
                    with self.assertRaisesRegex(ValueError, "not an admitted test input"):
                        runner.validate_dotenv_inputs(root, runner.MARTY_REVIEWED_DOTENV)
                    candidate.unlink()
            with self.assertRaisesRegex(ValueError, "not an admitted test input"):
                runner.validate_dotenv_inputs(root, {})
            (root / "ui/.env.test").write_text("VITE_API_URL=https://changed.invalid\n")
            with self.assertRaisesRegex(ValueError, "Reviewed dotenv input bytes differ"):
                runner.validate_dotenv_inputs(root, runner.MARTY_REVIEWED_DOTENV)


if __name__ == "__main__":
    unittest.main()
