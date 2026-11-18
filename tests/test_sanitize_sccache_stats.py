import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.ci.sanitize_sccache_stats import sanitize


class SanitizeSccacheStatsTest(unittest.TestCase):
    def test_only_allowlisted_numeric_counters_are_emitted(self):
        sample = [
            "Compile requests                    3166\n",
            "Cache hits                          2247\n",
            "Cache hits (Rust)                   1445\n",
            "Cache write errors                    0\n",
            "Cache location                  ghac, name: private-value\n",
            "Base directories                /private/workspace\n",
            "Cache hits rate                   100.00 %\n",
        ]

        self.assertEqual(
            sanitize(sample),
            {
                "compile_requests": 3166,
                "cache_hits": 2247,
                "cache_hits_rust": 1445,
                "cache_write_errors": 0,
            },
        )

    def test_empty_or_unrecognized_stats_do_not_leak_text(self):
        self.assertEqual(
            sanitize(["Cache location  secret\n", "No server running\n"]), {}
        )

    def test_cli_labels_host_capture_and_excludes_backend_details(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "scripts/ci/sanitize_sccache_stats.py"],
            cwd=root,
            input="Compile requests  12\nCache location  ghac, name: private\n",
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(result.stdout),
            {
                "schema_version": 1,
                "capture_point": "after_reusable_host_compile_step",
                "counters": {"compile_requests": 12},
            },
        )
        self.assertNotIn("private", result.stdout)

        missing = subprocess.run(
            [sys.executable, "scripts/ci/sanitize_sccache_stats.py"],
            cwd=root,
            input="Cache location  ghac, name: private\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(missing.stdout, "")
        self.assertNotIn("private", missing.stderr)


if __name__ == "__main__":
    unittest.main()
