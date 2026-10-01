import unittest

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
        self.assertEqual(sanitize(["Cache location  secret\n", "No server running\n"]), {})


if __name__ == "__main__":
    unittest.main()
