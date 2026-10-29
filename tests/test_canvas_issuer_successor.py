"""Pre-effect journal refusal controls; no runtime or credentials."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scoped_native_runtime import ref
from scoped_canvas_issuer_successor import IssuerSuccessor
from scoped_canvas_issuer_domain import attach_context


def barrier(accepted):
    return {"fileFsync": True, "parentDirectory": {"supported": accepted, "synced": accepted}}


class CanvasIssuerBarrierTests(unittest.TestCase):
    def test_domain_attachment_is_pure_for_check_and_bootstrap(self):
        context = {"require": lambda *_: self.fail("Unexpected require operation"),
                   "command": lambda *_: self.fail("Unexpected command")}
        attach_context(context, {})
        for name in ("node", "database_snapshot", "scoped_inventory_read", "publish_profile", "reconcile_owned", "controller_identity"):
            self.assertTrue(callable(context[name]))

    def test_apply_refuses_missing_intent_or_state_barrier_before_effects(self):
        for intent, state in [(False, True), (True, False)]:
            with self.subTest(intent=intent, state=state), tempfile.TemporaryDirectory() as temporary:
                calls = []
                preview = Path(temporary) / "preview.json"
                preview.write_text(json.dumps({"state": "READ_ONLY_PREVIEW_READY", "runId": "owned-run",
                                               "before": {}, "database": {}}))
                controller = IssuerSuccessor.__new__(IssuerSuccessor)
                controller.i = {"runId": "owned-run"}
                controller.state = {"operation": "CANVAS_ISSUER_SCOPED_JOBS"}
                controller.g = {"dispatch_enabled": True, "node": lambda *_: {}, "database_snapshot": lambda: {}}
                controller.store = types.SimpleNamespace(exclusive=lambda *_: barrier(intent), state=lambda *_: barrier(state))
                controller.replace = lambda *_: calls.append("stop/create/start")
                with self.assertRaisesRegex(ValueError, "DURABLE_.*_BARRIER_REQUIRED"):
                    controller.apply(ref(preview))
                self.assertEqual(calls, [])

    def test_recovery_refuses_missing_barrier_before_original_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            preview = Path(temporary) / "preview.json"
            preview.write_text("{}")
            calls = []
            state = {"new": {}}
            controller = IssuerSuccessor.__new__(IssuerSuccessor)
            controller.i = {"runId": "owned-run"}
            controller.store = types.SimpleNamespace(read=lambda _: state)
            controller.g = {"dispatch_enabled": True, "reconcile_owned": lambda _: True,
                            "rollback_journal_factory": lambda _: types.SimpleNamespace(exclusive=lambda *_: barrier(False))}
            controller.inspect = lambda _: calls.append("inspect")
            controller.command = lambda _: calls.append("start")
            with self.assertRaisesRegex(ValueError, "DURABLE_RECOVERY_INTENT_BARRIER_REQUIRED"):
                controller.rollback(ref(preview), state)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
