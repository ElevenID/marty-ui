"""Observe changed target generation using the existing real crash/expiry owner."""

from run_canvas_worker_provider_recovery_oracle import run as run_recovery


def run():
    return run_recovery("final", "canvas-worker-provider-generation-scenarios.json")
