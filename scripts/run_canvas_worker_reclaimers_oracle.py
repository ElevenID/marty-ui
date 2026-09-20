"""Reuse actual final-attempt crash/expiry with two competing reclaimers."""

from run_canvas_worker_provider_recovery_oracle import run as run_recovery


def run():
    return run_recovery("final", "canvas-worker-reclaimers-scenarios.json")
