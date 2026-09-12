"""Actual competing reclaimers preserve nonfinal retry eligibility and success."""

from run_canvas_worker_provider_recovery_oracle import run as run_recovery


def run():
    return run_recovery("recovery", "canvas-worker-reclaimers-retry-scenarios.json")
