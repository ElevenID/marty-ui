"""Final-attempt case through the shared actual renewal/recovery process owner."""

from run_canvas_worker_provider_recovery_oracle import run as run_recovery


def run():
    return run_recovery("final", "canvas-worker-provider-final-scenarios.json")
