"""Recovery-first direction through the shared actual process/terminal owner."""

from run_canvas_worker_provider_completion_oracle import run as run_race


def run():
    return run_race("canvas-worker-provider-recovery-first-scenarios.json")
