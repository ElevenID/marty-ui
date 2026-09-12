"""Reuse actual-process execution for all four Canvas REST fact types."""

from run_canvas_worker_rest_oracle import run as run_rest


def run():
    return run_rest("canvas-worker-facts-scenarios.json")
