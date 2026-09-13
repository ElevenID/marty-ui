"""Regenerate the logging configuration reference in the pinned isolated image."""

import re

from test_canvas_worker_image_entrypoint import docker, owned_container
from test_canvas_worker_image_startup import HARDENED, ROOT, contract, mount


def run():
    image = contract("canvas-worker-consumer-range-oracle.json")["observed_image"]
    assert re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image)
    with owned_container(
        "--network",
        "none",
        *HARDENED,
        "--no-healthcheck",
        *mount(ROOT / "contracts", "/verification/contracts"),
        *mount(
            ROOT / "scripts/run_canvas_worker_logging_oracle.py",
            "/verification/scripts/run_canvas_worker_logging_oracle.py",
        ),
        "--entrypoint",
        "python",
        image,
        "/verification/scripts/run_canvas_worker_logging_oracle.py",
        "--check",
    ) as container:
        docker("start", container)
        status = int(docker("wait", container, timeout=20))
        logs = docker("logs", container)
        assert status == 0, "Published logging reference regeneration failed"
        assert logs == "Published worker logging reference passed (16 cases)"
        print(logs)


if __name__ == "__main__":
    run()
