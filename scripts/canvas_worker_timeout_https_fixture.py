"""One owned HTTPS response, released independently of worker outcomes."""

import copy
from threading import Event, Thread
import time

from canvas_worker_https_fixture import WorkerHttpsFixture


class TimeoutHttpsFixture(WorkerHttpsFixture):
    def __init__(self, expected_request, response, *, delay_seconds):
        super().__init__()
        assert set(expected_request) == {"method", "path", "authorization", "accept"}
        assert expected_request["method"] == "GET"
        assert expected_request["path"].startswith("/")
        assert 0 <= delay_seconds < 20
        assert response["status"] == 200
        self.expected_request = copy.deepcopy(expected_request)
        self.stage = copy.deepcopy(response)
        self.delay_seconds = delay_seconds
        self.request_started = Event()
        self.prompt_ready = Event()
        self.response_unblocked = Event()
        self.cancel_controller = Event()
        self.received_at = None
        self.released_at = None
        self.controller = None

    def __enter__(self):
        super().__enter__()
        try:
            self.controller = Thread(target=self._control, daemon=False)
            self.controller.start()
            return self
        except BaseException:
            self.close()
            raise

    def _wait(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while not predicate():
            if self.cancel_controller.wait(0.01):
                return False
            assert time.monotonic() < deadline, "Owned timeout controller expired"
        return not self.cancel_controller.is_set()

    def _control(self):
        try:
            if not self._wait(self.request_started.is_set, 35):
                return
            if self.delay_seconds:
                ready = self._wait(
                    lambda: time.monotonic() >= self.received_at + self.delay_seconds,
                    25,
                )
            else:
                ready = self._wait(self.prompt_ready.is_set, 3)
            if ready:
                self.released_at = time.monotonic()
                self.release.set()
        except BaseException:
            self.failures.append("Owned timeout release controller failed")
            self.release.set()

    def wait_for_response(self, index, path, stage):
        assert index == 0, "Unexpected extra timeout provider request"
        assert path == self.expected_request["path"], "Unexpected timeout request path"
        assert stage is self.stage
        assert self.requests == [self.expected_request], (
            "Timeout provider authentication or request contract differs"
        )
        self.received_at = time.monotonic()
        self.request_started.set()
        assert self.release.wait(30), "Owned timeout response was never released"
        self.response_unblocked.set()
        return True

    def assert_requests(self):
        assert not self.failures, "Owned timeout transport failed"
        assert self.requests == [self.expected_request], (
            "Actual timeout provider requests differ"
        )

    def close(self):
        self.cancel_controller.set()
        self.release.set()
        try:
            if self.controller is not None and self.controller.ident is not None:
                self.controller.join(timeout=5)
                assert not self.controller.is_alive(), (
                    "Owned timeout controller did not stop"
                )
        finally:
            super().close()
