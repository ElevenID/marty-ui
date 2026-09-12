"""Indexed barriers over the existing owned HTTPS observer/response owner."""

from threading import Event
import time

from canvas_worker_https_fixture import WorkerHttpsFixture


class DeadlineHttpsFixture(WorkerHttpsFixture):
    def __init__(self, paths, responses):
        super().__init__()
        assert 1 <= len(paths) == len(set(paths)) <= 3
        assert set(paths) == set(responses)
        self.paths = tuple(paths)
        self.stage = {"responses": responses}
        self.request_received = [Event() for _ in paths]
        self.response_release = [Event() for _ in paths]
        self.response_unblocked = [Event() for _ in paths]
        self.received_at = [None for _ in paths]

    def wait_for_response(self, index, path, stage):
        # The inherited observer records every request, even unexpected traffic.
        # The subclass never edits that transcript or replaces a method handler.
        assert 0 <= index < len(self.paths), (
            "Unexpected extra deadline provider request"
        )
        assert path == self.paths[index], "Unexpected deadline provider request order"
        assert stage is self.stage
        assert self.requests[index]["method"] == "GET"
        self.received_at[index] = time.monotonic()
        self.request_received[index].set()
        assert self.response_release[index].wait(30), (
            "Deadline response was not released"
        )
        self.response_unblocked[index].set()
        return True

    def close(self):
        for release in self.response_release:
            release.set()
        super().close()
