"""One real HTTPS JSON body on an outcome-independent bounded flush schedule.

The existing request-handler thread owns the entire schedule: no extra worker,
timer or controller thread is introduced. Headers keep the shared Content-Length
framing. A held pre-response snapshot is the sole externally released barrier.
"""

import copy
import json
import math
import ssl
from threading import Event, Lock, RLock
import time

from canvas_worker_https_fixture import WorkerHttpsFixture


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


class BodyTimeoutHttpsFixture(WorkerHttpsFixture):
    MAX_BODY_BYTES = 65_536
    MAX_CHUNKS = 16
    MAX_SCHEDULE_SECONDS = 60

    def __init__(
        self,
        expected_request,
        response,
        *,
        chunk_offsets,
        late_disconnect_from_index=None,
        initial_wait_seconds=30.0,
    ):
        super().__init__()
        _require(
            type(expected_request) is dict
            and set(expected_request) == {"method", "path", "authorization", "accept"}
            and all(type(value) is str for value in expected_request.values())
            and expected_request["method"] == "GET"
            and expected_request["path"].startswith("/")
            and expected_request["accept"] == "application/json",
            "Invalid body-schedule request contract",
        )
        _require(
            type(response) is dict
            and set(response) == {"status", "body"}
            and type(response["status"]) is int
            and response["status"] == 200
            and type(response["body"]) in (dict, list),
            "Body schedule requires a plain uncompressed successful JSON response",
        )
        _require(
            type(chunk_offsets) in (list, tuple)
            and 2 <= len(chunk_offsets) <= self.MAX_CHUNKS
            and all(_number(value) for value in chunk_offsets)
            and chunk_offsets[0] == 0
            and all(
                left < right for left, right in zip(chunk_offsets, chunk_offsets[1:])
            )
            and chunk_offsets[-1] <= self.MAX_SCHEDULE_SECONDS,
            "Invalid bounded body flush schedule",
        )
        _require(
            _number(initial_wait_seconds) and 0 < initial_wait_seconds <= 30,
            "Invalid body initial-snapshot wait bound",
        )
        _require(
            late_disconnect_from_index is None
            or (
                type(late_disconnect_from_index) is int
                and late_disconnect_from_index == len(chunk_offsets) - 1
            ),
            "Only the final body slot can declare an expected late peer close",
        )
        try:
            encoded = json.dumps(
                response["body"], separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise AssertionError(
                "Body schedule response must be finite valid JSON"
            ) from None
        _require(
            len(encoded) <= self.MAX_BODY_BYTES,
            "Body schedule response exceeds its byte bound",
        )
        # Empty roster [] still has real nonempty writes in all four slots.
        # Prefix whitespace preserves the final closing delimiter for the last
        # slot: every proper chunk prefix remains an incomplete JSON document.
        encoded = b" " * max(0, len(chunk_offsets) - len(encoded)) + encoded
        count = len(chunk_offsets)
        self.body_bytes = encoded
        self.chunks = tuple(
            encoded[len(encoded) * index // count : len(encoded) * (index + 1) // count]
            for index in range(count)
        )
        self.expected_request = copy.deepcopy(expected_request)
        self.stage = copy.deepcopy(response)
        self.chunk_offsets = tuple(float(value) for value in chunk_offsets)
        self.late_disconnect_from_index = late_disconnect_from_index
        self.initial_wait_seconds = float(initial_wait_seconds)
        self.request_started = Event()
        self.initial_ready = Event()
        self.body_started = Event()
        self.chunk_events = tuple(Event() for _ in self.chunks)
        self.schedule_completed = Event()
        # Signals the body writer's finally block only. Header/parse failures
        # need not reach it; server_close still joins those request handlers.
        self.handler_finished = Event()
        self.cancel_schedule = Event()
        self.received_at = None
        self.body_started_at = None
        self.chunk_observations = []
        self._observation_lock = Lock()
        # Base entry can call self.close() on partial allocation failure.
        # Reentrancy preserves that cleanup while serializing entry and close.
        self._close_lock = RLock()
        self._entry_started = False
        self._closed = False

    def __enter__(self):
        with self._close_lock:
            _require(
                not self._entry_started and not self._closed,
                "Owned body fixture is single-use",
            )
            # Failed entry is single-use too: never overwrite partially owned
            # handles or reopen an object whose cancellation events are set.
            self._entry_started = True
            return super().__enter__()

    def wait_for_response(self, index, path, stage):
        _require(
            index == 0
            and path == self.expected_request["path"]
            and stage is self.stage
            and self.requests == [self.expected_request],
            "Body provider request differs from its exact contract",
        )
        self.received_at = time.monotonic()
        self.request_started.set()
        _require(
            self.initial_ready.wait(self.initial_wait_seconds),
            "Body initial-snapshot barrier was never released",
        )
        # Capture the origin before the shared handler writes headers or body.
        self.body_started_at = time.monotonic()
        self.body_started.set()
        # A held snapshot is not permission for broad TLS/header suppression.
        # Only the explicitly declared final-slot close is handled below.
        return False

    def encode_response_body(self, response):
        _require(response is self.stage, "Unexpected body response owner")
        return self.body_bytes

    def configure_request_connection(self, handler):
        # This opt-in runs before HTTP parsing and header/body writes. It does
        # not alter the inherited pre-handler TLS accept/handshake boundary.
        handler.connection.settimeout(2.0)

    def _wait_until(self, offset):
        deadline = self.body_started_at + offset
        while not self.cancel_schedule.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            self.cancel_schedule.wait(remaining)
        return False

    def _record(self, index, started, ended, outcome, category):
        with self._observation_lock:
            _require(
                len(self.chunk_observations) == index,
                "Body flush observation order differs",
            )
            self.chunk_observations.append(
                {
                    "index": index,
                    "scheduled_offset_seconds": self.chunk_offsets[index],
                    "write_started_seconds": started - self.body_started_at,
                    "write_completed_seconds": ended - self.body_started_at,
                    # byte_count is attempted length, not assumed peer receipt.
                    "byte_count": len(self.chunks[index]),
                    "flushed_byte_count": (
                        len(self.chunks[index]) if outcome == "flushed" else None
                    ),
                    "outcome": outcome,
                    "disconnect_category": category,
                }
            )
        self.chunk_events[index].set()

    def write_response_body(self, handler, body, *, index, path, stage):
        _require(
            index == 0
            and path == self.expected_request["path"]
            and stage is self.stage
            and body == self.body_bytes
            and self.body_started_at is not None,
            "Unexpected body write owner or payload",
        )
        try:
            for chunk_index, chunk in enumerate(self.chunks):
                if not self._wait_until(self.chunk_offsets[chunk_index]):
                    return
                started = time.monotonic()
                try:
                    written = handler.wfile.write(chunk)
                    _require(
                        written == len(chunk), "Body flush did not write its full chunk"
                    )
                    handler.wfile.flush()
                except (
                    BrokenPipeError,
                    ConnectionResetError,
                    ssl.SSLEOFError,
                    ssl.SSLZeroReturnError,
                ) as error:
                    if chunk_index != self.late_disconnect_from_index:
                        raise
                    category = {
                        BrokenPipeError: "broken_pipe",
                        ConnectionResetError: "connection_reset",
                        ssl.SSLEOFError: "tls_eof",
                        ssl.SSLZeroReturnError: "tls_closed",
                    }.get(type(error))
                    if category is None:
                        raise
                    self._record(
                        chunk_index, started, time.monotonic(), "peer_closed", category
                    )
                else:
                    self._record(
                        chunk_index, started, time.monotonic(), "flushed", None
                    )
            self.schedule_completed.set()
        finally:
            self.handler_finished.set()

    def assert_requests(self):
        _require(not self.failures, "Owned body transport failed")
        _require(
            self.requests == [self.expected_request],
            "Actual body provider requests differ",
        )

    def observations(self):
        with self._observation_lock:
            return copy.deepcopy(self.chunk_observations)

    def close(self):
        with self._close_lock:
            if self._closed:
                return
            self.cancel_schedule.set()
            self.initial_ready.set()
            super().close()
            self._closed = True
