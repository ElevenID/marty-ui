"""Transport-neutral batch receipt and redaction checks for protected beta."""

import hashlib
import hmac
import json
from pathlib import Path
from uuid import UUID

import pytest

from scripts.probe_passport_beta_batch import BatchProbeError, exercise


ROOT = Path(__file__).resolve().parents[1]
CONTAINER = "a" * 12
SOURCE = "b" * 40
STACK = "c" * 64
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "d" * 64
KEY = bytes(range(32))
IDS = (UUID(int=1), UUID(int=2), UUID(int=3))


def commitment(field: str, value: bytes) -> str:
    return hmac.new(KEY, b"passport-retirement/v2:" + field.encode() + b"\0" + value,
                    hashlib.sha256).hexdigest()


class Simulator:
    def __init__(self, *, duplicate: bool = False, receipt: str | None = "derived"):
        self.duplicate = duplicate
        self.receipt = receipt
        self.request_body = b""
        self.response_body = b""

    def __call__(self, command: list[str], body: bytes) -> bytes:
        assert command[:4] == ["docker", "exec", "-i", CONTAINER]
        assert "GRPC_SERVICE_TOKEN" in command[-3]
        if command[-1].endswith("/v1/personalization/batches"):
            self.request_body = body
            batch = json.loads(body)
            assert batch["organization_id"] == "org-test"
            assert len(batch["jobs"]) == 2
            assert all(job["application_id"].startswith("synthetic-") for job in batch["jobs"])
            assert all(len(job["mrz"][line]) == 44 for job in batch["jobs"]
                       for line in ("line_1", "line_2"))
            jobs = list(reversed(batch["jobs"]))
            self.response_body = json.dumps({"status": "QUEUED", "jobs": [
                {"job_id": job["job_id"],
                 "bureau_job_id": str(IDS[1] if self.duplicate else UUID(int=index + 4)),
                 "status": "QUEUED"}
                for index, job in enumerate(jobs)
            ]}, separators=(",", ":")).encode()
            return self.response_body + b"\n202"
        bureau_id = UUID(command[-1].rsplit("/", 1)[-1])
        receipt = hashlib.sha256(bureau_id.bytes).hexdigest() if self.receipt == "derived" else self.receipt
        response = json.dumps({
            "status": "SHIPPED",
            "tracking_number": f"BETA-SIM-{bureau_id.hex}",
            "callback_receipt_sha256": receipt,
        }).encode()
        return response + b"\n200"


def run(simulator: Simulator) -> dict:
    identifiers = iter(IDS)
    return exercise(
        "org-test", CONTAINER, SOURCE, STACK, SERVICES,
        runner=simulator, commitment_key=KEY, new_uuid=lambda: next(identifiers),
    )


def test_frozen_batch_contract_and_shuffled_private_response() -> None:
    contract = json.loads((ROOT / "contracts/passport-beta-batch-acceptance.json").read_text())
    assert contract["schema"] == "marty.passport-beta-batch-acceptance/v1"
    assert contract["input"]["minimum_jobs"] == 2
    assert contract["commitments"]["fields"] == ["source_job", "bureau_job", "request", "response"]
    simulator = Simulator()
    result = run(simulator)
    assert result["verified"] is True
    evidence = result["evidence"]
    assert evidence["provider_kind"] == "simulator"
    assert evidence["physical_claim"] == "not_claimed"
    assert evidence["http_status"] == 202
    assert evidence["batch_status"] == "QUEUED"
    assert evidence["request_commitment"] == commitment("request", simulator.request_body)
    assert evidence["response_commitment"] == commitment("response", simulator.response_body)
    assert evidence["submitted_job_commitments"] == [
        commitment("source_job", str(identifier).encode()) for identifier in IDS[1:]
    ]
    assert {job["source_job_commitment"] for job in evidence["returned_jobs"]} == set(
        evidence["submitted_job_commitments"]
    )
    assert len({job["bureau_job_commitment"] for job in evidence["returned_jobs"]}) == 2
    assert evidence["callback_receipts_sha256"] == [
        hashlib.sha256(UUID(int=5).bytes).hexdigest(),
        hashlib.sha256(UUID(int=4).bytes).hexdigest(),
    ]
    published = json.dumps(evidence)
    assert "org-test" not in published
    assert "synthetic-public-certificate" not in published
    assert "P<USA" not in published
    assert all(str(identifier) not in published for identifier in IDS)
    assert KEY.hex() not in published


def test_duplicate_bureau_jobs_fail_closed() -> None:
    with pytest.raises(BatchProbeError, match="one-to-one"):
        run(Simulator(duplicate=True))


def test_noncanonical_bureau_identity_fails_closed() -> None:
    simulator = Simulator()

    def noncanonical(command: list[str], body: bytes) -> bytes:
        response = simulator(command, body)
        if command[-1].endswith("/v1/personalization/batches"):
            payload = json.loads(response.rsplit(b"\n", 1)[0])
            payload["jobs"][0]["bureau_job_id"] = "{" + payload["jobs"][0]["bureau_job_id"] + "}"
            return json.dumps(payload).encode() + b"\n202"
        return response

    identifiers = iter(IDS)
    with pytest.raises(BatchProbeError, match="not canonical"):
        exercise("org-test", CONTAINER, SOURCE, STACK, SERVICES, runner=noncanonical,
                 commitment_key=KEY, new_uuid=lambda: next(identifiers))


def test_missing_signed_callback_receipt_fails_closed() -> None:
    with pytest.raises(BatchProbeError, match="signed callback receipt"):
        run(Simulator(receipt=None))


def test_duplicate_signed_callback_receipt_fails_closed() -> None:
    with pytest.raises(BatchProbeError, match="receipts are not distinct"):
        run(Simulator(receipt="e" * 64))


def test_unsigned_or_wrong_runtime_identity_never_calls_simulator() -> None:
    simulator = Simulator()
    with pytest.raises(BatchProbeError, match="Signed beta source"):
        exercise("org-test", CONTAINER, "wrong", STACK, SERVICES, runner=simulator)
    assert simulator.request_body == b""
