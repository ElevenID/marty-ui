"""Transport-neutral batch receipt and redaction checks for protected beta."""

import hashlib
import hmac
import json
from pathlib import Path
from uuid import UUID

import pytest

from scripts.probe_passport_beta_batch import BatchProbeError, _job_commit, exercise

ROOT = Path(__file__).resolve().parents[1]
CONTAINER = "a" * 12
SOURCE = "b" * 40
STACK = "c" * 64
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "d" * 64
KEY = bytes(range(32))
API_KEY = "k" * 32
IDS = (UUID(int=1), UUID(int=2), UUID(int=3))
SOURCE_JOBS = ("native-job-1", "native-job-2")
APPLICATION = {
    "organization_id": "org-test", "issuer_did": "did:example:issuer",
    "flow_execution_id": "synthetic-flow", "application_template_id": "template-test",
    "credential_template_id": "credential-test",
    "delivery_destination_profile_id": "destination-test",
    "country_code": "USA", "document_type": "TD3",
    "applicant": {"name": "Synthetic Test"},
    "mrz": {"line_1": "P<USASYNTHETIC<<TEST<<<<<<<<<<<<<<<<<<<<<<<<",
            "line_2": "0000000000USA0000000<<<<<<<<<<<<<<<<<<<<<<<<"},
    "data_groups": {"DG1": "c3ludGhldGljLWRhdGEtZ3JvdXA=", "DG2": "c3ludGhldGljLXR3bw=="},
}


def wire_commitment(field: str, value: bytes) -> str:
    return hmac.new(KEY, b"passport-retirement/v2:" + field.encode() + b"\0" + value,
                    hashlib.sha256).hexdigest()


def job_commitment(field: str, job_id: str, api_key: str = API_KEY) -> str:
    return hmac.new(api_key.encode("utf-8"), (field + ":" + job_id).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def document_digest(organization_id: str, job: dict) -> str:
    identity = {name: job[name] for name in (
        "job_id", "application_id", "country_code", "document_type",
        "data_groups", "mrz",
    )}
    identity["organization_id"] = organization_id
    return hashlib.sha256(json.dumps(identity, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


class Simulator:
    def __init__(self, *, duplicate: bool = False, receipt: str | None = "derived"):
        self.duplicate = duplicate
        self.receipt = receipt
        self.request_body = b""
        self.response_body = b""
        self.bound: set[str] = set()
        self.mapping: dict[str, str] = {}
        self.identities: dict[str, str] = {}
        self.unbound_callback_attempts = 0

    def callback(self, source: str) -> int:
        if source not in self.bound:
            self.unbound_callback_attempts += 1
            return 404
        return 204

    def __call__(self, command: list[str], body: bytes) -> bytes:
        assert command[:4] == ["docker", "exec", "-i", CONTAINER]
        assert "GRPC_SERVICE_TOKEN" in command[-3]
        if command[-1].endswith("/v1/personalization/batches"):
            self.request_body = body
            batch = json.loads(body)
            assert batch["organization_id"] == "org-test"
            assert len(batch["jobs"]) == 2
            assert {job["job_id"] for job in batch["jobs"]} == set(SOURCE_JOBS)
            assert {job["application_id"] for job in batch["jobs"]} == {"app-1", "app-2"}
            assert all(job["document_type"] == "TD3" for job in batch["jobs"])
            assert all(job["country_code"] == APPLICATION["country_code"]
                       and job["data_groups"] == APPLICATION["data_groups"]
                       and job["mrz"] == APPLICATION["mrz"] for job in batch["jobs"])
            assert all(len(job["mrz"][line]) == 44 for job in batch["jobs"]
                       for line in ("line_1", "line_2"))
            self.identities = {job["job_id"]: document_digest(batch["organization_id"], job)
                               for job in batch["jobs"]}
            jobs = list(reversed(batch["jobs"]))
            self.response_body = json.dumps({"status": "QUEUED", "jobs": [
                {"job_id": job["job_id"],
                 "bureau_job_id": str(IDS[1] if self.duplicate else UUID(int=index + 4)),
                 "status": "QUEUED"}
                for index, job in enumerate(jobs)
            ]}, separators=(",", ":")).encode()
            self.mapping = {job["job_id"]: job["bureau_job_id"]
                            for job in json.loads(self.response_body)["jobs"]}
            assert self.callback(SOURCE_JOBS[0]) == 404
            return self.response_body + b"\n202"
        bureau_id = UUID(command[-1].rsplit("/", 1)[-1])
        source = next((job for job, assigned in self.mapping.items()
                       if assigned == str(bureau_id)), None)
        if source not in self.bound:
            assert self.callback(source) == 404
            return b'{"status":"PRINTING","tracking_number":null}\n200'
        assert self.callback(source) == 204
        receipt = hashlib.sha256(bureau_id.bytes).hexdigest() if self.receipt == "derived" else self.receipt
        response = json.dumps({
            "status": "SHIPPED",
            "tracking_number": f"BETA-SIM-{bureau_id.hex}",
            "callback_receipt_sha256": receipt,
        }).encode()
        return response + b"\n200"


class Native:
    def __init__(self, simulator: Simulator, *, wrong_binding: bool = False,
                 changed_document: bool = False):
        self.simulator = simulator
        self.wrong_binding = wrong_binding
        self.changed_document = changed_document
        self.created = 0
        self.calls: list[str] = []
        self.flow_ids: dict[str, str] = {}
        self.documents: dict[str, dict] = {}
        self.active: set[str] = set()

    def __call__(self, method: str, path: str, body: dict | None,
                 api_key: str) -> tuple[int, dict]:
        assert api_key == "k" * 32
        self.calls.append(path)
        if path == "/v1/passport/applications":
            assert method == "POST" and body is not None
            assert body["flow_execution_id"].startswith("passport-batch-")
            assert {key: value for key, value in body.items()
                    if key != "flow_execution_id"} == {
                        key: value for key, value in APPLICATION.items()
                        if key != "flow_execution_id"
                    }
            self.created += 1
            source = SOURCE_JOBS[self.created - 1]
            self.flow_ids[source] = body["flow_execution_id"]
            self.documents[source] = body
            return 201, {"organization_id": "org-test", "id": source,
                         "flow_execution_id": body["flow_execution_id"],
                         "application_id": f"app-{self.created}", "status": "DRAFT"}
        number = int(path.split("/")[4].split("-")[1])
        source = SOURCE_JOBS[number - 1]
        base = {"organization_id": "org-test", "id": source,
                "application_id": f"app-{number}",
                "flow_execution_id": self.flow_ids[source]}
        if path.endswith("generate-data-groups"):
            return 200, base | {"status": "DATA_GENERATED"}
        if path.endswith("generate-sod"):
            return 200, base | {"status": "SOD_SIGNED",
                                "sod_signature_verified": True,
                                "sod_sha256": "f" * 64}
        if path.endswith("submit-personalization"):
            document = self.documents[source]
            identity = {"job_id": source, "application_id": f"app-{number}",
                        "country_code": document["country_code"],
                        "document_type": document["document_type"],
                        "data_groups": document["data_groups"],
                        "mrz": {"line_1": document["mrz"]["line_1"],
                                "line_2": document["mrz"]["line_2"]}}
            if self.changed_document:
                identity["mrz"]["line_1"] = "DRIFTED"
            if document_digest("org-test", identity) != self.simulator.identities[source]:
                return 409, {}
            bureau = self.simulator.mapping[source]
            if self.wrong_binding:
                bureau = str(UUID(int=99))
            else:
                self.simulator.bound.add(source)
            return 200, base | {"status": "SUBMITTED", "bureau_job_id": bureau}
        if path.endswith("production-status"):
            return 200, base | {"status": "ACTIVE" if source in self.active else "READY_FOR_ACTIVATION",
                                "completed_at": "2026-09-28T00:00:00Z" if source in self.active else None,
                                "bureau_job_id": self.simulator.mapping[source]}
        if path.endswith("quality-verify"):
            assert body == {"passed": True, "failure_codes": []}
            return 200, base | {"status": "READY_FOR_ACTIVATION",
                                "bureau_job_id": self.simulator.mapping[source]}
        assert path.endswith("activate")
        self.active.add(source)
        return 200, base | {"status": "ACTIVE", "completed_at": "2026-09-28T00:00:00Z",
                            "bureau_job_id": self.simulator.mapping[source]}


def run(simulator: Simulator) -> dict:
    identifiers = iter(IDS)
    return exercise(
        APPLICATION, API_KEY, CONTAINER, SOURCE, STACK, SERVICES,
        runner=simulator, native_request=Native(simulator),
        commitment_key=KEY, new_uuid=lambda: next(identifiers),
    )


def test_frozen_batch_contract_and_shuffled_private_response() -> None:
    contract = json.loads((ROOT / "contracts/passport-beta-batch-acceptance.json").read_text())
    assert contract["schema"] == "marty.passport-beta-batch-acceptance/v1"
    assert contract["input"]["minimum_jobs"] == 2
    assert "native passport jobs" in contract["input"]["native_binding"]
    assert contract["commitments"]["wire"]["fields"] == ["request", "response"]
    bureau_contract = json.loads((ROOT / "contracts/passport-beta-bureau-behavior.json").read_text())
    receipt_algorithm = bureau_contract["first_accepted_material_receipt"]["commitment_algorithm"]
    job_contract = contract["commitments"]["job_identity"]
    assert contract["commitments"]["scheme"] == receipt_algorithm["name"]
    assert job_contract["key"] == receipt_algorithm["key"]
    assert job_contract["source_job_preimage"] == receipt_algorithm["source_job_preimage"]
    assert job_contract["bureau_job_preimage"] == receipt_algorithm["bureau_job_preimage"]
    simulator = Simulator()
    result = run(simulator)
    assert result["verified"] is True
    evidence = result["evidence"]
    assert evidence["provider_kind"] == "simulator"
    assert evidence["physical_claim"] == "not_claimed"
    assert evidence["http_status"] == 202
    assert evidence["batch_status"] == "QUEUED"
    assert evidence["native_binding_verified"] is True
    assert evidence["native_completed_jobs"] == 2
    assert simulator.unbound_callback_attempts == 1
    assert evidence["request_commitment"] == wire_commitment("request", simulator.request_body)
    assert evidence["response_commitment"] == wire_commitment("response", simulator.response_body)
    assert evidence["submitted_job_commitments"] == [
        job_commitment("source-job", source) for source in SOURCE_JOBS
    ]
    assert {job["source_job_commitment"] for job in evidence["returned_jobs"]} == {
        job_commitment("source-job", source) for source in SOURCE_JOBS
    }
    assert {job["bureau_job_commitment"] for job in evidence["returned_jobs"]} == {
        job_commitment("bureau-job", bureau) for bureau in simulator.mapping.values()
    }
    assert evidence["submitted_job_commitments"][0] != wire_commitment(
        "request", SOURCE_JOBS[0].encode()
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
    assert all(source not in published for source in SOURCE_JOBS)
    assert KEY.hex() not in published
    assert API_KEY not in published


def test_job_commitments_match_frozen_first_accepted_receipt_vector() -> None:
    bureau_contract = json.loads((ROOT / "contracts/passport-beta-bureau-behavior.json").read_text())
    vector = bureau_contract["first_accepted_material_receipt"]["commitment_algorithm"]["test_vector"]
    assert _job_commit(vector["key_utf8"], "source-job", vector["source_job_id"]) == (
        vector["source_job_commitment"]
    )
    assert _job_commit(vector["key_utf8"], "bureau-job", vector["bureau_job_id"]) == (
        vector["bureau_job_commitment"]
    )
    assert job_commitment("source-job", vector["source_job_id"], vector["key_utf8"]) == (
        vector["source_job_commitment"]
    )
    assert job_commitment("bureau-job", vector["bureau_job_id"], vector["key_utf8"]) == (
        vector["bureau_job_commitment"]
    )


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
        exercise(APPLICATION, "k" * 32, CONTAINER, SOURCE, STACK, SERVICES,
                 runner=noncanonical, native_request=Native(simulator),
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
        exercise(APPLICATION, "k" * 32, CONTAINER, "wrong", STACK, SERVICES,
                 runner=simulator, native_request=lambda *args: pytest.fail("native mutation"))
    assert simulator.request_body == b""


def test_unbound_native_job_cannot_claim_simulator_receipt() -> None:
    simulator = Simulator()
    identifiers = iter(IDS)
    with pytest.raises(BatchProbeError, match="bureau binding"):
        exercise(APPLICATION, "k" * 32, CONTAINER, SOURCE, STACK, SERVICES,
                 runner=simulator, native_request=Native(simulator, wrong_binding=True),
                 commitment_key=KEY, new_uuid=lambda: next(identifiers))
    assert not simulator.bound


def test_native_document_identity_mismatch_fails_before_receipt() -> None:
    simulator = Simulator()
    identifiers = iter(IDS)
    with pytest.raises(BatchProbeError, match="bureau binding"):
        exercise(APPLICATION, "k" * 32, CONTAINER, SOURCE, STACK, SERVICES,
                 runner=simulator, native_request=Native(simulator, changed_document=True),
                 commitment_key=KEY, new_uuid=lambda: next(identifiers))
    assert simulator.unbound_callback_attempts == 1
    assert not simulator.bound


def test_batch_uses_fixed_synthetic_material_even_if_lifecycle_input_differs() -> None:
    simulator = Simulator()
    changed = dict(APPLICATION)
    changed["applicant"] = {"name": "Private Applicant"}
    changed["mrz"] = {"line_1": "PRIVATE", "line_2": "PRIVATE"}
    changed["data_groups"] = {"DG1": "cHJpdmF0ZQ==", "DG2": "cHJpdmF0ZQ=="}
    identifiers = iter(IDS)
    result = exercise(changed, "k" * 32, CONTAINER, SOURCE, STACK, SERVICES,
                      runner=simulator, native_request=Native(simulator),
                      commitment_key=KEY, new_uuid=lambda: next(identifiers))
    assert result["verified"] is True
    assert b"PRIVATE" not in simulator.request_body
    assert b"cHJpdmF0ZQ==" not in simulator.request_body
    assert b"Synthetic Test" not in json.dumps(result).encode()
