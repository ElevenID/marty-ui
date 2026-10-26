"""Fresh passport setup/retirement through existing production lifecycle APIs.

The request ports must be the already-bound recorder transport. This module
does not accept prior resource IDs or imported cleanup reports as ownership.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import UUID, uuid4

if __package__:
    from . import probe_passport_beta_native_batch as batch
    from .passport_supported_flow_references import provision_beta_physical_passport_references
    from .passport_supported_flow_start import create_physical_passport_definition
else:
    import probe_passport_beta_native_batch as batch
    from passport_supported_flow_references import provision_beta_physical_passport_references
    from passport_supported_flow_start import create_physical_passport_definition


class PassportOwnershipError(ValueError):
    pass


def require(value, message):
    if not value:
        raise PassportOwnershipError(message)


def public_key(value):
    require(isinstance(value, dict) and isinstance(value.get("kty"), str), "Owned issuer public key is unavailable")
    return {key: value[key] for key in ("kty", "crv", "x", "y", "n", "e") if key in value}


COLLECTIONS = {
    "application_template_id": "/v1/application-templates",
    "credential_template_id": "/v1/credential-templates",
    "delivery_destination_profile_id": "/v1/delivery-destinations",
    "flow_definition_id": "/v1/flows/definitions",
}


class OwnedPassportResources:
    def __init__(self, path: Path, organization: str, *, request, private_signing):
        batch.ensure_private_state_available(path)
        require(isinstance(organization, str) and bool(organization), "Owned passport organization is missing")
        self.path, self.organization = path, organization
        self.key_path = path.with_name(path.stem + ".key-recovery.json")
        batch.ensure_private_state_available(self.key_path)
        self.api_key = None
        self.request, self.private_signing = request, private_signing
        self.value = {"schema": "marty.passport-owned-resources/v1", "run_id": uuid4().hex,
                      "organization_id": organization, "resources": {}, "issuer_identities": [],
                      "jobs": [], "operations": [], "flow_start": None,
                      "cleanup_complete": False}
        self.save(initial=True)

    def save(self, *, initial=False):
        batch._write_private_state(self.path, self.value, initial=initial)

    def call(self, role, method, path, body=None, headers=None):
        if guard := getattr(self, "_failed_guard", None):
            guard()
        # Commit intent before dispatch: ambiguous failures remain recoverable.
        item = {"role": role, "method": method, "path": path,
                "request_sha256": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
                "response_received": False}
        self.value["operations"].append(item)
        self.save()
        status, response = (self.request(role, method, path, body, headers) if headers
                            else self.request(role, method, path, body))
        require(type(status) is int and 100 <= status <= 599 and isinstance(response, dict),
                "Owned passport response is malformed")
        item.update(response_received=True, http_status=status)
        self.save()
        return status, response

    def scoped(self, path):
        return path + "?organization_id=" + quote(self.organization, safe="")

    def private_call(self, path, body=None):
        if guard := getattr(self, "_failed_guard", None):
            guard()
        item = {"role": "governed-signing-service", "method": "POST" if body else "GET",
                "path": path, "response_received": False}
        self.value["operations"].append(item)
        self.save()
        response = self.private_signing(path, body)
        require(isinstance(response, dict), "Owned certificate response is malformed")
        item["response_received"] = True
        self.save()
        return response

    def fresh_plan(self, plan):
        result = copy.deepcopy(plan)
        issuer = result["application"]["issuer_did"]
        parts = issuer.split(":")
        require(len(parts) == 5 and parts[:4] == ["did", "web", "beta.elevenidllc.com", "orgs"]
                and bool(parts[4]) and len(parts[4]) + len("-demo-") + len(self.value["run_id"]) <= 128,
                "Owned passport issuer must fit the local did:web organization slug")
        # The production did:web parser accepts exactly five segments. Keep the
        # fresh marker inside the organization slug rather than adding DID paths.
        issuer = issuer + "-demo-" + self.value["run_id"]
        result["application"]["issuer_did"] = issuer
        certificate = result["certificate_plan"]
        certificate["csca"]["issuer_did"] = issuer
        certificate["dsc"].update(dsc_issuer_did=issuer, csca_issuer_did=issuer)
        certificate["csca"]["certificate_id"] = "demo-csca-" + self.value["run_id"]
        certificate["dsc"]["csca_certificate_id"] = certificate["csca"]["certificate_id"]
        certificate["dsc"]["idempotency_key"] = "demo-dsc-" + self.value["run_id"]
        # No fixture-supplied definition or template ID can become owned. These
        # placeholders are replaced by successful create responses after the
        # governed chain exists, before the first real Flow operation.
        result["selected_flow"]["flow_definition_id"] = "UNBOUND"
        result["selected_flow"]["references"] = {key: "UNBOUND" for key in COLLECTIONS if key != "flow_definition_id"}
        self.value["plan"] = result
        self.save()
        return result

    def create_inputs(self, plan, reference_plan):
        require(isinstance(reference_plan, dict) and set(reference_plan) == {
                    "name_prefix", "compliance_profile_id"}
                and isinstance(reference_plan["name_prefix"], str)
                and bool(reference_plan["name_prefix"].strip()),
                "Fresh passport reference plan cannot adopt IDs or custom resource payloads")
        require(plan["application"]["organization_id"] == self.organization
                and not self.value["resources"], "Fresh passport reference setup cannot be replayed")
        prefix = reference_plan["name_prefix"][:80] + " " + self.value["run_id"]
        collections = {path: field for field, path in COLLECTIONS.items()}

        def request(method, path, body=None, headers=None):
            creating = method == "POST" and path in collections
            if creating:
                require(isinstance(body, dict) and "id" not in body
                        and body.get("organization_id") == self.organization
                        and self.value["run_id"] in body.get("name", ""),
                        "Canonical passport create lost genuine ownership")
            status, response = self.call("flow", method, path, body, headers)
            if creating:
                field = collections[path]
                require(status == (201 if field == "delivery_destination_profile_id" else 200)
                        and isinstance(response.get("id"), str) and bool(response["id"])
                        and response.get("organization_id") == self.organization
                        and response.get("name") == body["name"]
                        and (field == "delivery_destination_profile_id" or response.get("status") == "DRAFT"),
                        "Canonical passport resource was not freshly created")
                self.value["resources"][field] = {"id": response["id"], "name": body["name"],
                    "organization_id": self.organization, "creation_returned": True}
                self.save()
            return status, response

        # These existing producers own the credential-first dependency order,
        # application Idempotency-Key, physical payloads and strict readbacks.
        references = provision_beta_physical_passport_references(
            request, self.organization, prefix, plan["application"]["issuer_did"],
            "passport-demo-" + self.value["run_id"], reference_plan["compliance_profile_id"])
        definition = create_physical_passport_definition(
            lambda method, path, body: request(method, path, body),
            self.organization, prefix + " flow", references)
        result = copy.deepcopy(plan)
        result["selected_flow"].update(flow_definition_id=definition, references=references)
        self.value["plan"] = result
        self.save()
        return result

    def create_key(self):
        body = {"name": "Passport demo " + self.value["run_id"], "is_test": True,
                "scopes": ["credentials:issue"],
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
        code, key = self.call("flow", "POST", self.scoped("/v1/api-keys"), body)
        # Retain the exact newly created authority before checking every
        # response field, so a contract mismatch cannot orphan a live key.
        require(code == 200 and isinstance(key, dict)
                and key.get("organization_id") == self.organization
                and key.get("name") == body["name"] and isinstance(key.get("id"), str)
                and bool(key["id"]), "Scoped passport API key identity was not returned")
        self.value["api_key_id"] = key["id"]
        self.save()
        raw_key = key.get("key")
        if isinstance(raw_key, str) and len(raw_key) >= 32:
            self.api_key = raw_key
            batch._write_private_state(self.key_path, {"schema": "marty.passport-owned-api-key/v1",
                "run_id": self.value["run_id"], "organization_id": self.organization,
                "key_id": key["id"], "key": raw_key}, initial=True)
        require(key.get("scopes") == body["scopes"] and key.get("scope_type") == "ORGANIZATION"
                and key.get("enabled") is True and isinstance(raw_key, str) and len(raw_key) >= 32,
                "Scoped passport API key was not newly created")
        return raw_key

    def create_issuers(self, plan):
        certificate = plan["certificate_plan"]
        require(certificate["organization_id"] == self.organization, "Certificate tenant changed")
        for role, purpose, did in (
            ("csca", "csca", certificate["csca"]["issuer_did"]),
            ("dsc", "x509_doc_signer", certificate["dsc"]["dsc_issuer_did"]),
        ):
            # A fresh path-scoped identity tuple prevents repair/adoption of a shared profile.
            require(self.value["run_id"] in did, "Passport issuer DID must contain this genuine run marker")
            payload = {"issuer_did": did, "key_purpose": purpose,
                       "credential_format": "ICAO_EMRTD", "algorithm": "ES256"}
            status, response = self.call(role, "POST", self.scoped("/v1/signing-keys/issuer-identities"), payload)
            identity = response.get("identity", {})
            require(status == 200 and response.get("created") is True
                    and all(identity.get(key) == value for key, value in payload.items()),
                    "Passport issuer identity is not newly owned")
            owned = {"role": role, "tuple": payload, "creation_returned": True}
            self.value["issuer_identities"].append(owned)
            self.save()
            code, resolved = self.call(role, "POST", self.scoped("/v1/signing-keys/issuer-identities/resolve"), payload)
            require(code == 200, "New owned issuer does not resolve")
            owned["public_key"] = public_key(resolved.get("public_jwk"))
            self.save()

    def owned_job(self, event, record):
        require(event in ("companion_created", "batch_bound", "companion_terminal")
                and record.get("organization_id") == self.organization,
                "Unexpected owned passport job observation")
        self.value["jobs"].append({"event": event, **record})
        self.save()

    def start_selected_flow(self, body, request):
        """Journal one owned start before dispatch; a lost response never authorizes retry."""
        definition = self.value["resources"].get("flow_definition_id", {})
        require(self.value["flow_start"] is None
                and isinstance(body, dict) and set(body) == {
                    "organization_id", "flow_definition_id", "initial_context"}
                and body["organization_id"] == self.organization
                and body["flow_definition_id"] == definition.get("id")
                and definition.get("creation_returned") is True,
                "Selected Flow start is not bound to this owned definition")
        self.value["flow_start"] = {
            "state": "INTENT", "organization_id": self.organization,
            "flow_definition_id": definition["id"],
            "request_sha256": hashlib.sha256(json.dumps(body, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
        }
        self.save()
        try:
            status, response = request("POST", "/v1/flows/instances", body)
        except Exception:
            self._reconcile_selected_flow_start(request)
            raise
        if status != 200 or not self._owned_started_flow(response):
            self._reconcile_selected_flow_start(request)
            raise PassportOwnershipError("Selected Flow start response is not owned")
        self.value["flow_start"].update(state="OBSERVED", instance_id=response["id"],
                                         application_id=response["context_data"]["physical_document_job"]["application_id"],
                                         source_job_id=response["context_data"]["physical_document_job"]["id"])
        self.save()
        return status, response

    def _owned_started_flow(self, response):
        if not isinstance(response, dict):
            return False
        context = response.get("context_data")
        job = context.get("physical_document_job") if isinstance(context, dict) else None
        start = self.value["flow_start"]
        return (isinstance(job, dict) and isinstance(response.get("id"), str)
                and bool(response["id"]) and response.get("organization_id") == self.organization
                and response.get("flow_id") == start["flow_definition_id"]
                and response.get("flow_type") == "physical_document_issuance"
                and response.get("status") == "IN_PROGRESS"
                and job.get("organization_id") == self.organization
                and job.get("flow_execution_id") == response["id"]
                and job.get("issuer_did") == self.value["plan"]["application"]["issuer_did"]
                and job.get("status") == "DRAFT"
                and all(isinstance(job.get(key), str) and bool(job[key])
                        for key in ("id", "application_id")))

    def _reconcile_selected_flow_start(self, request):
        start = self.value["flow_start"]
        start["state"] = "UNKNOWN"
        self.save()
        path = ("/v1/flows/instances?organization_id=" + quote(self.organization, safe="")
                + "&flow_definition_id=" + quote(start["flow_definition_id"], safe="")
                + "&limit=100&offset=0")
        try:
            status, rows = request("GET", path, None)
            if (status == 200 and isinstance(rows, list) and len(rows) == 1
                    and self._owned_started_flow(rows[0])):
                job = rows[0]["context_data"]["physical_document_job"]
                start.update(state="RECONCILED_AFTER_UNKNOWN_RESPONSE",
                             instance_id=rows[0]["id"], application_id=job["application_id"],
                             source_job_id=job["id"])
                self.save()
        except Exception:
            pass  # Preserve UNKNOWN and the original failed start, without retry.

    def retire(self, *, selected, certificate_id, check_key_denied, retire_sessions):
        require("failed_cleanup" not in self.value, "Failed cleanup cannot qualify successful retirement")
        require(self.value.get("plan") and len(self.value["issuer_identities"]) == 2,
                "Owned passport setup is incomplete")
        require(all(item["response_received"] for item in self.value["operations"]),
                "Ambiguous passport mutation requires explicit reconciliation")
        start = self.value.get("flow_start")
        require(isinstance(start, dict) and start.get("state") == "OBSERVED"
                and start.get("instance_id") == selected["flow_instance_id"]
                and start.get("application_id") == selected["application_id"]
                and start.get("source_job_id") == selected["source_job_id"],
                "Selected Flow start is not durably observed with exact owned job")
        bound = [item for item in self.value["jobs"] if item["event"] == "batch_bound"]
        require(len(bound) == 1 and len(bound[0].get("jobs", [])) == 2,
                "Exact two-job ownership journal is unavailable")
        jobs = bound[0]["jobs"]
        require(all(job.get("organization_id") == self.organization and all(
                    isinstance(job.get(field), str) and bool(job[field]) for field in
                    ("id", "application_id", "flow_execution_id", "bureau_job_id")) for job in jobs)
                and all(len({job[field] for job in jobs}) == 2
                        for field in ("id", "application_id", "bureau_job_id")),
                "Two-job journal has foreign or duplicated identity")
        require(any(job.get("application_id") == selected["application_id"]
                    and job.get("id") == selected["source_job_id"]
                    and job.get("bureau_job_id") == selected["bureau_job_id"] for job in jobs),
                "Selected passport job differs from the actual returned batch")
        for job in jobs:
            path = "/v1/passport/applications/" + quote(job["application_id"], safe="") + "/production-status"
            code, actual = self.call("api", "GET", path)
            require(code == 200 and all(actual.get(field) == job.get(field) for field in
                    ("id", "organization_id", "application_id", "flow_execution_id", "bureau_job_id"))
                    and actual.get("status") == "ACTIVE" and bool(actual.get("completed_at")),
                    "Owned passport job is not terminal with exact identity")
        require(bound[0].get("owned_flow_instance_ids") == [selected["flow_instance_id"]]
                and isinstance(bound[0].get("standalone_companion_execution_id"), str)
                and bound[0]["standalone_companion_execution_id"].startswith("passport-native-batch-")
                and {row["flow_execution_id"] for row in jobs} == {
                    selected["flow_instance_id"], bound[0]["standalone_companion_execution_id"]},
                "Owned Flow instance set differs from native companion correlation")
        for instance_id in bound[0]["owned_flow_instance_ids"]:
            instance_path = "/v1/flows/instances/" + quote(instance_id, safe="")
            code, instance = self.call("flow", "GET", instance_path)
            require(code == 200 and instance.get("id") == instance_id
                    and instance.get("organization_id") == self.organization
                    and instance.get("flow_id") == self.value["resources"]["flow_definition_id"]["id"]
                    and str(instance.get("status")).upper() == "COMPLETED", "Owned passport Flow is not terminal")
        self._retire_owned_material(certificate_id)
        # Key ownership is supplied only by the same run's actual create port.
        api_key_id = self.value.get("api_key_id")
        require(isinstance(api_key_id, str) and bool(api_key_id), "Cannot revoke unowned passport API authority")
        code, response = self.call("flow", "DELETE", self.scoped("/v1/api-keys/" + quote(api_key_id, safe="")))
        require(code == 200 and response.get("success") is True, "Owned passport key revocation failed")
        require(check_key_denied() is True, "Retired passport key is still accepted")
        batch.clear_private_state(self.key_path)
        require(retire_sessions() is True, "Owned passport session retirement is incomplete")
        self.value["cleanup_complete"] = True
        self.save()
        return {"complete": True, "terminal_jobs": 2, "flow_retired": True,
                "templates_deprecated": True, "issuer_tuples_retired": True,
                "csca_revoked": True, "api_key_denied": True,
                "sessions_denied": True, "history_retained": True}

    def _retire_owned_material(self, certificate_id):
        owned = self.value["resources"]["flow_definition_id"]
        path = COLLECTIONS["flow_definition_id"] + "/" + quote(owned["id"], safe="")
        self.check_resource(path, owned)
        code, draft = self.call("flow", "PATCH", path, {"organization_id": self.organization, "name": owned["name"]})
        require(code == 200 and draft.get("id") == owned["id"]
                and draft.get("organization_id") == self.organization
                and str(draft.get("status")).upper() == "DRAFT"
                and all(draft.get(key) == value for key, value in self.value["plan"]["selected_flow"]["references"].items()),
                "Owned Flow did not enter draft with unchanged references")
        code, _ = self.call("flow", "DELETE", path)
        require(code == 200, "Owned draft Flow deletion failed")
        code, _ = self.call("flow", "GET", path)
        require(code == 404, "Owned Flow remains reusable")
        for field in ("credential_template_id", "application_template_id"):
            owned = self.value["resources"][field]
            path = COLLECTIONS[field] + "/" + quote(owned["id"], safe="")
            self.check_resource(path, owned)
            code, _ = self.call("flow", "POST", path + "/deprecate")
            require(code == 200, "Owned template deprecation failed")
            code, actual = self.call("flow", "GET", path)
            require(code == 200 and actual.get("id") == owned["id"]
                    and actual.get("organization_id") == self.organization
                    and str(actual.get("status")).upper() == "DEPRECATED", "Owned template remains active")
        # Revoke only our genuinely new certificate before removing its issuer tuple.
        require(certificate_id == self.value["plan"]["certificate_plan"]["csca"]["certificate_id"],
                "Cannot retire a foreign CSCA certificate")
        certificate_path = ("/internal/documents/" + quote(self.organization, safe="")
                            + "/csca-certificates/" + quote(certificate_id, safe=""))
        prior = self.private_call(certificate_path)
        csca = next(item for item in self.value["issuer_identities"] if item["role"] == "csca")
        require(prior.get("certificate_id") == certificate_id
                and prior.get("metadata", {}).get("issuer_did") == csca["tuple"]["issuer_did"]
                and public_key(prior.get("public_jwk")) == csca["public_key"],
                "CSCA lifecycle record no longer matches the genuinely owned issuer")
        revoked = self.private_call(certificate_path + "/revoke", {"reason": "Owned demo run retired"})
        readback = self.private_call(certificate_path)
        require(all(value.get("certificate_id") == certificate_id and value.get("status") == "REVOKED"
                    and bool(value.get("revoked_at")) for value in (revoked, readback)),
                "Owned CSCA revocation did not persist")
        for identity in reversed(self.value["issuer_identities"]):
            code, current = self.call(identity["role"], "POST", self.scoped("/v1/signing-keys/issuer-identities/resolve"), identity["tuple"])
            require(code == 200 and public_key(current.get("public_jwk")) == identity["public_key"],
                    "Owned issuer key changed before retirement")
            code, retired = self.call(identity["role"], "DELETE", self.scoped("/v1/signing-keys/issuer-identities"), identity["tuple"])
            require(code == 200 and all(retired.get("deleted", {}).get(key) == value
                    for key, value in identity["tuple"].items()), "Owned issuer retirement failed")
            code, _ = self.call(identity["role"], "POST", self.scoped("/v1/signing-keys/issuer-identities/resolve"), identity["tuple"])
            require(code == 404, "Retired issuer tuple still resolves")
        destination = self.value["resources"]["delivery_destination_profile_id"]
        path = COLLECTIONS["delivery_destination_profile_id"] + "/" + quote(destination["id"], safe="")
        self.check_resource(path, destination)
        code, _ = self.call("flow", "DELETE", path)
        require(code == 200, "Owned delivery destination retirement failed")
        code, _ = self.call("flow", "GET", path)
        require(code == 404, "Owned delivery destination remains available")

    @classmethod
    def failed_continuation(cls, path, *, journal_ref, wire_ref, failure_ref, fixture_ref,
                            request, private_signing, verify_runtime, resume=False):
        """Continue a hash-bound failed batch, never adopt it as a fresh demo.

        Ports retain the existing bound transport contract. verify_runtime must
        verify the actual runtime and return its reviewed profile SHA-256, not a
        report's qualification flag. No credential or wire key is imported.
        """
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, "Failed cleanup JSON has duplicate fields")
                result[key] = value
            return result

        def read(ref):
            require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}
                    and isinstance(ref["sha256"], str) and batch.SHA256.fullmatch(ref["sha256"]),
                    "Failed cleanup source reference is invalid")
            source = Path(ref["path"])
            require(source.is_absolute() and source.is_file() and not source.is_symlink()
                    and source.resolve() == source.absolute()
                    and Path.cwd().resolve() not in source.resolve().parents,
                    "Failed cleanup source must be an existing private regular file")
            if os.name == "posix":
                require(source.parent.stat().st_mode & 0o077 == 0
                        and source.stat().st_mode & 0o077 == 0, "Failed cleanup source is not private")
            raw = source.read_bytes()
            require(hashlib.sha256(raw).hexdigest() == ref["sha256"], "Failed cleanup source changed")
            return json.loads(raw, object_pairs_hook=unique)

        original, wire, failure = (read(ref) for ref in (journal_ref, wire_ref, failure_ref))
        raw_fixture = read(fixture_ref)
        # Project only existing provenance metadata. Never retain fixture.custody.
        fixture = {"schema": raw_fixture.get("schema"), "wire": raw_fixture.get("privateStatePath"),
                   "handoff": raw_fixture.get("privateHandoffPath"),
                   "organization_id": raw_fixture.get("plan", {}).get("application", {}).get("organization_id")}
        del raw_fixture
        producer_directory = Path(fixture_ref["path"]).parent
        require(fixture["schema"] == "marty.passport-fresh-private/v3"
                and isinstance(fixture["wire"], str) and isinstance(fixture["handoff"], str)
                and Path(fixture["wire"]) == Path(wire_ref["path"])
                and Path(fixture["handoff"]).with_name(Path(fixture["handoff"]).stem + ".owned-resources.json")
                    == Path(journal_ref["path"])
                and all(Path(ref["path"]).parent == producer_directory for ref in (journal_ref, wire_ref, failure_ref))
                and Path(fixture["handoff"]).parent == producer_directory,
                "Producer fixture does not bind these exact journal/wire paths")
        failure_path = Path(failure_ref["path"])
        token = failure_path.name.removeprefix("passport-failure-").removesuffix(".json")
        try:
            require(failure_path.name == "passport-failure-" + UUID(token).hex + ".json"
                    and set(producer_directory.glob("passport-failure-*.json")) == {failure_path},
                    "Producer failure reference is ambiguous")
        except (ValueError, TypeError, AttributeError) as exc:
            raise PassportOwnershipError("Producer failure reference is invalid") from exc
        require(set(failure) <= {"schema", "stage", "errorType", "qualificationEligible", "sourceTrace",
                                "captureFailureType", "captureFailureTrace"}
                and isinstance(failure.get("stage"), str) and bool(failure["stage"])
                and isinstance(failure.get("errorType"), str) and bool(failure["errorType"]),
                "Failure record differs from its privacy-preserving producer contract")
        require(original.get("schema") == "marty.passport-owned-resources/v1"
                and original.get("cleanup_complete") is False
                and failure.get("schema") == "marty.passport-private-failure/v1"
                and failure.get("qualificationEligible") is False
                and wire.get("schema") == "marty.passport-beta-native-pending/v1",
                "Sources do not describe an unresolved failed owned batch")
        organization, run = original.get("organization_id"), original.get("run_id")
        require(isinstance(run, str) and len(run) == 32 and all(c in "0123456789abcdef" for c in run)
                and isinstance(organization, str) and organization
                and fixture["organization_id"] == organization
                and wire.get("organization_id") == organization
                and all(item.get("response_received") is True for item in original["operations"]),
                "Original batch has ambiguous authority or operations")
        authority = original.get("authority_retirement", {})
        require(authority.get("complete") is True and authority.get("keyDenied") is True
                and authority.get("qualificationEligible") is False,
                "Original failed-run authority has not been retired")
        resources, plan = original["resources"], original["plan"]
        require(set(resources) == set(COLLECTIONS) and all(
            row.get("creation_returned") is True and row.get("organization_id") == organization
            and isinstance(row.get("id"), str) and row["id"]
            and isinstance(row.get("name"), str) and run in row["name"]
            for row in resources.values()), "Original resources are not genuinely owned")
        require(plan["selected_flow"]["flow_definition_id"] == resources["flow_definition_id"]["id"]
                and all(plan["selected_flow"]["references"].get(key) == resources[key]["id"]
                        for key in resources if key != "flow_definition_id"),
                "Original plan and resource ownership disagree")
        identities = original["issuer_identities"]
        require(len(identities) == 2 and {row.get("role") for row in identities} == {"csca", "dsc"}
                and all(row.get("creation_returned") is True and run in row.get("tuple", {}).get("issuer_did", "")
                        and public_key(row.get("public_key")) for row in identities)
                and plan["certificate_plan"]["organization_id"] == organization
                and plan["certificate_plan"]["csca"]["certificate_id"] == "demo-csca-" + run,
                "Original certificate/issuer ownership is incomplete")
        bound = [item for item in original["jobs"] if item.get("event") == "batch_bound"]
        events = [row.get("event") for row in original["jobs"]]
        require(len(events) == 3 and set(events) == {"companion_created", "batch_bound", "companion_terminal"}
                and len(bound) == 1 and len(bound[0].get("jobs", [])) == 2
                and bound[0].get("organization_id") == organization
                and bound[0].get("batch_id") == wire.get("batch_id"), "Batch ownership is ambiguous")
        jobs = bound[0]["jobs"]
        fields = ("id", "organization_id", "application_id", "flow_execution_id", "bureau_job_id")
        require(all(job.get("organization_id") == organization and all(
            isinstance(job.get(key), str) and job[key] for key in fields) for job in jobs)
            and all(len({job[key] for job in jobs}) == 2 for key in ("id", "application_id", "bureau_job_id")),
            "Batch has foreign or duplicate jobs")
        try:
            require(all(str(UUID(job[key])) == job[key] for job in jobs for key in ("id", "application_id")),
                    "Native job identity is not canonical")
        except (ValueError, TypeError, AttributeError) as exc:
            raise PassportOwnershipError("Native job identity is not canonical") from exc
        selected = next((job for job in jobs if job["id"] == wire.get("selected_source_job_id")), None)
        companion = next((job for job in jobs if job["id"] == wire.get("companion_source_job_id")), None)
        require(selected is not None and companion is not None and selected is not companion
                and selected["application_id"] == wire.get("selected_application_id")
                and selected["flow_execution_id"] == wire.get("selected_flow_instance_id")
                and companion["application_id"] == wire.get("companion_application_id")
                and companion["flow_execution_id"] == wire.get("companion_flow_execution_id")
                and bound[0].get("owned_flow_instance_ids") == [selected["flow_execution_id"]]
                and bound[0].get("standalone_companion_execution_id") == companion["flow_execution_id"]
                and companion["flow_execution_id"].startswith("passport-native-batch-"),
                "Private wire identity differs from the owned batch")
        created = next(row for row in original["jobs"] if row["event"] == "companion_created")
        require(created.get("flow_instance_created") is False
                and all(created.get(key) == companion[key] for key in
                        ("id", "organization_id", "application_id", "flow_execution_id"))
                and created.get("issuer_did") == plan["application"]["issuer_did"],
                "Companion creation is not the exact standalone owned job")
        start = original.get("flow_start")
        if start is not None:
            require(start.get("state") == "OBSERVED" and start.get("instance_id") == selected["flow_execution_id"]
                    and start.get("application_id") == selected["application_id"]
                    and start.get("source_job_id") == selected["id"], "Unknown Flow start cannot be adopted")
        # Pre-1579 journals have no flow_start. Keep that absence truthful: the
        # wire/batch correlation and fresh owned Flow readback are separate proof.
        terminal = [row for row in original["jobs"] if row.get("event") == "companion_terminal"]
        require(len(terminal) == 1 and terminal[0].get("status") == "ACTIVE"
                and terminal[0].get("completed_at") and all(terminal[0].get(key) == companion[key] for key in fields),
                "The companion is not the recorded successful job")
        source_refs = {"journal": journal_ref, "wire": wire_ref, "failure": failure_ref, "fixture": fixture_ref}
        require(isinstance(path, Path) and path.is_absolute() and not path.is_symlink()
                and path.resolve() == path.absolute() and Path.cwd().resolve() not in path.resolve().parents
                and all(path != Path(ref["path"]) for ref in source_refs.values()),
                "Failed continuation must be a separate private path")
        if os.name == "posix" and path.exists():
            require(path.parent.stat().st_mode & 0o077 == 0 and path.stat().st_mode & 0o077 == 0,
                    "Failed continuation is not private")
        profile = verify_runtime()
        require(isinstance(profile, str) and batch.SHA256.fullmatch(profile), "Runtime binding is unverified")
        instance = cls.__new__(cls)
        instance.path, instance.organization = path, organization
        instance.key_path = path.with_name(path.stem + ".key-recovery.json")
        instance.api_key, instance.request, instance.private_signing = None, request, private_signing
        immutable = ("schema", "run_id", "organization_id", "resources", "plan", "issuer_identities", "jobs", "api_key_id",
                     "flow_start", "authority_retirement")
        if path.exists():
            require(resume and not path.is_symlink(), "Failed cleanup continuation already exists")
            instance.value = json.loads(path.read_bytes(), object_pairs_hook=unique)
            require(all(instance.value.get(key) == original.get(key) for key in immutable)
                    and ("flow_start" in instance.value) == ("flow_start" in original)
                    and instance.value.get("operations", [])[:len(original["operations"])] == original["operations"]
                    and instance.value.get("failed_cleanup", {}).get("sources") == source_refs
                    and instance.value["failed_cleanup"].get("runtime_profile_sha256") == profile,
                    "Continuation identity or runtime changed")
            state = instance.value["failed_cleanup"]
            expected_intent = cls._failed_cancel_intent(journal_ref["sha256"], selected["id"])
            require(instance.value.get("cleanup_complete") is False
                    and state.get("qualificationEligible") is False
                    and state.get("stage") in {"PREFLIGHT", "CANCEL_INTENT", "NATIVE_CANCELLED",
                                               "RESOURCES_RETIRED_AUTHORITY_PENDING"}
                    and (state.get("cancel_intent") == expected_intent if state["stage"] != "PREFLIGHT"
                         else "cancel_intent" not in state)
                    and ("flow_cancel_intent" not in state or state["flow_cancel_intent"] is True),
                    "Continuation cancellation intent/stage is invalid or needs separate lifecycle reconciliation")
            if state["stage"] == "RESOURCES_RETIRED_AUTHORITY_PENDING":
                require(all(isinstance(state.get(key), str) and batch.SHA256.fullmatch(state[key]) for key in
                            ("successful_companion_sha256", "selected_cancelled_sha256", "owned_flow_instances_readback_sha256"))
                        and isinstance(state.get("cancellation_audit"), dict),
                        "Authority-only recovery lacks recorded terminal readbacks")
        else:
            batch.ensure_private_state_available(path)
            instance.value = copy.deepcopy(original)
            instance.value["failed_cleanup"] = {"sources": copy.deepcopy(source_refs),
                "runtime_profile_sha256": profile, "qualificationEligible": False,
                "failure_body_has_identity_fields": False,
                "failure_correlation": "OPERATOR_PINNED_HASH_AND_EXISTING_PRODUCER_FIXTURE_DIRECTORY_ONLY",
                "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "stage": "PREFLIGHT"}
            instance.save(initial=True)
        def guard():
            for ref in source_refs.values():
                read(ref)
            require(verify_runtime() == profile and all(instance.value.get(key) == original.get(key) for key in immutable)
                    and set(producer_directory.glob("passport-failure-*.json")) == {failure_path}
                    and instance.value["failed_cleanup"]["qualificationEligible"] is False
                    and instance.value["failed_cleanup"]["driver_sha256"]
                        == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "Failed cleanup ownership/runtime changed")
        instance._failed_guard = guard
        instance._failed_jobs = selected, companion
        return instance

    @staticmethod
    def _failed_cancel_intent(journal_sha256, job_id):
        return {"key": "passport-failed-" + hashlib.sha256((journal_sha256 + job_id).encode()).hexdigest(),
                "body": {"expected_job_id": job_id, "reason_code": "ADMINISTRATIVE_ABANDONMENT",
                         "reason": "Original owned demo failed; administratively retire its local job"}}

    def retire_failed(self, *, retire_cleanup_authority):
        """Always close the separately owned cleanup authority, including on error."""
        require(hasattr(self, "_failed_guard"), "Failed cleanup was not privately bound")
        def close_authority():
            state = self.value["failed_cleanup"]
            try:
                retired = retire_cleanup_authority() is True
            except Exception as exc:
                retired = False
                state["cleanup_authority_error_type"] = type(exc).__name__
            state["cleanup_authority_retired"] = retired
            self.save()
            return retired
        try:
            result = self._retire_failed_resources()
        except Exception:
            close_authority()
            raise
        require(close_authority(), "Fresh cleanup authority is not retired")
        self._failed_guard()
        self.value["failed_cleanup"].update(stage="RETIRED_FAILED_ONLY", qualificationEligible=False)
        self.value["cleanup_complete"] = True
        self.save()
        return {"complete": True, "qualificationEligible": False, **result}

    def _retire_failed_resources(self):
        """Failed-only terminal disposition; never qualifies the original demo."""
        require(hasattr(self, "_failed_guard"), "Failed cleanup was not privately bound")
        self._failed_guard()
        state = self.value["failed_cleanup"]
        if state["stage"] == "RESOURCES_RETIRED_AUTHORITY_PENDING":
            return self._verify_failed_retired_state()
        selected, companion = self._failed_jobs
        allowed_pending = {
            "/v1/passport/applications/" + quote(selected["application_id"], safe="") + "/cancel",
            "/v1/flows/instances/" + quote(selected["flow_execution_id"], safe="") + "/cancel",
        }
        original_count = len(json.loads(Path(state["sources"]["journal"]["path"]).read_bytes())["operations"])
        require(all(item.get("response_received") is True or
                    (item.get("method") == "POST" and item.get("path") in allowed_pending)
                    for item in self.value["operations"][original_count:]),
                "Ambiguous lifecycle mutation requires separate readback reconciliation")
        for field, owned in self.value["resources"].items():
            current = self.check_resource(COLLECTIONS[field] + "/" + quote(owned["id"], safe=""), owned)
            if field == "flow_definition_id":
                require(all(current.get(key) == value for key, value in self.value["plan"]["selected_flow"]["references"].items()),
                        "Owned Flow references changed")
        def job(row):
            code, actual = self.call("api", "GET", "/v1/passport/applications/" + quote(row["application_id"], safe=""))
            require(code == 200 and all(actual.get(key) == row[key] for key in
                    ("id", "organization_id", "application_id", "flow_execution_id", "bureau_job_id"))
                    and actual.get("credential_template_id") == self.value["resources"]["credential_template_id"]["id"]
                    and actual.get("delivery_destination_profile_id") == self.value["resources"]["delivery_destination_profile_id"]["id"]
                    and actual.get("issuer_did") == self.value["plan"]["application"]["issuer_did"],
                    "Current native job differs from original ownership")
            return actual
        before, successful = job(selected), job(companion)
        require(successful.get("status") == "ACTIVE" and successful.get("completed_at"), "Successful companion changed")
        successful_sha256 = hashlib.sha256(json.dumps(successful, sort_keys=True).encode()).hexdigest()
        require(state.get("successful_companion_sha256", successful_sha256) == successful_sha256,
                "Successful companion differs from the original readback")
        allowed = {"DRAFT", "DATA_GENERATED", "SOD_SIGNED", "SUBMITTED", "IN_PRODUCTION", "QUALITY_CHECK", "READY_FOR_ACTIVATION"}
        require(before.get("status") in allowed or (before.get("status") == "CANCELLED" and "cancel_intent" in state),
                "Successful or unrelated terminal job cannot enter failed cancellation")
        flow_id = selected["flow_execution_id"]
        flow_path = "/v1/flows/instances/" + quote(flow_id, safe="")
        code, flow = self.call("flow", "GET", flow_path)
        def owned_flow(value):
            return self._failed_owned_flow(value, selected)
        require(code == 200 and owned_flow(flow) and (str(flow.get("status")).upper() == "IN_PROGRESS"
                or (str(flow.get("status")).upper() == "CANCELLED" and state.get("flow_cancel_intent") is True)),
                "Current Flow is not the exact failed owned instance")
        intent = self._failed_cancel_intent(state["sources"]["journal"]["sha256"], selected["id"])
        key, body = intent["key"], intent["body"]
        require(state.get("cancel_intent", intent) == intent, "Cancellation replay identity changed")
        state.update(cancel_intent=intent, stage="CANCEL_INTENT", successful_companion_sha256=successful_sha256)
        self.save()  # Same exact key/body is durable before any native mutation.
        code, cancelled = self.call("api", "POST", "/v1/passport/applications/" + quote(selected["application_id"], safe="") + "/cancel",
                                    body, {"idempotency-key": key})
        audit = cancelled.get("administrative_cancellation", {})
        returned = cancelled.get("job", {})
        require(isinstance(audit, dict) and isinstance(returned, dict), "Native cancellation response is malformed")
        require(code == 200 and cancelled.get("bureau_cancellation_requested") is False
                and cancelled.get("flow_cancellation_requested") is False
                and audit.get("bureau_cancellation_requested") is False
                and audit.get("job_id") == selected["id"] and audit.get("organization_id") == self.organization
                and audit.get("actor_kind") == "AUTHENTICATED_PASSPORT_TENANT"
                and audit.get("actor_organization_id") == self.organization
                and audit.get("prior_status") in allowed
                and audit.get("reason_code") == body["reason_code"] and audit.get("reason") == body["reason"]
                and audit.get("recorded_at") and audit.get("event_id")
                and returned.get("status") == "CANCELLED"
                and all(returned.get(key) == selected[key] for key in
                        ("id", "organization_id", "application_id", "flow_execution_id", "bureau_job_id")),
                "Native cancellation audit is unproven")
        try:
            require(str(UUID(audit["event_id"])) == audit["event_id"]
                    and datetime.fromisoformat(audit["recorded_at"]).utcoffset() is not None,
                    "Native cancellation audit identity/time is invalid")
        except (ValueError, TypeError, AttributeError) as exc:
            raise PassportOwnershipError("Native cancellation audit identity/time is invalid") from exc
        current = job(selected)
        require(current.get("status") == "CANCELLED" and job(companion) == successful,
                "Native cancellation or successful companion readback changed")
        state.update(stage="NATIVE_CANCELLED", cancellation_audit=copy.deepcopy(audit),
                     selected_cancelled_sha256=hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest())
        self.save()
        if str(flow.get("status")).upper() != "CANCELLED":
            state["flow_cancel_intent"] = True
            self.save()
            code, result = self.call("flow", "POST", flow_path + "/cancel")
            require(code == 200 and owned_flow(result) and str(result.get("status")).upper() == "CANCELLED",
                    "Separate Flow cancellation was not returned")
        code, flow = self.call("flow", "GET", flow_path)
        require(code == 200 and owned_flow(flow) and str(flow.get("status")).upper() == "CANCELLED",
                "Owned Flow cancellation did not persist")
        self._failed_guard()
        code, instances = self.request("flow", "GET", "/v1/flows/instances?organization_id=" + quote(self.organization, safe="")
            + "&flow_definition_id=" + quote(self.value["resources"]["flow_definition_id"]["id"], safe="") + "&limit=100&offset=0", None)
        require(code == 200 and isinstance(instances, list) and len(instances) == 1 and owned_flow(instances[0])
                and str(instances[0].get("status")).upper() == "CANCELLED", "Additional or nonterminal Flow instances block retirement")
        state["owned_flow_instances_readback_sha256"] = hashlib.sha256(json.dumps(instances, sort_keys=True).encode()).hexdigest()
        self.save()
        self._retire_owned_material(self.value["plan"]["certificate_plan"]["csca"]["certificate_id"])
        self._failed_guard()
        state.update(stage="RESOURCES_RETIRED_AUTHORITY_PENDING", qualificationEligible=False)
        self.save()
        return {"originalFailurePreserved": True,
                "selectedJobCancelled": True, "successfulCompanionPreserved": True,
                "flowCancelled": True, "bureauCancellationRequested": False, "historyRetained": True}

    def _failed_owned_flow(self, value, selected):
        if not isinstance(value, dict) or not isinstance(value.get("context_data"), dict):
            return False
        context = value["context_data"].get("physical_document_job")
        return (isinstance(context, dict) and value.get("id") == selected["flow_execution_id"]
                and value.get("organization_id") == self.organization
                and value.get("flow_id") == self.value["resources"]["flow_definition_id"]["id"]
                and all(context.get(key) == selected[key] for key in
                        ("id", "organization_id", "application_id", "flow_execution_id", "bureau_job_id")))

    def _verify_failed_retired_state(self):
        """Authority-only recovery re-observes retirement, never repeats it."""
        state = self.value["failed_cleanup"]
        selected, companion = self._failed_jobs
        for row, digest, status in [(selected, "selected_cancelled_sha256", "CANCELLED"),
                                    (companion, "successful_companion_sha256", "ACTIVE")]:
            code, current = self.call("api", "GET", "/v1/passport/applications/" + quote(row["application_id"], safe=""))
            require(code == 200 and current.get("status") == status
                    and all(current.get(key) == row[key] for key in
                            ("id", "organization_id", "application_id", "flow_execution_id", "bureau_job_id"))
                    and hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest() == state[digest],
                    "Authority-only recovery has changed native history")
        flow_path = "/v1/flows/instances/" + quote(selected["flow_execution_id"], safe="")
        code, flow = self.call("flow", "GET", flow_path)
        require(code == 200 and self._failed_owned_flow(flow, selected)
                and str(flow.get("status")).upper() == "CANCELLED",
                "Authority-only recovery has no exact terminal Flow")
        self._failed_guard()
        code, instances = self.request("flow", "GET", "/v1/flows/instances?organization_id=" + quote(self.organization, safe="")
            + "&flow_definition_id=" + quote(self.value["resources"]["flow_definition_id"]["id"], safe="") + "&limit=100&offset=0", None)
        require(code == 200 and isinstance(instances, list) and len(instances) == 1
                and self._failed_owned_flow(instances[0], selected)
                and str(instances[0].get("status")).upper() == "CANCELLED"
                and hashlib.sha256(json.dumps(instances, sort_keys=True).encode()).hexdigest()
                    == state["owned_flow_instances_readback_sha256"],
                "Authority-only recovery has changed owned Flow history")
        for field in ("flow_definition_id", "delivery_destination_profile_id"):
            code, _ = self.call("flow", "GET", COLLECTIONS[field] + "/" + quote(self.value["resources"][field]["id"], safe=""))
            require(code == 404, "Retired owned resource is available again")
        for field in ("credential_template_id", "application_template_id"):
            owned = self.value["resources"][field]
            current = self.check_resource(COLLECTIONS[field] + "/" + quote(owned["id"], safe=""), owned)
            require(str(current.get("status")).upper() == "DEPRECATED", "Owned template is not retired")
        certificate_id = self.value["plan"]["certificate_plan"]["csca"]["certificate_id"]
        certificate = self.private_call("/internal/documents/" + quote(self.organization, safe="")
                                       + "/csca-certificates/" + quote(certificate_id, safe=""))
        csca = next(row for row in self.value["issuer_identities"] if row["role"] == "csca")
        require(certificate.get("certificate_id") == certificate_id and certificate.get("status") == "REVOKED"
                and certificate.get("revoked_at")
                and certificate.get("metadata", {}).get("issuer_did") == csca["tuple"]["issuer_did"]
                and public_key(certificate.get("public_jwk")) == csca["public_key"],
                "Authority-only recovery has no exact revoked certificate")
        for identity in self.value["issuer_identities"]:
            code, _ = self.call(identity["role"], "POST", self.scoped("/v1/signing-keys/issuer-identities/resolve"), identity["tuple"])
            require(code == 404, "Retired issuer identity resolves again")
        self._failed_guard()
        state["authority_only_terminal_readbacks_verified"] = True
        self.save()
        return {"originalFailurePreserved": True, "selectedJobCancelled": True,
                "successfulCompanionPreserved": True, "flowCancelled": True,
                "bureauCancellationRequested": False, "historyRetained": True, "authorityOnlyResume": True}

    def check_resource(self, path, owned):
        require(owned.get("creation_returned") is True, "Resource ownership is unproven")
        code, current = self.call("flow", "GET", path)
        require(code == 200 and all(current.get(key) == owned[key]
                for key in ("id", "organization_id", "name")), "Owned passport resource changed identity")
        return current


def retire_failed_owned_resources(path, *, journal_ref, wire_ref, failure_ref, fixture_ref,
                                 request, private_signing, verify_runtime, retire_cleanup_authority,
                                 resume=False):
    """Own the supplied dedicated authority even when source construction fails.

    The caller provisions and binds only its fresh cleanup authority. This
    function never accepts/revives the original failed run's credentials.
    """
    attempted, failure = False, None
    def close():
        nonlocal attempted
        attempted = True
        return retire_cleanup_authority()
    try:
        continuation = OwnedPassportResources.failed_continuation(path, journal_ref=journal_ref,
            wire_ref=wire_ref, failure_ref=failure_ref, fixture_ref=fixture_ref, request=request,
            private_signing=private_signing, verify_runtime=verify_runtime, resume=resume)
        return continuation.retire_failed(retire_cleanup_authority=close)
    except BaseException as exc:
        failure = exc
        raise
    finally:
        if not attempted:
            try:
                retired = close() is True
            except Exception:
                retired = False
            if not retired and failure is not None:
                failure.add_note("Dedicated cleanup authority retirement is unverified")
