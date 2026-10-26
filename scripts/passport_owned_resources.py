"""Fresh passport setup/retirement through existing production lifecycle APIs.

The request ports must be the already-bound recorder transport. This module
does not accept prior resource IDs or imported cleanup reports as ownership.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

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

    def check_resource(self, path, owned):
        require(owned.get("creation_returned") is True, "Resource ownership is unproven")
        code, current = self.call("flow", "GET", path)
        require(code == 200 and all(current.get(key) == owned[key]
                for key in ("id", "organization_id", "name")), "Owned passport resource changed identity")
        return current
