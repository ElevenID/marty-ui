#!/usr/bin/env python3
"""Join protected passport publication and soak with the exact live beta release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

if __package__:
    from .collect_passport_beta_acceptance import (
        REQUIRED_PROBES,
        production_attachment_commitment,
        production_snapshot_commitment,
        verify_attestations,
    )
    from .collect_passport_beta_aggregate_acceptance import collect_aggregate
    from .collect_passport_beta_soak_sample import (
        production_public_site,
        read_private_handoff,
    )
    from .match_passport_beta_preliminary_soak import match_preliminary_soak
    from .match_passport_beta_publication import match_publication
    from .probe_passport_beta_batch import _identity_commit
    from .probe_passport_beta_gateway import request_beta
    from .probe_passport_beta_host import (
        assert_production_unchanged,
        beta_legacy_drain,
        beta_native_route_ownership,
        production_attachment_sha256,
        production_snapshot,
    )
    from .read_protected_passport_artifact import read_artifact
    from .verify_protected_passport_soak import verify_protected
else:
    from collect_passport_beta_acceptance import (
        REQUIRED_PROBES,
        production_attachment_commitment,
        production_snapshot_commitment,
        verify_attestations,
    )
    from collect_passport_beta_aggregate_acceptance import collect_aggregate
    from collect_passport_beta_soak_sample import (
        production_public_site,
        read_private_handoff,
    )
    from match_passport_beta_preliminary_soak import match_preliminary_soak
    from match_passport_beta_publication import match_publication
    from probe_passport_beta_batch import _identity_commit
    from probe_passport_beta_gateway import request_beta
    from probe_passport_beta_host import (
        assert_production_unchanged,
        beta_legacy_drain,
        beta_native_route_ownership,
        production_attachment_sha256,
        production_snapshot,
    )
    from read_protected_passport_artifact import read_artifact
    from verify_protected_passport_soak import verify_protected


SHA = re.compile(r"[0-9a-f]{40}\Z")
SLUG = "physical-passport-issuance-evidence"
DEMO_MANIFEST = "https://beta.elevenidllc.com/demos/manifests/2026.08.0.json"
DEMO_PAGE = f"https://beta.elevenidllc.com/demos/2026.08.0/{SLUG}"
EXPECTED_DRAIN = {
    "verified": True,
    "evidence": {
        "in_flight_jobs": 0,
        "legacy_or_unknown_artifacts": 0,
        "active_physical_document_flows": 0,
        "database": "beta",
        "source": "live PostgreSQL",
    },
}


class FinalAcceptanceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FinalAcceptanceError(message)


def public_get(url: str, limit: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/html",
            "Cache-Control": "no-cache",
            "User-Agent": "MartyPassportBeta/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            require(
                response.status == 200 and response.geturl() == url,
                "D-12 public demo URL is unavailable",
            )
            raw = response.read(limit + 1)
    except OSError as exc:
        raise FinalAcceptanceError("D-12 public demo URL is unavailable") from exc
    require(0 < len(raw) <= limit, "D-12 public demo response is invalid")
    return raw


def recheck_public_demo(publication: dict[str, Any]) -> str:
    youtube = publication["value"]["youtube"]
    raw = public_get(DEMO_MANIFEST, 8 * 1024 * 1024)
    require(
        hashlib.sha256(raw).hexdigest()
        == publication["value"]["media"]["public_manifest_sha256"],
        "Public beta D-12 manifest differs from reviewed publication bytes",
    )
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise FinalAcceptanceError("Public D-12 manifest is invalid") from exc
    scenarios = manifest.get("scenarios") if isinstance(manifest, dict) else None
    matches = (
        [
            item
            for item in scenarios
            if isinstance(item, dict) and item.get("slug") == SLUG
        ]
        if isinstance(scenarios, list)
        else []
    )
    require(
        len(matches) == 1
        and matches[0].get("state") == "PUBLIC"
        and matches[0].get("youtube_id") == youtube["video_id"]
        and isinstance(matches[0].get("title"), str)
        and bool(matches[0]["title"].strip()),
        "Public D-12 manifest no longer names the reviewed video",
    )
    public_get(DEMO_PAGE, 2 * 1024 * 1024)
    return matches[0]["title"]


def recheck_selected_job(
    handoff: dict[str, str],
    lineage: dict[str, Any],
    api_key: str,
) -> None:
    require(
        handoff.get("source_commit") == lineage["release"]["source_commit"]
        and handoff.get("stack_manifest_sha256")
        == lineage["release"]["stack_manifest_sha256"],
        "Private selected job differs from the signed release",
    )
    path = (
        "/v1/passport/applications/"
        + quote(handoff["application_id"], safe="")
        + "/production-status"
    )
    code, status = request_beta("GET", path, None, api_key)
    require(
        code == 200
        and isinstance(status, dict)
        and status.get("id") == handoff["source_job_id"]
        and status.get("application_id") == handoff["application_id"]
        and status.get("bureau_job_id") == handoff["bureau_job_id"]
        and status.get("organization_id") == handoff["organization_id"]
        and status.get("status") == "ACTIVE"
        and _identity_commit(api_key, "source-job", handoff["source_job_id"])
        == lineage["selected_source_job_commitment"]
        and _identity_commit(api_key, "bureau-job", handoff["bureau_job_id"])
        == lineage["selected_bureau_job_commitment"],
        "Selected passport job is no longer ACTIVE on the signed beta",
    )


def recheck_youtube(
    recorder_root: Path,
    recorder_commit: str,
    publication: dict[str, Any],
    scenario_title: str,
) -> dict[str, Any]:
    require(
        SHA.fullmatch(recorder_commit) is not None and recorder_root.is_dir(),
        "Pinned recorder checkout is unavailable",
    )
    try:
        head = subprocess.run(
            ["git", "-C", str(recorder_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(recorder_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise FinalAcceptanceError("Pinned recorder checkout is unavailable") from exc
    require(
        head == recorder_commit and not dirty,
        "Pinned recorder revision changed before final public check",
    )
    with tempfile.TemporaryDirectory(prefix="marty-passport-final-public-") as name:
        input_path = Path(name) / "publication.json"
        input_path.write_text(
            json.dumps(
                {"publication": publication["value"], "scenario_title": scenario_title}
            ),
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [
                    "node",
                    "tests/scripts/recheck-passport-publication.js",
                    str(recorder_root),
                    str(input_path),
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
            )
            observed = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise FinalAcceptanceError(
                "D-12 video is no longer public on YouTube"
            ) from exc
    youtube = publication["value"]["youtube"]
    require(
        observed.get("verified") is True
        and observed.get("video_id") == youtube["video_id"]
        and observed.get("playlist_id") == youtube["playlist_id"]
        and observed.get("page_verified") is True
        and isinstance(observed.get("checked_at_utc"), str),
        "Live D-12 YouTube or rendered page identity changed",
    )
    return observed


def compose(
    live: dict[str, Any],
    preliminary: dict[str, Any],
    soak: dict[str, Any],
    publication: dict[str, Any],
    drain: dict[str, Any],
    routes: dict[str, Any],
    source: str,
    run_id: int,
    *,
    fresh_selected: bool,
    fresh_public: dict[str, Any],
) -> dict[str, Any]:
    """Accept only one reviewed selected job across every protected stage."""
    lineage = match_preliminary_soak(live, preliminary, soak)
    recorded = match_publication(lineage, publication)
    require(
        fresh_selected is True
        and fresh_public.get("verified") is True
        and fresh_public.get("page_verified") is True
        and fresh_public.get("video_id") == recorded["evidence"]["video_id"]
        and datetime.fromisoformat(fresh_public["checked_at_utc"])
        >= datetime.fromisoformat(soak["last_observed_at_utc"]),
        "Final selected job or D-12 public video was not rechecked after soak",
    )
    require(
        lineage["release"]["source_commit"] == source
        and SHA.fullmatch(source) is not None
        and live["release"].get("signed_manifest_verified") is True
        and type(run_id) is int
        and run_id > 0,
        "Final acceptance differs from this protected main revision",
    )
    require(
        drain == EXPECTED_DRAIN and routes.get("verified") is True,
        "Final beta drain or native routing is unverified",
    )
    runtime = live.get("runtime_images")
    bureau = runtime.get("passport-beta-bureau") if isinstance(runtime, dict) else None
    require(
        isinstance(bureau, dict)
        and bureau.get("container_id") == soak["identity"].get("simulator_container_id")
        and bureau.get("oci_digest") == soak["identity"].get("simulator_oci_digest"),
        "Live simulator runtime differs from the protected soak",
    )
    prelim_probes = preliminary["value"].get("probes")
    require(
        isinstance(prelim_probes, dict)
        and all(
            isinstance(probe, dict)
            and probe.get("verified") is True
            and isinstance(probe.get("evidence"), dict)
            for probe in prelim_probes.values()
        )
        and live.get("probes", {}).get("capabilities_http", {}).get("verified") is True
        and live.get("probes", {}).get("unauthenticated_denial", {}).get("verified")
        is True,
        "Protected D-12 probes or live capability are incomplete",
    )
    probes = dict(prelim_probes)
    probes["packaged_image"] = {
        "verified": True,
        "evidence": {
            "source_commit": source,
            "stack_manifest_sha256": lineage["release"]["stack_manifest_sha256"],
            "services_oci_reference": bureau["oci_reference"],
            "simulator_oci_digest": bureau["oci_digest"],
        },
    }
    probes["legacy_drain"] = drain
    probes["production_isolation"] = {
        "verified": True,
        "evidence": {
            "production_snapshot_commitment": lineage["deployment"][
                "production_snapshot_commitment"
            ],
            "production_attachment_commitment": lineage["deployment"][
                "production_attachment_commitment"
            ],
            "protected_soak_samples": soak["sample_count"],
            "minimum_hours": soak["minimum_hours"],
            "production_unchanged": True,
        },
    }
    probes["recorded_demo"] = recorded
    probes["recorded_demo"]["evidence"]["final_live_checked_at_utc"] = fresh_public[
        "checked_at_utc"
    ]
    probes["recorded_demo"]["evidence"]["final_page_verified"] = True
    require(
        all(
            isinstance(probes.get(name), dict)
            and probes[name].get("verified") is True
            and isinstance(probes[name].get("evidence"), dict)
            for name in REQUIRED_PROBES
        ),
        "Final passport acceptance probe set is incomplete",
    )
    return {
        "schema": "marty.passport-beta-acceptance/v1",
        "status": "accepted",
        "protected_run": {"run_id": str(run_id), "workflow_commit": source},
        "accepted_at_utc": datetime.now(timezone.utc).isoformat(),
        "beta_origin": "https://beta.elevenidllc.com",
        "physical_claim": "not_claimed",
        "booklet_verified": False,
        "release": live["release"],
        "deployment": live["deployment"],
        "runtime_images": runtime,
        "probes": probes,
        "lineage": {
            "preliminary_run_id": preliminary["run_id"],
            "preliminary_artifact_sha256": preliminary["artifact_sha256"],
            "publication_run_id": publication["run_id"],
            "publication_artifact_sha256": publication["artifact_sha256"],
            "soak_samples": soak["samples"],
            "soak_first_observed_at_utc": soak["first_observed_at_utc"],
            "soak_last_observed_at_utc": soak["last_observed_at_utc"],
        },
    }


def produce(args: argparse.Namespace) -> None:
    api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY", "")
    source = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and os.environ.get("GITHUB_WORKFLOW_REF")
        == (
            "ElevenID/marty-ui/.github/workflows/"
            "passport-beta-final-acceptance.yml@refs/heads/main"
        )
        and SHA.fullmatch(source) is not None
        and run_id.isdecimal()
        and int(run_id) > 0
        and len(api_key) >= 32
        and args.artifact_dir.is_dir()
        and args.private_selected_handoff.is_file()
        and args.output.parent.is_dir()
        and not args.output.exists()
        and not args.output.is_symlink(),
        "Protected final acceptance context is invalid",
    )
    before = production_snapshot()
    attachment_before = production_attachment_sha256()
    require(production_public_site(), "Production public site is unavailable")
    try:
        live = collect_aggregate(
            args.artifact_dir, api_key=api_key, attest=verify_attestations
        )
        require(
            production_snapshot_commitment(api_key, before["sha256"])
            == live["deployment"]["production_snapshot_commitment"]
            and production_attachment_commitment(api_key, attachment_before)
            == live["deployment"]["production_attachment_commitment"],
            "Production differs from the aggregate baseline",
        )
        preliminary = read_artifact("preliminary", args.preliminary_run_id)
        soak = verify_protected(args.soak_run_ids, as_of=datetime.now(timezone.utc))
        publication = read_artifact("publication", args.publication_run_id)
        lineage = match_preliminary_soak(live, preliminary, soak)
        handoff = read_private_handoff(args.private_selected_handoff, args.artifact_dir)
        recheck_selected_job(handoff, lineage, api_key)
        scenario_title = recheck_public_demo(publication)
        fresh_public = recheck_youtube(
            args.recorder_root, args.recorder_commit, publication, scenario_title
        )
        drain = beta_legacy_drain()
        routes = beta_native_route_ownership(live["runtime_images"])
        report = compose(
            live,
            preliminary,
            soak,
            publication,
            drain,
            routes,
            source,
            int(run_id),
            fresh_selected=True,
            fresh_public=fresh_public,
        )
    finally:
        after = production_snapshot()
        attachment_after = production_attachment_sha256()
        require(production_public_site(), "Production public site is unavailable")
        assert_production_unchanged(before, after)
        require(
            attachment_after == attachment_before,
            "Production network attachments changed during acceptance",
        )
    with args.output.open("x", encoding="utf-8") as output:
        os.chmod(args.output, 0o600)
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--preliminary-run-id", required=True, type=int)
    parser.add_argument("--publication-run-id", required=True, type=int)
    parser.add_argument("--soak-run-ids", required=True, nargs="+", type=int)
    parser.add_argument("--private-selected-handoff", required=True, type=Path)
    parser.add_argument("--recorder-root", required=True, type=Path)
    parser.add_argument("--recorder-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(
        args.preliminary_run_id > 0
        and args.publication_run_id > 0
        and len(args.soak_run_ids) >= 3
        and all(run > 0 for run in args.soak_run_ids)
        and len(set(args.soak_run_ids)) == len(args.soak_run_ids),
        "Protected final acceptance run IDs are incomplete",
    )
    produce(args)


if __name__ == "__main__":
    main()
