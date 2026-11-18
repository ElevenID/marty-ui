"""Run one signed candidate installation as an explicitly unqualified trial.

Acquire original assets and the initial signed grant with the existing transport
helpers first. This controller never requests a new grant or retries a consumed
nonce. Keep its registry, guest and native journal after any uncertain outcome.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import time
import uuid

from installer_candidate_authorize import read_record
from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _read_record, _write
from installer_candidate_vm_host_preflight import ENGINEERING, preflight, consume_preflight
from installer_candidate_vm_exchange import exchange, dispatch_once
import installer_candidate_dispatch as dispatch
import installer_candidate_rendezvous as transport
import installer_release as release


def run(*, client, registry: Path, runtime_parent: Path, vm_id: str,
        installation_id: str, context: Path, authorization: Path, assets: Path,
        descriptor: Path, gh: Path, cosign: Path, ssh: Path, scp: Path,
        controller_user_id: int, clock=time.time) -> dict:
    """Consume, exchange and dispatch exactly once with fixed engineering scope."""
    release.require(os.geteuid() == 0, "root engineering controller required")
    for path in (registry, runtime_parent, context, authorization, assets,
                 descriptor, gh, cosign, ssh, scp):
        release.require(path.is_absolute(), "engineering controller path is relative")
    for value in (vm_id, installation_id):
        release.require(type(value) is str and str(uuid.UUID(value)) == value
                        and uuid.UUID(value).version == 4,
                        "engineering trial identity invalid")
    transport.controller_id(controller_user_id)
    context_raw = read_record(context)
    expected = release.decode(context_raw)
    release.exact(expected, release.CONTEXT_FIELDS, "engineering candidate context")
    first, final, consumed = (str(uuid.uuid4()) for _ in range(3))
    with ControllerLease(registry) as lease:
        record = preflight(
            lease, registry, runtime_parent, vm_id=vm_id,
            installation_id=installation_id, observation_id=first,
            final_observation_id=final, authorization=authorization,
            assets=assets, expected=expected, gh=gh, cosign=cosign,
            clock=clock, purpose=ENGINEERING)
        release.require(read_record(context) == context_raw,
                        "engineering candidate context changed")
        consume_preflight(
            lease, registry, runtime_parent, vm_id=vm_id,
            installation_id=installation_id, observation_id=first,
            consumption_observation_id=consumed, preflight_record=record,
            authorization=authorization, assets=assets, expected=expected,
            gh=gh, cosign=cosign, clock=clock, purpose=ENGINEERING)
    nonce = expected["nonce"]
    upload_output = registry / (nonce + ".engineering-upload.json")
    grant_output = registry / (nonce + ".engineering-grant")
    exchanged = exchange(
        client=client, registry=registry, authorization=authorization,
        assets=assets, expected=expected, gh=gh, cosign=cosign,
        descriptor=descriptor, upload_output=upload_output,
        grant_output=grant_output, controller_user_id=controller_user_id,
        clock=clock, purpose=ENGINEERING)
    name = nonce + ".engineering-exchange.json"
    with ControllerLease(registry) as lease:
        dispatch.registry_unchanged(lease.parent, registry)
        release.require(read_record(context) == context_raw,
                        "engineering candidate context changed")
        _write(lease.parent, name, exchanged)
        dispatch.registry_unchanged(lease.parent, registry)
        release.require(_read_record(lease.parent, name)[1] == exchanged,
                        "engineering exchange evidence changed")
    # The coordinator reauthenticates the durable intent and signed grant under
    # its own held lease before every stage. Nonzero native exit is not retried.
    result = dispatch_once(
        registry=registry, runtime_parent=runtime_parent, vm_id=vm_id,
        installation_id=installation_id, observation_id=str(uuid.uuid4()),
        final_observation_id=str(uuid.uuid4()), exchange_result=exchanged,
        authorization=authorization, assets=assets, expected=expected,
        gh=gh, cosign=cosign, grants=grant_output, ssh=ssh, scp=scp,
        clock=clock, purpose=ENGINEERING)
    release.require(result.get("purpose") == ENGINEERING
                    and result.get("qualification_eligible") is False
                    and result.get("installation_ready") is False
                    and result.get("acceptance") is False,
                    "engineering dispatch falsely claims qualification")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("registry", "runtime-parent", "context", "authorization", "assets",
                 "descriptor", "gh", "cosign", "ssh", "scp"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("vm-id", "installation-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--controller-user-id", type=int, required=True)
    args = vars(parser.parse_args(argv))
    try:
        run(**args, client=transport.Client(os.environ.get("GH_TOKEN")))
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, "Engineering trial refused, incomplete or uncertain; retain all VM and nonce evidence.\n")
    print("Engineering attempt returned zero; installation and release remain unqualified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
