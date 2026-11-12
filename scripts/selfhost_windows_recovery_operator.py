"""Fresh signed operator successor admission; never rewrites selected history."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import selfhost_windows_renewal as renewal
import selfhost_windows_renewal_native as native
import verify_installer_provenance as provenance


@contextmanager
def admitted_operator(config, assets, expected, *, gh, cosign, docker_prefix,
                      runner=provenance.command):
    """Hold a separately published stable operator through its consumer action.

    The caller supplies already pinned verifier executables. Local admission
    receipts cannot substitute for fresh release/run and signature verification.
    """
    require = renewal.require
    require(set(expected) == {'source_sha','release_tag','run_id','run_attempt','binary_sha256'})
    require(re.fullmatch(r'[0-9a-f]{40}', expected['source_sha'])
            and re.fullmatch(r'v\d+\.\d+\.\d+', expected['release_tag'])
            and re.fullmatch(r'[0-9a-f]{64}', expected['binary_sha256']))
    require(all(type(expected[key]) is int and expected[key] > 0 for key in ('run_id','run_attempt')))
    assets, gh, cosign = Path(assets), Path(gh), Path(cosign)
    require(assets.is_absolute() and gh.is_absolute() and cosign.is_absolute())
    binary = assets/'marty-deploy-linux-amd64'
    with ExitStack() as stack:
        stack.enter_context(renewal.hold_storage_namespace(assets))
        from selfhost_windows_inputs import _held_private_input
        stack.enter_context(_held_private_input(assets, directory=True))
        payload = stack.enter_context(renewal.hold_private_input(binary, max_bytes=256*1024*1024))
        require(hashlib.sha256(payload).hexdigest() == expected['binary_sha256'])
        for suffix in ('.provenance.jsonl', '.sigstore.json'):
            stack.enter_context(renewal.hold_private_input(assets/(binary.name+suffix), max_bytes=4*1024*1024))
        published = json.loads(runner([str(gh),'api',f'repos/ElevenID/marty-ui/releases/tags/{expected["release_tag"]}']))
        require(published.get('tag_name') == expected['release_tag'] and published.get('draft') is False
                and published.get('prerelease') is False and bool(published.get('published_at')))
        subjects = [asset for asset in published.get('assets',[]) if asset.get('name') == binary.name]
        require(len(subjects)==1 and subjects[0].get('size')==len(payload)
                and subjects[0].get('digest')=='sha256:'+expected['binary_sha256'])
        run = json.loads(runner([str(gh),'api',f'repos/ElevenID/marty-ui/actions/runs/{expected["run_id"]}/attempts/{expected["run_attempt"]}']))
        require(run.get('id')==expected['run_id'] and run.get('run_attempt')==expected['run_attempt']
                and run.get('head_sha')==expected['source_sha'] and run.get('status')=='completed'
                and run.get('conclusion')=='success' and run.get('path')=='.github/workflows/cd.yml')
        provenance.verify_subject(binary, assets/(binary.name+'.provenance.jsonl'), gh=gh,
            workflow='.github/workflows/cd.yml',source_sha=expected['source_sha'],
            run_id=expected['run_id'],run_attempt=expected['run_attempt'],cosign=cosign,
            signature_bundle=assets/(binary.name+'.sigstore.json'),runner=runner)
        successor = deepcopy(config)
        successor.update(binary=str(binary),binary_sha256=expected['binary_sha256'],
                         source_sha=expected['source_sha'],release_tag=expected['release_tag'])
        native.require_recovery_capability(successor, docker_prefix)
        yield successor, {'schema':'marty.windows-recovery-operator-admission/v1', **expected,
                          'historical_operator_sha256':config['binary_sha256']}
