"""Create an unsigned admission only from two authenticated installed journeys.

Caller supplies authenticated GitHub API snapshots and pinned verifier binaries.
No report synthesis, channel publication, release mutation or VM observation.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path

import installer_release as release
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive

TOOLS = {
    'cosign': ('424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa', 145688404),
    'gh': ('cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e', 41070752),
}
SUBJECTS = ['installer-inventory.json', *sorted(release.ARTIFACTS)]
SUFFIXES = ('', '.sigstore.json', '.provenance.jsonl')


def check_run(run, *, run_id, attempt, workflow, source=None, active=False):
    release.positive(run_id)
    release.positive(attempt)
    release.require(isinstance(run, dict) and isinstance(run.get('repository'), dict), 'run shape differs')
    release.require(run['repository'].get('full_name') == release.REPOSITORY
        and run.get('id') == run_id and run.get('run_attempt') == attempt
        and run.get('path') == workflow and run.get('head_branch') == 'main'
        and run.get('event') == 'workflow_dispatch'
        and run.get('status') == ('in_progress' if active else 'completed')
        and run.get('conclusion') == (None if active else 'success'), 'run identity or outcome differs')
    release.sha(run.get('head_sha'))
    if source is not None:
        release.require(run['head_sha'] == source, 'run source differs')


def snapshot(directory, names):
    release.require({p.name for p in directory.iterdir()} == set(names), 'artifact closure differs')
    result = {}
    for name in names:
        path = directory / name
        maximum = release.ARTIFACT_MAX_BYTES.get(name, 65536 if name.endswith('.json')
                                                and not name.endswith('.sigstore.json') else 1048576)
        provenance.local_file(path, private=True, maximum=maximum)
        with path.open('rb') as stream:
            result[name] = (path.stat().st_size, hashlib.file_digest(stream, 'sha256').hexdigest())
    return result


def promote(*, assets, staged, published, runs, gh, cosign, output, source_sha, release_tag,
            build_run_id, build_run_attempt, staged_run_id, staged_run_attempt,
            published_run_id, published_run_attempt, promotion_source_sha,
            promotion_run_id, promotion_run_attempt, runner=provenance.command):
    api_bytes = read_record(runs)
    api = release.decode(api_bytes)
    release.exact(api, {'build', 'staged', 'published', 'promotion'}, 'authoritative API snapshots')
    tier, _ = release.classify_release_tag(release_tag)
    workflow = '.github/workflows/nightly-release.yml' if tier == 'nightly' else '.github/workflows/cd.yml'
    check_run(api['build'], run_id=build_run_id, attempt=build_run_attempt, workflow=workflow, source=source_sha)
    check_run(api['promotion'], run_id=promotion_run_id, attempt=promotion_run_attempt,
              workflow=release.PROMOTION_WORKFLOW, source=promotion_source_sha, active=True)
    # Each phase must be independently evidenced; a single run may produce both
    # phases, but its report bytes and phase binding remain distinct.
    for phase, run_id, attempt in [('staged', staged_run_id, staged_run_attempt),
                                   ('published', published_run_id, published_run_attempt)]:
        check_run(api[phase], run_id=run_id, attempt=attempt, workflow=release.acceptance.WORKFLOW)
    for name, path in [('gh', gh), ('cosign', cosign)]:
        expected, size = TOOLS[name]
        provenance.local_file(path, private=True, maximum=size)
        with path.open('rb') as stream:
            release.require(path.stat().st_size == size and hashlib.file_digest(stream, 'sha256').hexdigest() == expected,
                            'verifier trust anchor differs')
    names = [name + suffix for name in SUBJECTS for suffix in SUFFIXES]
    before = snapshot(assets, names)
    inventory = read_record(assets / 'installer-inventory.json')
    expected = dict(source_sha=source_sha, release_tag=release_tag,
                    build_run_id=build_run_id, build_run_attempt=build_run_attempt)
    release.verify_inventory_assets(assets, **expected)
    for name in SUBJECTS:
        provenance.verify_subject(assets / name, assets / (name + '.provenance.jsonl'), gh=gh, cosign=cosign,
            signature_bundle=assets / (name + '.sigstore.json'), workflow=workflow,
            source_sha=source_sha, run_id=build_run_id, run_attempt=build_run_attempt, runner=runner)
    reports, snapshots = {}, {}
    report_names = ['installer-acceptance.json' + suffix for suffix in SUFFIXES]
    for phase, directory in [('staged', staged), ('published', published)]:
        snapshots[phase] = snapshot(directory, report_names)
        subject = directory / 'installer-acceptance.json'
        proof = directory / 'installer-acceptance.json.provenance.jsonl'
        run = api[phase]
        provenance.verify_subject(subject, proof, gh=gh, cosign=cosign,
            signature_bundle=directory / 'installer-acceptance.json.sigstore.json',
            workflow=release.acceptance.WORKFLOW, source_sha=run['head_sha'],
            run_id=run['id'], run_attempt=run['run_attempt'], runner=runner)
        reports[phase] = subject, proof, run
    result = release.admission(inventory, reports=reports, gh=gh, promotion_source_sha=promotion_source_sha,
        promotion_run_id=promotion_run_id, promotion_run_attempt=promotion_run_attempt, runner=runner)
    release.require(snapshot(assets, names) == before and read_record(runs) == api_bytes, 'promotion inputs changed')
    for phase, directory in [('staged', staged), ('published', published)]:
        release.require(snapshot(directory, report_names) == snapshots[phase], 'verified report changed')
    release.validate_admission(result)
    write_exclusive(output, release.encode(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'staged', 'published', 'runs', 'gh', 'cosign', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('source-sha', 'release-tag', 'promotion-source-sha'):
        parser.add_argument('--' + name, required=True)
    for name in ('build-run-id', 'build-run-attempt', 'staged-run-id', 'staged-run-attempt',
                 'published-run-id', 'published-run-attempt', 'promotion-run-id', 'promotion-run-attempt'):
        parser.add_argument('--' + name, required=True, type=int)
    try:
        promote(**vars(parser.parse_args(argv)))
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, 'Installer admission refused; preserve evidence. No channel or release was modified.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
