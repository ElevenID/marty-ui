"""Signed new-version channel production and non-force Git-reference publication.

Exact installed acceptance is mandatory through the immutable signed admission.
No same-version renewal, automatic conflict recovery, tag overwrite or force push.
Publication conflicts retain immutable metadata and evidence for reviewed recovery.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import os
from pathlib import Path
import time

import installer_release as r
import installer_promote as promotion
import installer_publish_admission as publication
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive

REPO = publication.REPO
REF = REPO + '/git/ref/heads/installer-channel'
CONTEXT_SCHEMA = 'elevenid.installer-channel-publication-context/v1'


def pointer(raw, channel):
    value = r.decode(raw)
    r.exact(value, {'schema', 'repository', 'channel', 'generation', 'record_sha256'}, 'channel pointer')
    r.require(value['schema'] == 'elevenid.installer-channel-pointer/v1'
              and value['repository'] == r.REPOSITORY and value['channel'] == channel, 'pointer identity differs')
    r.positive(value['generation']); r.sha(value['record_sha256'], 64)
    return value


def branch(client):
    ref = client.request('GET', REF, missing=True)
    if ref is None:
        return None, None, {}
    r.require(isinstance(ref, dict) and ref.get('ref') == 'refs/heads/installer-channel'
              and isinstance(ref.get('object'), dict) and ref['object'].get('type') == 'commit', 'channel ref differs')
    head = ref['object']['sha']; r.sha(head)
    commit = client.request('GET', REPO + '/git/commits/' + head)
    r.require(commit.get('sha') == head and isinstance(commit.get('tree'), dict), 'channel commit differs')
    tree_sha = commit['tree']['sha']; r.sha(tree_sha)
    return head, tree_sha, tree_files(client, tree_sha)


def tree_files(client, tree_sha):
    tree = client.request('GET', REPO + '/git/trees/' + tree_sha + '?recursive=1')
    r.require(tree.get('sha') == tree_sha and tree.get('truncated') is False and isinstance(tree.get('tree'), list)
              and len(tree['tree']) <= 2, 'channel tree closure differs')
    files = {}
    for entry in tree['tree']:
        name = entry.get('path')
        r.require(name in {'nightly.json', 'stable.json'} and name not in files
                  and entry.get('mode') == '100644' and entry.get('type') == 'blob', 'channel tree entry differs')
        sha = entry['sha']; r.sha(sha)
        blob = client.request('GET', REPO + '/git/blobs/' + sha)
        r.require(blob.get('sha') == sha and blob.get('encoding') == 'base64'
                  and type(blob.get('size')) is int and 0 < blob['size'] <= 65536, 'channel blob differs')
        raw = base64.b64decode(blob['content'].replace('\n', ''), validate=True)
        r.require(len(raw) == blob['size'] and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == sha,
                  'channel blob content differs')
        pointer(raw, name[:-5])
        files[name] = raw
    return files


def tools(gh, cosign):
    for name, path in [('gh', gh), ('cosign', cosign)]:
        digest, size = promotion.TOOLS[name]
        provenance.local_file(path, private=True, maximum=size)
        with path.open('rb') as stream:
            r.require(path.stat().st_size == size and hashlib.file_digest(stream, 'sha256').hexdigest() == digest,
                      'channel verifier differs')


def verify(directory, stem, record, *, client, gh, cosign, runner):
    for key in ('promotion_source_sha',): r.sha(record.get(key))
    for key in ('promotion_run_id', 'promotion_run_attempt'): r.positive(record.get(key))
    api = client.request('GET', REPO + '/actions/runs/' + str(record['promotion_run_id']))
    promotion.check_run(api, run_id=record['promotion_run_id'], attempt=record['promotion_run_attempt'],
                        workflow=r.PROMOTION_WORKFLOW, source=record['promotion_source_sha'])
    provenance.verify_subject(directory / stem, directory / (stem + '.provenance.jsonl'), gh=gh, cosign=cosign,
        signature_bundle=directory / (stem + '.sigstore.json'), workflow=r.PROMOTION_WORKFLOW,
        source_sha=record['promotion_source_sha'], run_id=record['promotion_run_id'],
        run_attempt=record['promotion_run_attempt'], runner=runner)


def acquire(client, tag, stem, destination):
    remote = client.request('GET', REPO + '/releases/tags/' + tag)
    r.require(isinstance(remote, dict) and remote.get('tag_name') == tag and remote.get('draft') is False
              and remote.get('immutable') is True and remote.get('prerelease') is True, 'immutable metadata unavailable')
    r.positive(remote.get('id'))
    assets = client.request('GET', f"{REPO}/releases/{remote['id']}/assets?per_page=100")
    names = {stem + suffix for suffix in promotion.SUFFIXES}
    r.require(isinstance(assets, list) and len(assets) == 3
              and {a.get('name') for a in assets if isinstance(a, dict)} == names, 'metadata closure differs')
    destination.mkdir(mode=0o700)
    for asset in assets:
        name = asset['name']; r.positive(asset.get('id'))
        r.require(asset.get('state') == 'uploaded' and type(asset.get('size')) is int
                  and 0 < asset['size'] <= (65536 if name == stem else 1048576), 'metadata asset size differs')
        raw = client.request('GET', f"{REPO}/releases/assets/{asset['id']}", binary=True)
        r.require(len(raw) == asset['size'] and asset.get('digest') == 'sha256:' + r.digest(raw), 'metadata bytes differ')
        write_exclusive(destination / name, raw)
    again = client.request('GET', REPO + '/releases/tags/' + tag)
    r.require(again.get('id') == remote['id'] and again.get('immutable') is True
              and again.get('draft') is False, 'metadata release changed')
    raw = read_record(destination / stem)
    record = r.decode(raw)
    r.require(remote.get('target_commitish') == record.get('promotion_source_sha'), 'metadata source differs')
    check_tag(client, tag, record['promotion_source_sha'])
    return raw, record


def admission(client, work, source, tag, gh, cosign, runner):
    raw, record = acquire(client, 'installer-admission-' + tag, 'installer-admission.json', work / 'admission')
    verify(work / 'admission', 'installer-admission.json', record, client=client, gh=gh, cosign=cosign, runner=runner)
    r.validate_admission(record)
    r.require(record['source_sha'] == source and record['release_tag'] == tag, 'admitted version differs')
    return raw


def prior(client, work, channel, files, gh, cosign, runner, now):
    raw_pointer = files.get(channel + '.json')
    if raw_pointer is None:
        return None
    located = pointer(raw_pointer, channel)
    raw, record = acquire(client, f"installer-channel-{channel}-{located['generation']}",
                          'installer-channel.json', work / 'previous')
    verify(work / 'previous', 'installer-channel.json', record, client=client, gh=gh, cosign=cosign, runner=runner)
    r.validate_channel(record, now=now, allow_expired=True)
    r.require(record['channel'] == channel and record['generation'] == located['generation']
              and r.digest(raw) == located['record_sha256'], 'previous channel binding differs')
    return raw


def produce(*, client, work, output, gh, cosign, source_sha, release_tag, promotion_source_sha,
            promotion_run_id, promotion_run_attempt, clock=time.time, runner=provenance.command):
    tools(gh, cosign)
    current = client.request('GET', REPO + '/actions/runs/' + str(promotion_run_id))
    promotion.check_run(current, run_id=promotion_run_id, attempt=promotion_run_attempt,
                        workflow=r.PROMOTION_WORKFLOW, source=promotion_source_sha, active=True)
    channel, _ = r.classify_release_tag(release_tag)
    head, _, files = branch(client)
    accepted = admission(client, work, source_sha, release_tag, gh, cosign, runner)
    previous = prior(client, work, channel, files, gh, cosign, runner, int(clock()))
    record = r.channel(accepted, channel_name=channel, previous_bytes=previous,
        promotion_source_sha=promotion_source_sha, promotion_run_id=promotion_run_id,
        promotion_run_attempt=promotion_run_attempt, now=int(clock()))
    observed_head, _, observed_files = branch(client)
    r.require(observed_head == head and observed_files == files, 'channel changed during production')
    raw = r.encode(record)
    context = dict(schema=CONTEXT_SCHEMA, repository=r.REPOSITORY, channel=channel,
        record_sha256=r.digest(raw), expected_head=head,
        previous_pointer_sha256=None if channel + '.json' not in files else r.digest(files[channel + '.json']),
        promotion_source_sha=promotion_source_sha, promotion_run_id=promotion_run_id,
        promotion_run_attempt=promotion_run_attempt)
    write_exclusive(output / 'installer-channel.json', raw)
    write_exclusive(output / 'installer-channel-context.json', r.encode(context))
    return record


def validate_context(context, record, raw):
    r.exact(context, {'schema', 'repository', 'channel', 'record_sha256', 'expected_head',
        'previous_pointer_sha256', 'promotion_source_sha', 'promotion_run_id', 'promotion_run_attempt'}, 'channel publication context')
    r.require(context['schema'] == CONTEXT_SCHEMA and context['repository'] == r.REPOSITORY
              and context['record_sha256'] == r.digest(raw)
              and all(context[k] == record[k] for k in ('channel', 'promotion_source_sha', 'promotion_run_id', 'promotion_run_attempt')),
              'channel publication context differs')
    if context['expected_head'] is not None: r.sha(context['expected_head'])
    if context['previous_pointer_sha256'] is not None: r.sha(context['previous_pointer_sha256'], 64)


def check_base(client, context):
    head, tree, files = branch(client)
    current = files.get(context['channel'] + '.json')
    r.require(head == context['expected_head'] and (None if current is None else r.digest(current))
              == context['previous_pointer_sha256'], 'channel compare-and-swap base changed')
    return head, tree, files


def branch_policy(client):
    # Effective rules are public repository metadata. Do not change policy here.
    rules = client.request('GET', REPO + '/rules/branches/installer-channel')
    r.require(isinstance(rules, list) and len(rules) <= 100
              and {'deletion', 'non_fast_forward'} <= {v.get('type') for v in rules if isinstance(v, dict)},
              'installer-channel deletion/non-fast-forward protection is required')


def publish_generation(client, record, files, evidence):
    tag = f"installer-channel-{record['channel']}-{record['generation']}"
    source = record['promotion_source_sha']
    endpoint = REPO + '/releases/tags/' + tag
    existing = client.request('GET', endpoint, missing=True)
    if existing is not None:
        publication.release_identity(existing, tag, source, draft=False)
        check_generation_bytes(client, existing['id'], files)
        check_tag(client, tag, source)
        return existing['id']
    r.require(client.request('GET', REPO + '/git/ref/tags/' + tag, missing=True) is None, 'channel metadata tag exists')
    r.require(client.request('GET', REPO + '/immutable-releases', policy=True).get('enabled') is True,
              'immutable releases are not enabled')
    write_exclusive(evidence / 'channel-generation-pending.json', r.encode(dict(tag=tag,
        assets={k: r.digest(v) for k,v in files.items()})))
    remote = client.request('POST', REPO + '/releases', dict(tag_name=tag, target_commitish=source,
        name=tag, body='Verified installer channel metadata; pointer publication is separate.',
        draft=True, prerelease=True, make_latest='false'))
    publication.release_identity(remote, tag, source, draft=True)
    ident = remote['id']
    write_exclusive(evidence / 'channel-generation-created.json', r.encode(dict(release_id=ident, tag=tag)))
    for name, raw in files.items():
        publication.release_identity(client.request('GET', f'{REPO}/releases/{ident}'), tag, source, draft=True)
        client.request('POST', f'{REPO}/releases/{ident}/assets?name={name}', raw, upload=True)
    check_generation_bytes(client, ident, files)
    r.require(client.request('GET', REPO + '/immutable-releases', policy=True).get('enabled') is True,
              'immutability policy changed')
    publication.release_identity(client.request('GET', f'{REPO}/releases/{ident}'), tag, source, draft=True)
    tag_ref = client.request('GET', REPO+'/git/ref/tags/'+tag, missing=True)
    r.require(tag_ref is None or isinstance(tag_ref.get('object'),dict)
              and tag_ref['object'].get('type')=='commit' and tag_ref['object'].get('sha')==source,
              'generation tag changed')
    write_exclusive(evidence / 'channel-generation-publish-intent.json', r.encode(dict(release_id=ident, tag=tag)))
    client.request('PATCH', f'{REPO}/releases/{ident}', dict(draft=False, make_latest='false'))
    publication.release_identity(client.request('GET', f'{REPO}/releases/{ident}'), tag, source, draft=False)
    check_generation_bytes(client, ident, files)
    check_tag(client, tag, source)
    return ident


def check_tag(client, tag, source):
    ref=client.request('GET',REPO+'/git/ref/tags/'+tag)
    r.require(isinstance(ref,dict) and isinstance(ref.get('object'),dict)
              and ref['object'].get('type')=='commit' and ref['object'].get('sha')==source,
              'immutable generation tag differs')


def check_generation_bytes(client, ident, files):
    assets = client.request('GET', f'{REPO}/releases/{ident}/assets?per_page=100')
    r.require(isinstance(assets, list) and len(assets) == 3
              and {a.get('name') for a in assets if isinstance(a, dict)} == set(files), 'generation closure differs')
    for asset in assets:
        r.positive(asset.get('id')); raw = files[asset['name']]
        r.require(asset.get('state') == 'uploaded' and asset.get('size') == len(raw)
                  and asset.get('digest') == 'sha256:' + r.digest(raw), 'generation asset differs')
        r.require(client.request('GET', f"{REPO}/releases/assets/{asset['id']}", binary=True) == raw,
                  'generation readback differs')


def publish(*, client, work, assets, evidence, gh, cosign, source_sha, release_tag,
            promotion_source_sha, promotion_run_id, promotion_run_attempt, clock=time.time, runner=provenance.command):
    tools(gh, cosign)
    names = [stem + suffix for stem in ('installer-channel.json','installer-channel-context.json') for suffix in promotion.SUFFIXES]
    before = promotion.snapshot(assets, names)
    raw = read_record(assets / 'installer-channel.json'); record = r.decode(raw)
    context = r.decode(read_record(assets / 'installer-channel-context.json'))
    r.validate_channel(record, now=int(clock())); validate_context(context, record, raw)
    r.require(all(record[k] == v for k,v in dict(source_sha=source_sha, release_tag=release_tag,
        promotion_source_sha=promotion_source_sha, promotion_run_id=promotion_run_id,
        promotion_run_attempt=promotion_run_attempt).items()), 'selected channel invocation differs')
    for stem in ('installer-channel.json','installer-channel-context.json'):
        verify(assets, stem, record, client=client, gh=gh, cosign=cosign, runner=runner)
    branch_policy(client)
    head, tree, old_files = check_base(client, context)
    accepted = admission(client, work, source_sha, release_tag, gh, cosign, runner)
    previous = prior(client, work, record['channel'], old_files, gh, cosign, runner, int(clock()))
    # Recompute exactly: same-version refresh/rollback and predecessor substitution
    # cannot enter through a separately signed publication context.
    expected = r.channel(accepted, channel_name=record['channel'], previous_bytes=previous,
        promotion_source_sha=promotion_source_sha, promotion_run_id=promotion_run_id,
        promotion_run_attempt=promotion_run_attempt, now=record['issued_at'],
        lifetime=record['expires_at']-record['issued_at'])
    r.require(record == expected and promotion.snapshot(assets, names) == before, 'channel production differs')
    files = {name:(assets/name).read_bytes() for name in names if not name.startswith('installer-channel-context')}
    r.require(all((len(v),r.digest(v)) == before[k] for k,v in files.items()), 'generation bytes changed')
    write_exclusive(evidence / 'channel-publication-pending.json', r.encode(dict(context=context,
        channel_sha256=r.digest(raw), expected_head=head)))
    release_id = publish_generation(client, record, files, evidence)
    check_base(client, context)
    r.validate_channel(record, now=int(clock()))
    value = r.encode(dict(schema='elevenid.installer-channel-pointer/v1', repository=r.REPOSITORY,
        channel=record['channel'], generation=record['generation'], record_sha256=r.digest(raw)))
    change = dict(path=record['channel']+'.json', mode='100644', type='blob', content=value.decode())
    body = dict(tree=[change])
    if tree is not None: body['base_tree'] = tree
    new_tree = client.request('POST', REPO+'/git/trees', body); r.sha(new_tree.get('sha'))
    wanted = dict(old_files); wanted[record['channel']+'.json'] = value
    r.require(tree_files(client,new_tree['sha'])==wanted,'CAS tree changed unrelated pointer')
    parents = [] if head is None else [head]
    commit = client.request('POST', REPO+'/git/commits', dict(message='Publish verified installer channel generation',
        tree=new_tree['sha'], parents=parents)); r.sha(commit.get('sha'))
    # Re-read Git objects before reference mutation. Exactly one prior parent (or
    # an initial root commit) makes a non-force update a compare-and-swap.
    inspected = client.request('GET', REPO+'/git/commits/'+commit['sha'])
    r.require(inspected.get('sha') == commit['sha'] and inspected.get('tree',{}).get('sha') == new_tree['sha']
              and [p.get('sha') for p in inspected.get('parents',[])] == parents, 'CAS commit differs')
    check_base(client, context)
    r.validate_channel(record, now=int(clock()))
    branch_policy(client)
    write_exclusive(evidence/'channel-cas-intent.json', r.encode(dict(expected_head=head, commit=commit['sha'],
        pointer_sha256=r.digest(value), immutable_release_id=release_id)))
    if head is None:
        client.request('POST', REPO+'/git/refs', dict(ref='refs/heads/installer-channel', sha=commit['sha']))
    else:
        client.request('PATCH', REPO+'/git/refs/heads/installer-channel', dict(sha=commit['sha'], force=False))
    final_head, _, final_files = branch(client)
    r.require(final_head == commit['sha'] and final_files == wanted, 'channel CAS readback differs')
    result = dict(commit=final_head, immutable_release_id=release_id, channel=record['channel'],
                  generation=record['generation'], pointer_sha256=r.digest(value))
    write_exclusive(evidence/'channel-publication-result.json', r.encode(result))
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('produce','publish'))
    for name in ('work','gh','cosign'): parser.add_argument('--'+name,type=Path,required=True)
    for name in ('assets','evidence','output'): parser.add_argument('--'+name,type=Path)
    for name in ('source-sha','release-tag','promotion-source-sha'): parser.add_argument('--'+name,required=True)
    for name in ('promotion-run-id','promotion-run-attempt'): parser.add_argument('--'+name,type=int,required=True)
    args=vars(parser.parse_args(argv)); operation=args.pop('operation')
    try:
        token=os.environ.get('GH_TOKEN')
        if operation=='produce':
            r.require(args.pop('assets') is None and args.pop('evidence') is None and args['output'] is not None,'producer options differ')
            # Read-only producer never uses the policy endpoint.
            produce(**args,client=publication.Client(token,token))
        else:
            r.require(args.pop('output') is None and args['assets'] is not None and args['evidence'] is not None,'publisher options differ')
            publish(**args,client=publication.Client(token,os.environ.get('INSTALLER_REPOSITORY_POLICY_TOKEN')))
    except (ValueError,OSError,TypeError,KeyError):
        parser.exit(1,'Channel production/publication refused or uncertain; preserve metadata and CAS evidence. No force or automatic retry.\n')
    return 0


if __name__=='__main__': raise SystemExit(main())
