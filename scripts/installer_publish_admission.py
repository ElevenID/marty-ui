"""Publish an authenticated admission triplet to its own immutable GitHub release.

Requires protected-environment INSTALLER_REPOSITORY_POLICY_TOKEN with repository
Administration:read solely for the fixed immutability policy GET. GH_TOKEN needs
Contents:write for the exact derived metadata release. Never changes policy,
original version releases, channels or tags by force. Uncertain drafts are retained
and refused on retry; no partial-release adoption or asset replacement.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

import installer_release as r
import installer_promote as promotion
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive

REPO = '/repos/ElevenID/marty-ui'
NAMES = tuple('installer-admission.json' + suffix for suffix in promotion.SUFFIXES)
MAX_BYTES = 1048576


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, token, policy_token):
        for value in (token, policy_token):
            r.require(isinstance(value, str) and value and all(32 < ord(c) < 127 for c in value),
                      'publication credentials unavailable')
        self.token, self.policy_token = token, policy_token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, *, policy=False, missing=False, upload=False, binary=False):
        r.require(path.startswith(REPO + '/') and not any(c in path for c in '\r\n#'), 'API path invalid')
        if policy:
            r.require(method == 'GET' and path == REPO + '/immutable-releases' and body is None,
                      'policy credential scope differs')
        if upload:
            r.require(method == 'POST' and isinstance(body, bytes) and len(body) <= MAX_BYTES,
                      'invalid metadata upload')
        host = 'uploads.github.com' if upload else 'api.github.com'
        data = body if upload else (None if body is None else r.encode(body))
        token = self.policy_token if policy else self.token
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
                   'Content-Type': 'application/octet-stream' if upload else 'application/json',
                   'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'marty-installer-admission'}
        request = urllib.request.Request('https://' + host + path, data=data, method=method, headers=headers)
        try:
            return self.read(request, binary=binary)
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            if binary and error.code in (301, 302, 303, 307, 308):
                target = urllib.parse.urlsplit(error.headers.get('Location', ''))
                r.require(target.scheme == 'https' and target.hostname == 'release-assets.githubusercontent.com'
                          and target.port in (None, 443) and not target.username and not target.password
                          and not target.fragment, 'asset redirect differs')
                # No bearer, cookies, proxy or second redirect on public delivery.
                try:
                    return self.read(urllib.request.Request(target.geturl()), binary=True)
                except (urllib.error.HTTPError, OSError):
                    raise ValueError('metadata download failed') from None
            raise ValueError('metadata API request failed') from None
        except OSError:
            raise ValueError('metadata API request failed') from None

    def read(self, request, *, binary):
        with self.opener.open(request, timeout=20) as response:
            deadline, raw = time.monotonic() + 60, bytearray()
            while True:
                r.require(time.monotonic() < deadline, 'metadata response timeout')
                chunk = response.read1(min(8192, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                r.require(len(raw) <= MAX_BYTES, 'metadata response exceeds bound')
        if binary:
            return bytes(raw)
        def pairs(items):
            result = {}
            for key, value in items:
                r.require(key not in result, 'duplicate metadata API field')
                result[key] = value
            return result
        return json.loads(bytes(raw), object_pairs_hook=pairs)


def release_identity(remote, tag, source, *, draft):
    r.require(isinstance(remote, dict), 'metadata release missing')
    r.positive(remote.get('id'))
    r.require(remote.get('tag_name') == tag and remote.get('target_commitish') == source
              and remote.get('draft') is draft and remote.get('prerelease') is True,
              'metadata release identity differs')
    if not draft:
        r.require(remote.get('immutable') is True, 'metadata release is not immutable')


def remote_bytes(client, release_id, expected):
    assets = client.request('GET', f'{REPO}/releases/{release_id}/assets?per_page=100')
    r.require(isinstance(assets, list) and len(assets) == 3
              and {a.get('name') for a in assets if isinstance(a, dict)} == set(NAMES), 'metadata asset closure differs')
    for asset in assets:
        name = asset['name']
        r.positive(asset.get('id'))
        r.require(asset.get('state') == 'uploaded' and asset.get('size') == len(expected[name])
                  and asset.get('digest') == 'sha256:' + r.digest(expected[name]), 'metadata asset differs')
        raw = client.request('GET', f"{REPO}/releases/assets/{asset['id']}", binary=True)
        r.require(raw == expected[name], 'downloaded metadata bytes differ')


def publish(*, assets, run_record, gh, cosign, evidence, source_sha, release_tag,
            promotion_source_sha, promotion_run_id, promotion_run_attempt,
            client, runner=provenance.command):
    api_bytes = read_record(run_record)
    api = r.decode(api_bytes)
    promotion.check_run(api, run_id=promotion_run_id, attempt=promotion_run_attempt,
                        workflow=r.PROMOTION_WORKFLOW, source=promotion_source_sha)
    r.sha(source_sha)
    r.classify_release_tag(release_tag)
    before = promotion.snapshot(assets, NAMES)
    for name, path in [('gh', gh), ('cosign', cosign)]:
        digest, size = promotion.TOOLS[name]
        provenance.local_file(path, private=True, maximum=size)
        import hashlib
        with path.open('rb') as stream:
            r.require(path.stat().st_size == size and hashlib.file_digest(stream, 'sha256').hexdigest() == digest,
                      'publication verifier differs')
    subject = assets / NAMES[0]
    provenance.verify_subject(subject, assets / NAMES[2], gh=gh, cosign=cosign,
        signature_bundle=assets / NAMES[1], workflow=r.PROMOTION_WORKFLOW, source_sha=promotion_source_sha,
        run_id=promotion_run_id, run_attempt=promotion_run_attempt, runner=runner)
    accepted = r.decode(read_record(subject))
    r.validate_admission(accepted)
    r.require(all(accepted[key] == value for key, value in dict(source_sha=source_sha, release_tag=release_tag,
        promotion_source_sha=promotion_source_sha, promotion_run_id=promotion_run_id,
        promotion_run_attempt=promotion_run_attempt).items()), 'admission differs from selected candidate')
    r.require(promotion.snapshot(assets, NAMES) == before and read_record(run_record) == api_bytes,
              'verified publication inputs changed')
    files = {name: (assets / name).read_bytes() for name in NAMES}
    r.require(all((len(files[name]), r.digest(files[name])) == before[name] for name in NAMES), 'metadata changed')
    tag = 'installer-admission-' + release_tag
    endpoint = REPO + '/releases/tags/' + tag
    current = client.request('GET', endpoint, missing=True)
    if current is not None:
        release_identity(current, tag, promotion_source_sha, draft=False)
        remote_bytes(client, current['id'], files)
        again = client.request('GET', endpoint)
        release_identity(again, tag, promotion_source_sha, draft=False)
        r.require(again['id'] == current['id'], 'metadata release replaced')
        tag_ref = client.request('GET', REPO + '/git/ref/tags/' + tag)
        r.require(isinstance(tag_ref, dict) and isinstance(tag_ref.get('object'), dict)
                  and tag_ref['object'].get('type') == 'commit' and tag_ref['object'].get('sha') == promotion_source_sha,
                  'existing metadata tag differs')
        write_exclusive(evidence / 'admission-publication-existing.json', r.encode(dict(
            schema='elevenid.installer-admission-existing-verification/v1', release_id=current['id'], tag=tag,
            commit=promotion_source_sha, immutable=True, channel_updated=False,
            assets={name: r.digest(raw) for name, raw in files.items()})))
        return dict(release_id=current['id'], existing=True, immutable=True, channel_updated=False)
    # Do not let a pre-existing tag silently select a different commit.
    r.require(client.request('GET', REPO + '/git/ref/tags/' + tag, missing=True) is None,
              'metadata tag already exists without its immutable release')
    policy = client.request('GET', REPO + '/immutable-releases', policy=True)
    r.require(isinstance(policy, dict) and policy.get('enabled') is True, 'immutable releases are not enabled')
    write_exclusive(evidence / 'admission-publication-pending.json', r.encode(dict(
        schema='elevenid.installer-admission-publication/v1', tag=tag, promotion_source_sha=promotion_source_sha,
        promotion_run_id=promotion_run_id, promotion_run_attempt=promotion_run_attempt,
        assets={name: r.digest(raw) for name, raw in files.items()}, channel_updated=False)))
    remote = client.request('POST', REPO + '/releases', dict(tag_name=tag, target_commitish=promotion_source_sha,
        name='Installer admission ' + release_tag, body='Verified installed acceptance metadata; original release unchanged.',
        draft=True, prerelease=True, make_latest='false'))
    release_identity(remote, tag, promotion_source_sha, draft=True)
    release_id = remote['id']
    write_exclusive(evidence / 'admission-publication-created.json', r.encode(dict(release_id=release_id, tag=tag)))
    for name, raw in files.items():
        release_identity(client.request('GET', f'{REPO}/releases/{release_id}'), tag, promotion_source_sha, draft=True)
        client.request('POST', f'{REPO}/releases/{release_id}/assets?name={name}', raw, upload=True)
    remote_bytes(client, release_id, files)
    r.require(client.request('GET', REPO + '/immutable-releases', policy=True).get('enabled') is True,
              'immutability policy changed')
    release_identity(client.request('GET', f'{REPO}/releases/{release_id}'), tag, promotion_source_sha, draft=True)
    tag_ref = client.request('GET', REPO + '/git/ref/tags/' + tag, missing=True)
    r.require(tag_ref is None or isinstance(tag_ref.get('object'), dict)
              and tag_ref['object'].get('type') == 'commit' and tag_ref['object'].get('sha') == promotion_source_sha,
              'metadata tag raced with publication')
    write_exclusive(evidence / 'admission-publication-publish-intent.json', r.encode(dict(release_id=release_id, tag=tag)))
    client.request('PATCH', f'{REPO}/releases/{release_id}', dict(draft=False, make_latest='false'))
    final = client.request('GET', f'{REPO}/releases/{release_id}')
    release_identity(final, tag, promotion_source_sha, draft=False)
    tag_ref = client.request('GET', REPO + '/git/ref/tags/' + tag)
    r.require(isinstance(tag_ref, dict) and isinstance(tag_ref.get('object'), dict)
              and tag_ref['object'].get('type') == 'commit' and tag_ref['object'].get('sha') == promotion_source_sha,
              'published metadata tag differs')
    remote_bytes(client, release_id, files)
    result = dict(release_id=release_id, existing=False, immutable=True, channel_updated=False)
    write_exclusive(evidence / 'admission-publication-result.json', r.encode(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'run-record', 'gh', 'cosign', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'release-tag', 'promotion-source-sha'):
        parser.add_argument('--' + name, required=True)
    for name in ('promotion-run-id', 'promotion-run-attempt'):
        parser.add_argument('--' + name, type=int, required=True)
    try:
        publish(**vars(parser.parse_args(argv)), client=Client(os.environ.get('GH_TOKEN'),
            os.environ.get('INSTALLER_REPOSITORY_POLICY_TOKEN')))
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, 'Admission publication refused or uncertain; retain draft and publication evidence. No channel update.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
