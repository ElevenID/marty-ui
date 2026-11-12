#!/usr/bin/env python3
"""Derive the existing Canvas edge from its hash-bound canonical Compose model.

Default validates files and prints a plan. --render runs only Compose config;
it never inspects an engine, creates a service, changes a route or grants TLS
qualification. The operator supplies a reviewed nginx config and public CA PEM.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess

PROJECT = 'canvas-oss-portability'


def require(value, code):
    if not value:
        raise RuntimeError(code)


def bound(reference, maximum=1024 * 1024):
    require(isinstance(reference, dict) and isinstance(reference.get('path'), str)
            and isinstance(reference.get('sha256'), str)
            and re.fullmatch('[0-9a-f]{64}', reference.get('sha256', '')), 'HASH_BOUND_FILE_REQUIRED')
    require(set(reference) <= {'path', 'sha256', 'bytes', 'gitBlob'}, 'NON_SECRET_REF_METADATA_ONLY')
    if 'gitBlob' in reference:
        require(isinstance(reference['gitBlob'], str) and re.fullmatch('[0-9a-f]{40}', reference['gitBlob']), 'GIT_BLOB_REFERENCE_REQUIRED')
    path = Path(reference['path'])
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, 'REGULAR_BOUNDED_FILE_REQUIRED')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == reference['sha256'], 'SOURCE_FILE_CHANGED')
    if 'bytes' in reference:
        require(type(reference['bytes']) is int and len(data) == reference['bytes'], 'SOURCE_BYTE_COUNT_CHANGED')
    return path


def public_ca(path):
    data = path.read_bytes()
    require(len(data) <= 65536, 'PUBLIC_CA_BOUND_EXCEEDED')
    text = data.decode('ascii')
    pattern = r'-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----'
    blocks = re.findall(pattern, text)
    require(blocks and not re.sub(pattern, '', text).strip(), 'PUBLIC_CA_CERTIFICATES_ONLY')
    for body in blocks:
        try:
            der = base64.b64decode(''.join(body.split()), validate=True)
        except binascii.Error as error:
            raise RuntimeError('PUBLIC_CA_CERTIFICATES_ONLY') from error
        require(der.startswith(b'\x30'), 'PUBLIC_CA_CERTIFICATES_ONLY')


def render(compose, project, source):
    result = subprocess.run([str(compose), '--project-name', project, '--file', str(source),
                             'config', '--no-interpolate', '--no-path-resolution', '--format', 'json', 'canvas-edge'],
                            capture_output=True, timeout=60, check=True)
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 16384, 'RENDER_OUTPUT_BOUND')
    return json.loads(result.stdout), result.stderr.decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--render', action='store_true')
    args = parser.parse_args()
    input_bytes = args.inputs.read_bytes()
    require(len(input_bytes) <= 65536, 'INPUT_BOUND_EXCEEDED')
    plan = json.loads(input_bytes)
    require(isinstance(plan, dict) and set(plan) <= {'sourceRevision', 'project', 'canonical', 'lock', 'compose', 'relayConfig', 'publicCa'}
            and {'project', 'canonical', 'lock', 'compose', 'relayConfig', 'publicCa'} <= set(plan), 'CLOSED_NON_SECRET_INPUTS_REQUIRED')
    require(plan.get('project') == PROJECT, 'EXACT_EXISTING_PROJECT_REQUIRED')
    if 'sourceRevision' in plan:
        require(isinstance(plan['sourceRevision'], str) and re.fullmatch('[0-9a-f]{40}', plan['sourceRevision']), 'SOURCE_REVISION_REQUIRED')
    canonical = bound(plan['canonical'])
    lock = json.loads(bound(plan['lock']).read_bytes())
    compose = bound(plan['compose'], 128 * 1024 * 1024)
    relay = bound(plan['relayConfig'])
    ca = bound(plan['publicCa'], 65536)
    public_ca(ca)
    output = args.output.resolve()
    evidence_path = Path(str(output) + '.source-check.json')
    if not args.render:
        print(json.dumps({'state': 'SOURCE_ONLY_EDGE_DERIVATION_PLAN', 'engineCalls': 0,
                          'output': str(output), 'publicCaSha256': plan['publicCa']['sha256']}))
        return
    require(output.parent.is_dir() and not output.exists() and not evidence_path.exists(), 'FRESH_OUTPUT_FILES_REQUIRED')
    model, warning = render(compose, PROJECT, canonical)
    edge = copy.deepcopy(model['services']['canvas-edge'])
    require(edge['container_name'] == 'marty-canvas-oss-edge', 'EXACT_EXISTING_EDGE_REQUIRED')
    require(set(edge['networks']) == {'beta-tunnel', 'canvas-oss-private'}
            and edge['networks']['beta-tunnel']['aliases'] == ['canvas-real'], 'CANONICAL_EDGE_NETWORK_CHANGED')
    edge['image'] = lock['runtime_dependencies']['edge']
    require(re.fullmatch(r'nginx:1\.27-alpine@sha256:[0-9a-f]{64}', edge['image']), 'LOCKED_EDGE_IMAGE_REQUIRED')
    edge.pop('depends_on', None)
    edge['mem_limit'] = 64 * 1024**2
    edge['volumes'] = [
        {'type': 'bind', 'source': str(relay.resolve()), 'target': '/etc/nginx/conf.d/default.conf',
         'read_only': True, 'bind': {'create_host_path': False}},
        {'type': 'bind', 'source': str(ca.resolve()), 'target': '/etc/nginx/canvas-remote-ca.pem',
         'read_only': True, 'bind': {'create_host_path': False}},
    ]
    networks = {name: {'name': model['networks'][name]['name'], 'external': True} for name in edge['networks']}
    result = {'name': PROJECT, 'services': {'canvas-edge': edge}, 'networks': networks}
    with output.open('xb') as stream:
        stream.write((json.dumps(result, indent=2) + '\n').encode())
    checked, _ = render(compose, PROJECT, output)
    require(set(checked['services']) == {'canvas-edge'}, 'EDGE_ONLY_MODEL_REQUIRED')
    require(not any(key in checked for key in ('secrets', 'volumes')), 'UNRELATED_FIXTURE_MODEL_REFUSED')
    require(all(network['external'] is True for network in checked['networks'].values()), 'EXISTING_NETWORKS_ONLY')
    for key in ('canonical', 'lock', 'relayConfig', 'publicCa'):
        bound(plan[key])
    bound(plan['compose'], 128 * 1024 * 1024)
    require(args.inputs.read_bytes() == input_bytes, 'INPUT_FILE_CHANGED')
    evidence = {'state': 'EDGE_ONLY_CANONICAL_DERIVATION_PASS', 'engineCalls': 0, 'inspectOrMutationCalls': 0,
                'inputs': {'path': str(args.inputs.resolve()), 'sha256': hashlib.sha256(input_bytes).hexdigest()},
                'source': plan, 'canonicalRenderedServices': sorted(model['services']),
                'selectedServices': sorted(checked['services']), 'existingNetworkNames': networks,
                'output': {'path': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest()},
                'actualCaInput': plan['publicCa'], 'actualTlsQualified': False,
                'actualEdgeGenerationQualified': False, 'baseReaderWarning': warning}
    with evidence_path.open('x') as stream:
        json.dump(evidence, stream, indent=2)
    print(json.dumps({key: evidence[key] for key in ('state', 'engineCalls', 'selectedServices', 'output')}))


if __name__ == '__main__':
    main()
