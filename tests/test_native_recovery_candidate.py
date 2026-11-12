"""Full POSIX generation, HTTPS scope and signature proof for recovery."""
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from scripts.selfhost_native_operator import operator_bytes
from tests.test_selfhost_native_activation import preflight_server, prepare_certificates, OPERATOR
from tests.test_selfhost_native_certificates import key, certificate, pem

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Native generation ownership requires POSIX')


@pytest.mark.parametrize('fault', [None, 'new-root-child', 'ttl-short', 'policy-drift',
                                   'sign-version', 'key-export', 'new-short-leaf', 'static-drift',
                                   'missing-closed-metadata', 'normalized-old-token', 'normalized-duplicate-token',
                                   'issuer-switch', 'signer-switch'])
def test_recovery_candidate_admits_only_fresh_complete_scoped_generation(preflight_server, fault):
    state = preflight_server
    state.closed_metadata = fault != 'missing-closed-metadata'
    prepare_certificates(state, mode='recovery', fault='short-leaf' if fault == 'new-short-leaf' else None)
    state.fault = fault
    if fault == 'issuer-switch':
        signer = key()
        issuer = certificate('synthetic successor keycloak issuer', signer.public_key(), signer=signer, ca=True)
        state.next_keycloak_issuer = pem(issuer).decode()
        for realm in ('master', '11id'):
            path = state.new/f'keycloak_{realm}_rs256_cert'
            public = x509.load_pem_x509_certificate(path.read_bytes()).public_key()
            path.write_bytes(pem(certificate('synthetic successor leaf', public, issuer, signer)))
    if fault == 'signer-switch':
        signer = key()
        issuer_key, issuer = state.fixture_roots['workload-pki']
        remote, filename = 'workload-tls-auth-server', 'auth_workload_server_cert'
        (state.new/filename).write_bytes(pem(certificate(remote, signer.public_key(), issuer, issuer_key)))
        metadata = dict(state.metadata[remote])
        metadata['keys'] = {'1': {'public_key': signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}}
        state.next_metadata = {remote: metadata}
    for root in (state.old, state.new):
        root.chmod(0o700)
        (root/'static-preserved').write_text('PUBLIC_PRESERVED')
        for path in root.iterdir():
            path.chmod(0o600)
    if fault == 'static-drift':
        (state.new/'static-preserved').write_text('PUBLIC_CHANGED')
    if fault == 'normalized-old-token':
        name = 'keycloak_signing_kms_token'
        (state.new/name).write_text((state.old/name).read_text()+'\n')
    if fault == 'normalized-duplicate-token':
        (state.new/'keycloak_master_cookie_token').write_text((state.new/'keycloak_signing_kms_token').read_text()+'\n')
    context = {'token': OPERATOR, 'old': str(state.old), 'new': str(state.new), 'minimum_ttl': 3600}
    result = json.loads(operator_bytes(ROOT, 'operator', 'recovery-candidate',
                        state.bao.endpoint, str(state.bao.ca), input=json.dumps(context).encode()))
    if fault:
        assert set(result) == {'error'} and result['error']
    else:
        assert result == {'value': None}
        lookups = [body['token'] for _, path, body, _ in state.seen if path == 'auth/token/lookup']
        assert lookups.count(OPERATOR) == 1
        assert len(lookups) == 43 and len(set(lookups) - {OPERATOR}) == 21
        assert sum(path.startswith('transit/sign/') for _, path, *_ in state.seen) == 36
    assert not any('synthetic-old-' in str(body) or str(token).startswith('synthetic-old-')
                   for _, _, body, token in state.seen)
    assert all(method == 'GET' or path == 'auth/token/lookup' or path.startswith('transit/sign/')
               for method, path, *_ in state.seen)
