"""Real HTTPS and signatures for retained evidence; all keys are synthetic."""
import json
from pathlib import Path
import re

import pytest
from cryptography.hazmat.primitives import serialization

from scripts.selfhost_native_operator import operator_bytes
from tests.native_operator_https import https_json_server
from tests.test_selfhost_native_certificates import certificate, key, pem

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('fault', [None, 'future-leaf', 'expired-issuer', 'wrong-signature',
                                   'wrong-key', 'exportable', 'authority', 'anchor'])
def test_retained_certificate_evidence_over_https(tmp_path, fault):
    ca_keys = [key(), key()]
    issuers = [certificate(f'synthetic retained issuer {index}', signer.public_key(), signer=signer, ca=True,
                           before=-86400, after=-60 if fault == 'expired-issuer' else 86400)
               for index, signer in enumerate(ca_keys)]
    generation = tmp_path/'generation'
    generation.mkdir()
    roles = re.findall(r'key_name: "([^"]+)",\s*cert_file: "([^"]+)"',
                       (ROOT/'rust/crates/selfhost-identity/src/lib.rs').read_text())
    assert len(roles) >= 15 and len({name for name, _ in roles}) == len(roles)
    roles += [(f'keycloak-{realm}-rs256', f'keycloak_{realm}_rs256_cert') for realm in ('master', '11id')]
    metadata = {}
    for name, file in roles:
        issuer_index = int(name.startswith('keycloak-'))
        signing_key = key('RSA' if issuer_index else 'EC')
        leaf = certificate('synthetic retained leaf', signing_key.public_key(), issuers[issuer_index],
                           key() if fault == 'wrong-signature' else ca_keys[issuer_index],
                           before=3600 if fault == 'future-leaf' else -7200,
                           after=7200 if fault == 'future-leaf' else -60)
        (generation/file).write_bytes(pem(leaf))
        public = (key() if fault == 'wrong-key' else signing_key).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        metadata[name] = {'type': 'rsa-2048' if name.startswith('keycloak-') else 'ecdsa-p256',
                          'exportable': fault == 'exportable', 'allow_plaintext_backup': False,
                          'latest_version': 1, 'keys': {'1': {'public_key': public}}}
    (generation/'workload_identity_ca_cert').write_bytes(b'PUBLIC_INVALID' if fault == 'anchor' else pem(issuers[0]))
    seen, errors = [], []
    def dispatch(method, path, body, token):
        seen.append((method, path))
        assert token == 'synthetic-renewal-token'
        if path == 'auth/token/lookup':
            assert method == 'POST' and body == {'token': token}
            return 200, {'data': {'policies': ['selfhost-kms-renewal'],
                                  'path': 'auth/selfhost-renew/login',
                                  'ttl': 0 if fault == 'authority' else 7200}}
        assert method == 'GET'
        if path in ('workload-pki/cert/ca', 'keycloak-pki/cert/ca'):
            return 200, {'data': {'certificate': pem(issuers[int(path.startswith('keycloak-'))]).decode()}}
        assert path.startswith('transit/keys/')
        return 200, {'data': metadata[path.removeprefix('transit/keys/')]}
    with https_json_server(tmp_path, dispatch, errors) as transport:
        context = {'token': 'synthetic-renewal-token', 'generation': str(generation), 'minimum_ttl': 3600}
        def invoke(operation, body):
            return json.loads(operator_bytes(ROOT, 'operator', operation, transport.endpoint, str(transport.ca),
                                             input=json.dumps(body).encode()))
        if fault:
            refused = invoke('retained-certificates', context)
            assert set(refused) == {'error'} and isinstance(refused['error'], str) and refused['error']
        else:
            assert invoke('retained-certificates', context) == {'value': None}
            # The same expired leaves remain unusable for normal activation.
            refused = invoke('activation-certificates', {'token': context['token'], 'old': str(generation),
                       'new': str(generation), 'minimum_ttl': 3600, 'replacement': None, 'retiring': False})
            assert set(refused) == {'error'} and refused['error']
    assert seen and all(method == 'GET' or path == 'auth/token/lookup' for method, path in seen)

    if fault is None:
        assert {path for method, path in seen if method == 'GET'} == {
            'workload-pki/cert/ca', 'keycloak-pki/cert/ca',
            *(f'transit/keys/{name}' for name, _ in roles)}
