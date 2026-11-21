"""Actual worker control flow with synthetic files and subprocess doubles only."""
import base64
import builtins
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_renewal_native as native
import selfhost_windows_selection as selection


def worker(tmp_path, *, fault=None, mode='inspection'):
    """Execute the shipped WORKER, mapping only its fixed sandbox paths."""
    binary=tmp_path/'operator/tool';binary.parent.mkdir();binary.write_bytes(b'PUBLIC_TEST_BINARY')
    control=tmp_path/'control';control.mkdir()
    current=control/'generation';current.mkdir()
    (current/'public_cert').write_bytes(b'PUBLIC_TEST_CERT')
    (control/'token').write_bytes(b'PRIVATE_SYNTHETIC_TOKEN')
    (tmp_path/'proof').mkdir()
    request={'binary_sha256':selection.digest(binary.read_bytes()),'source_sha':'a'*40,
        'release_tag':'v1.2.3','current':'/control/generation','renewed':'/control/generation',
        'token_file':'/control/token','bao_addr':'https://synthetic.invalid','minimum_ttl':3600,
        'transition':False,'count':1,'changed':0,'initial_current':False,
        'bytes':{role:{'public_cert':base64.b64encode(b'PUBLIC_TEST_CERT').decode()}
                 for role in ('old','new')}}
    if mode=='inspection':request['certificate_inspection']=True
    if fault=='binary':request['binary_sha256']='0'*64
    if fault=='mirror':(current/'public_cert').write_bytes(b'PUBLIC_CHANGED_CERT')
    if fault=='extra-mirror':(current/'extra').write_bytes(b'PUBLIC_EXTRA')
    if fault=='transition':request['transition']=True
    if fault=='initial':request['initial_current']=True
    if fault=='recovery':request['recovery']=True
    calls=[]
    def run(args,**options):
        assert options['capture_output'] is True
        if args[1:]==['--build-identity']:
            return subprocess.CompletedProcess(args,0,
                (('b' if fault=='identity' else 'a')*40+':v1.2.3').encode(),b'')
        op=args[2];calls.append(op)
        assert op in ('authority-check','activation-certificates','activation-tokens')
        body=json.loads(options['input'])
        assert body['token']=='PRIVATE_SYNTHETIC_TOKEN'
        output=b'{"value":null}';code=0;stderr=b''
        target='authority-check' if fault and fault.startswith('authority-') else 'activation-certificates'
        case=fault.removeprefix('authority-') if fault else None
        if op==target:
            if case=='timeout':raise subprocess.TimeoutExpired(args,90,output=b'PRIVATE_SYNTHETIC_PARTIAL')
            if case=='nonzero':code=1
            if case in (None,'nonzero','stderr','oversized-stderr','transition','initial','recovery'):
                output=json.dumps({'error':native.CERTIFICATE_LIFETIME_REFUSAL}).encode()
            elif case=='generic':output=b'{"error":"KMS operator input refused"}'
            elif case=='invalid-cert':output=b'{"error":"renewed certificate validity is invalid"}'
            elif case=='unknown':output=b'{"error":"PRIVATE_SYNTHETIC_UNKNOWN"}'
            elif case=='duplicate':output=b'{"value":null,"value":null}'
            elif case=='duplicate-error':
                output=('{"error":"ignored","error":'+json.dumps(native.CERTIFICATE_LIFETIME_REFUSAL)+'}').encode()
            elif case=='extra':output=b'{"value":null,"unexpected":false}'
            elif case=='wrong-value':output=b'{"value":false}'
            elif case=='malformed':output=b'PRIVATE_SYNTHETIC_INVALID_JSON'
            elif case=='oversized':output=b' '*(4097)+b'{"value":null}'
            elif case=='array':output=b'[]'
            elif case=='stderr':stderr=b'PRIVATE_SYNTHETIC_DIAGNOSTIC'
            if case=='oversized-stderr':stderr=b'x'*4097
        return subprocess.CompletedProcess(args,code,output,stderr)
    def path(*args):
        first=str(args[0])
        if first=='/operator/tool' or first=='/proof' or first.startswith('/control'):
            return Path(tmp_path,first.lstrip('/'),*args[1:])
        return Path(*args)
    # Linux-only O_NOFOLLOW is represented by a synthetic flag on Windows.
    # This proves worker control flow only, not Linux/NTFS filesystem custody.
    synthetic_os=SimpleNamespace(**dict(vars(os),O_NOFOLLOW=getattr(os,'O_NOFOLLOW',0)))
    imports={'pathlib':SimpleNamespace(Path=path),'subprocess':SimpleNamespace(run=run),'os':synthetic_os}
    original_import=builtins.__import__
    def imported(name,*args,**kwargs):return imports.get(name) or original_import(name,*args,**kwargs)
    output=io.StringIO();stdin=sys.stdin;failed=None;old_umask=os.umask(0o077)
    try:
        sys.stdin=io.StringIO(json.dumps(request))
        with redirect_stdout(output):
            try:exec(compile(native.WORKER,'shipped-certificate-worker','exec'),
                     {'__builtins__':dict(vars(builtins),__import__=imported)})
            except (AssertionError,ValueError,subprocess.TimeoutExpired) as error:failed=error
    finally:
        sys.stdin=stdin
        os.umask(old_umask)
    assert 'PRIVATE_' not in output.getvalue()
    return calls,output.getvalue(),failed


@pytest.mark.parametrize('outcome,fault',[('lifetime-refused',None),('completed','success')])
def test_certificate_inspection_is_separate_and_never_examines_tokens(tmp_path,outcome,fault):
    calls,output,failed=worker(tmp_path,fault=fault)
    assert failed is None and calls==['authority-check','activation-certificates']
    assert json.loads(output)==native.certificate_inspection_result(outcome)


@pytest.mark.parametrize('fault',['binary','identity','mirror','extra-mirror','transition','initial','recovery',
    'nonzero','timeout','generic','invalid-cert','unknown','duplicate','duplicate-error','extra',
    'wrong-value','malformed','oversized','oversized-stderr','array',
    'authority-generic','authority-nonzero','authority-timeout','authority-duplicate','authority-extra',
    'authority-malformed','authority-oversized','authority-oversized-stderr'])
def test_uncertain_or_malformed_native_outcome_has_no_semantic_refusal_output(tmp_path,fault):
    calls,output,failed=worker(tmp_path,fault=fault)
    assert failed is not None and not output
    assert 'activation-tokens' not in calls
    if fault.startswith('authority-'):assert calls==['authority-check']


def test_ordinary_current_proof_keeps_token_first_and_rejects_certificate_refusal(tmp_path):
    calls,output,failed=worker(tmp_path,mode='ordinary')
    assert failed is not None and not output
    assert calls==['authority-check','activation-tokens','activation-certificates']


def transport(monkeypatch,tmp_path,reply,*,code=0,stderr=b''):
    binary=tmp_path/'tool';binary.write_bytes(b'PUBLIC_TEST_BINARY')
    ca=tmp_path/'ca';ca.write_bytes(b'PUBLIC_TEST_CA')
    config={'binary':str(binary),'binary_sha256':selection.digest(binary.read_bytes()),
        'ca_file':str(ca),'source_sha':'a'*40,'release_tag':'v1.2.3',
        'helper_image':'python@sha256:'+'b'*64,'control_volume':'marty-production-test-renewal-control',
        'network':'marty-production-test_default','bao_addr':'https://openbao:8200','minimum_ttl':3600,
        'current':'/control/generation','renewed':'/control/unused','token_file':'/control/session/token'}
    calls=[]
    @contextmanager
    def held(path,**_kwargs):yield path.read_bytes()
    def run(args,**kwargs):
        calls.append(json.loads(kwargs['stdin_bytes']))
        assert args[-1]==native.WORKER
        return subprocess.CompletedProcess(args,code,reply,stderr)
    monkeypatch.setattr(native,'hold_private_input',held)
    monkeypatch.setattr(selection.renewal,'run_owned_mutation',run)
    return config,calls


@pytest.mark.parametrize('fault',['numeric-authority','numeric-tokens','numeric-whole','numeric-admission',
    'duplicate','extra','missing','generic','malformed','nonzero','oversized','oversized-stderr'])
def test_outer_transport_rejects_malformed_or_numeric_boolean_envelopes(monkeypatch,tmp_path,fault):
    reply=deepcopy(native.certificate_inspection_result('lifetime-refused'))
    if fault.startswith('numeric-'):
        field={'authority':'authority_verified','tokens':'tokens_examined',
               'whole':'whole_current_proof','admission':'credential_admission'}[fault.split('-')[1]]
        reply[field]=int(reply[field])
    elif fault=='extra':reply['unexpected']=False
    elif fault=='missing':del reply['operation']
    elif fault=='generic':reply={'error':'KMS operator input refused'}
    raw=selection.packed(reply)
    if fault=='malformed':raw=b'PRIVATE_SYNTHETIC_INVALID_JSON'
    if fault=='duplicate':raw=raw.rstrip()[:-1]+b',"tokens_examined":false}'
    if fault=='oversized':raw=b' '*4097+raw
    config,calls=transport(monkeypatch,tmp_path,raw,code=1 if fault=='nonzero' else 0,
                           stderr=b'x'*4097 if fault=='oversized-stderr' else b'')
    with pytest.raises(ValueError):
        native.inspect_current_certificates(config,'marty-production-test',{'public_cert':b'PUBLIC'},['SYNTHETIC'])
    assert len(calls)==1 and calls[0]['certificate_inspection'] is True


def test_successful_certificate_subcheck_never_substitutes_for_ordinary_preflight(monkeypatch,tmp_path):
    config,calls=transport(monkeypatch,tmp_path,selection.packed(native.certificate_inspection_result('completed')))
    assert native.inspect_current_certificates(config,'marty-production-test',{'public_cert':b'PUBLIC'},['SYNTHETIC'])==native.certificate_inspection_result('completed')
    config['certificate_inspection']=True # untrusted config cannot opt ordinary preflight in
    with pytest.raises(ValueError):
        native.preflight_current(config,'marty-production-test',{'public_cert':b'PUBLIC'},['SYNTHETIC'])
    assert 'certificate_inspection' not in calls[-1]
