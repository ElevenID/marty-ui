"""Local TLS server exercises real verification; no installed-app claim."""
import base64
import json
import http.client
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import installer_live_tls_probe as probe


INSTALLATION = '22345678-1234-4234-8234-123456789abc'
ENGINE = 'test-engine-12345678'


def test_public_mode_refuses_private_ca_override_before_network(monkeypatch):
    def forbidden():raise AssertionError('no trust-store read before refusing override')
    monkeypatch.setattr(probe,'system_public_roots',forbidden)
    with pytest.raises(ValueError):
        probe.probe('https://marty.example.test','127.0.0.1:18443','public-ingress',
            'private-ca',INSTALLATION,ENGINE,public_roots=True,expected_leaf='a'*64)


def test_public_mode_uses_fixed_system_bundle_and_pins_selected_leaf(monkeypatch):
    monkeypatch.setenv('SSL_CERT_FILE','/does/not/exist/private.pem')
    monkeypatch.setenv('SSL_CERT_DIR','/does/not/exist')
    origin='https://marty.example.test'
    issuer=origin+probe.ISSUER_PATH
    metadata=dict(issuer=issuer,authorization_endpoint=issuer+'/protocol/openid-connect/auth',
        token_endpoint=issuer+'/protocol/openid-connect/token',jwks_uri=issuer+'/protocol/openid-connect/certs')
    contexts=[]
    def fetcher(context,address,identity,path):
        contexts.append(context)
        body=json.dumps(metadata).encode() if path==probe.DISCOVERY_PATH else b'OK'
        return ('a'*64,'TLSv1.3',200,body)
    result=probe.probe(origin,'127.0.0.1:18443','public-ingress','',INSTALLATION,ENGINE,
        public_roots=True,expected_leaf='a'*64,fetcher=fetcher)
    assert result['schema']=='elevenid.installer-live-tls-observation/v3'
    assert result['probe_trust_source']=='ubuntu-system-ca-bundle'
    assert len(result['probe_trust_bundle_sha256'])==64 and 'ca_der_sha256' not in result
    assert result['public_endpoint_observed'] is False and result['browser_login_observed'] is False
    assert all(c.check_hostname and c.verify_mode==ssl.CERT_REQUIRED and c.get_ca_certs() for c in contexts)
    with pytest.raises(ValueError):
        probe.probe(origin,'127.0.0.1:18443','public-ingress','',INSTALLATION,ENGINE,
            public_roots=True,expected_leaf='b'*64,fetcher=fetcher)


def cert(tmp_path, name, common):
    if shutil.which('openssl') is None:
        pytest.skip('openssl is required for the local TLS fixture')
    certificate=tmp_path/(name+'.pem')
    key=tmp_path/(name+'.key')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN='+common,'-addext','subjectAltName=DNS:'+common,
        '-keyout',str(key),'-out',str(certificate)],check=True,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,timeout=30)
    return certificate,key


def serve(certificate,key,port,origin,requests=None):
    listener=socket.socket()
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('127.0.0.1',port))
    listener.listen(3)
    listener.settimeout(10)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate),str(key))
    def worker():
        try:
            for _ in range(3):
                raw,_=listener.accept()
                try:
                    with context.wrap_socket(raw,server_side=True) as secured:
                        request=secured.recv(4096)
                        if requests is not None:requests.append(request)
                        if b'openid-configuration' in request:
                            issuer=origin+probe.ISSUER_PATH
                            body=json.dumps(dict(issuer=issuer,
                                authorization_endpoint=issuer+'/protocol/openid-connect/auth',
                                token_endpoint=issuer+'/protocol/openid-connect/token',
                                jwks_uri=issuer+'/protocol/openid-connect/certs')).encode()
                        else:body=b'OK'
                        secured.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+
                            b'\r\nConnection: close\r\n\r\n'+body)
                except ssl.SSLError:
                    pass
        except (OSError,TimeoutError):
            pass
        finally:
            listener.close()
    thread=threading.Thread(target=worker,daemon=True)
    thread.start()
    return thread


def test_real_local_tls_discovery_and_untrusted_ca_failure(tmp_path):
    certificate,key=cert(tmp_path,'server','localhost')
    other,_=cert(tmp_path,'other','localhost')
    reserved=socket.socket();reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1];reserved.close()
    origin='https://localhost:'+str(port)
    worker=serve(certificate,key,port,origin)
    address='127.0.0.1:'+str(port)
    result=probe.probe(origin,address,'public-ingress',certificate.read_text(),INSTALLATION,ENGINE,now=lambda:100000)
    assert result['issuer']==origin+'/realms/11id'
    assert result['tls_version'] in ('TLSv1.2','TLSv1.3')
    assert result['browser_login_observed'] is False
    with pytest.raises(ssl.SSLError):
        probe.probe(origin,address,'public-ingress',other.read_text(),INSTALLATION,ENGINE)
    worker.join(timeout=2)


@pytest.mark.parametrize('origin',['https://marty.example.test','https://marty.example.test:9443'])
def test_public_authority_verified_over_separate_local_socket(tmp_path,origin):
    certificate,key=cert(tmp_path,'server','marty.example.test')
    reserved=socket.socket();reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1];reserved.close()
    address='127.0.0.1:'+str(port)
    requests=[]
    worker=serve(certificate,key,port,origin,requests)
    result=probe.probe(origin,address,'backend',certificate.read_text(),INSTALLATION,ENGINE)
    expected=('Host: '+origin.removeprefix('https://')+'\r\n').encode()
    assert len(requests)==2 and all(expected in request for request in requests)
    assert result['origin']==origin and result['local_probe_address']==address
    assert result['certificate_scope']=='backend'
    assert result['public_endpoint_observed'] is False
    assert result['browser_login_observed'] is False
    # The local transport never replaces the certificate's DNS identity.
    with pytest.raises(ssl.SSLCertVerificationError):
        probe.probe('https://wrong.example.test',address,'backend',certificate.read_text(),INSTALLATION,ENGINE)
    worker.join(timeout=2)


@pytest.mark.parametrize('origin',[
    'http://marty.example.test','https://marty.example.test/',
    'https://marty.example.test:443','https://marty.example.test:08443',
    'https://MARTY.example.test','https://user@marty.example.test',
    'https://marty.example.test?','https://marty.example.test#',
    'https://marty.example.test\\evil','https://marty.example.test\r\nHost:evil',
    'https://127.1','https://0x7f000001','https://[::ffff:127.0.0.1]',
])
def test_origin_aliases_and_request_injection_refuse_before_network(origin):
    with pytest.raises(ValueError):probe.public_origin(origin)


@pytest.mark.parametrize('address',[
    'marty.example.test:8443','127.0.0.1','127.0.0.1:443','127.0.0.1:08443',
    '0.0.0.0:8443','[::]:8443','127.0.0.1:8443/path','127.0.0.1:8443#',
    '127.0.0.1:8443\r\nHost:evil','[::ffff:127.0.0.1]:8443',
])
def test_transport_must_be_exact_numeric_listener_socket(address):
    with pytest.raises(ValueError):probe.local_address(address)


def test_ipv6_local_transport_does_not_change_dns_identity():
    assert probe.local_address('[::1]:18443')==('::1',18443)
    assert probe.public_origin('https://marty.example.test').netloc=='marty.example.test'


@pytest.mark.parametrize('key,value',[('issuer','https://evil.example/realms/11id'),
    ('authorization_endpoint','https://evil.example/auth'),
    ('token_endpoint','https://localhost:18444/realms/11id/protocol/openid-connect/token'),
    ('jwks_uri','http://localhost:18443/certs')])
def test_discovery_rejects_cross_origin_metadata(tmp_path,key,value):
    certificate,_=cert(tmp_path,'server','localhost')
    origin='https://localhost:18443'
    metadata=dict(issuer=origin+probe.ISSUER_PATH,
        authorization_endpoint=origin+probe.ISSUER_PATH+'/protocol/openid-connect/auth',
        token_endpoint=origin+probe.ISSUER_PATH+'/protocol/openid-connect/token',
        jwks_uri=origin+probe.ISSUER_PATH+'/protocol/openid-connect/certs')
    metadata[key]=value
    def fetcher(context,address,identity,path):
        body=(json.dumps(metadata).encode() if path==probe.DISCOVERY_PATH else b'OK')
        return ('a'*64,'TLSv1.3',200,body)
    with pytest.raises(ValueError):
        probe.probe(origin,'127.0.0.1:18443','public-ingress',certificate.read_text(),INSTALLATION,ENGINE,fetcher=fetcher)


def test_malformed_http_cli_refuses_without_reflecting_server_text(monkeypatch,capsys):
    ca = base64.b64encode(b'public-ca-fixture').decode('ascii')
    monkeypatch.setattr(sys,'argv',['probe','https://localhost:18443','127.0.0.1:18443','public-ingress',ca,INSTALLATION,ENGINE])
    called = []
    def malformed_http(*args):
        called.append(args)
        raise http.client.BadStatusLine('private-server-text')
    monkeypatch.setattr(probe,'probe',malformed_http)
    with pytest.raises(SystemExit,match='Installed TLS observation refused'):
        probe.main()
    assert len(called) == 1
    assert signal.alarm(0) == 0
    captured=capsys.readouterr()
    assert 'private-server-text' not in captured.out+captured.err
