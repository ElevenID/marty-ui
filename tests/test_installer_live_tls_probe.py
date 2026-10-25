"""Local TLS server exercises real verification; no installed-app claim."""
import json
import http.client
from pathlib import Path
import shutil
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


def serve(certificate,key,port,origin):
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
    result=probe.probe(origin,certificate.read_text(),INSTALLATION,ENGINE,now=lambda:100000)
    assert result['issuer']==origin+'/realms/11id'
    assert result['tls_version'] in ('TLSv1.2','TLSv1.3')
    assert result['browser_login_observed'] is False
    with pytest.raises(ssl.SSLError):
        probe.probe(origin,other.read_text(),INSTALLATION,ENGINE)
    worker.join(timeout=2)


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
    def fetcher(context,port,path):
        body=(json.dumps(metadata).encode() if path==probe.DISCOVERY_PATH else b'OK')
        return ('a'*64,'TLSv1.3',200,body)
    with pytest.raises(ValueError):
        probe.probe(origin,certificate.read_text(),INSTALLATION,ENGINE,fetcher=fetcher)


def test_malformed_http_cli_refuses_without_reflecting_server_text(monkeypatch,capsys):
    monkeypatch.setattr(sys,'argv',['probe','https://localhost:18443','invalid',INSTALLATION,ENGINE])
    monkeypatch.setattr(probe,'probe',lambda *args:(_ for _ in ()).throw(
        http.client.BadStatusLine('private-server-text')))
    with pytest.raises(SystemExit,match='Installed TLS observation refused'):
        probe.main()
    captured=capsys.readouterr()
    assert 'private-server-text' not in captured.out+captured.err
