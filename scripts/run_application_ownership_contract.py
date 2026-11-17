#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compile exact ownership module with only production-lock registry dependencies.

The separate PostgreSQL script tests real SQL, not Gateway/session authentication.
This harness does not qualify mounting, migration registration or deployed roles.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    if sys.argv[1:]==['--source-contract']:
        subprocess.run([sys.executable,str(ROOT/'scripts/test_external_association_sources.py'),'--rust-contract'],check=True,stderr=subprocess.STDOUT)
        return
    if not sys.argv[1:]:
        subprocess.run([sys.executable,str(ROOT/'scripts/test_application_ownership.py'),'--rust-contract'],check=True,stderr=subprocess.STDOUT)
        return
    source_contract=os.environ.get('EXTERNAL_ASSOCIATION_SOURCE_TEST')=='synthetic-local-only'
    gateway_contract=os.environ.get('EXTERNAL_ASSOCIATION_GATEWAY_TEST')=='synthetic-local-only'
    assert sys.argv[1:]==['--compile-only'] and (source_contract or os.environ.get('APPLICATION_OWNERSHIP_CONTRACT_TEST')=='synthetic-local-only')
    workspace=tomllib.loads((ROOT/'rust/Cargo.toml').read_text())
    service=tomllib.loads((ROOT/'rust/services/issuance/Cargo.toml').read_text())
    declarations=[]
    names=['serde','serde_json','sqlx','uuid','axum','tokio','subtle','tower','base64','sha2','http-body-util']
    if gateway_contract:names+=['async-trait','chrono','mmf-platform','mmf-security','reqwest','tonic','tokio-stream']
    for name in names:
        value=workspace['workspace']['dependencies'][name]
        value={'version':value} if isinstance(value,str) else dict(value)
        assert not set(value)-{'version','features','default-features','package',*(['git','rev'] if gateway_contract else [])}
        override=service['dependencies'].get(name,{})
        if isinstance(override,dict):value['features']=sorted(set(value.get('features',[]))|set(override.get('features',[])))
        def render(item):
            if isinstance(item,dict):return '{ '+', '.join(key+' = '+render(val) for key,val in item.items())+' }'
            return json.dumps(item)
        declarations.append(name+' = '+render(value))
    if gateway_contract:
        for name,path in [('marty-gateway','rust/services/gateway'),('marty-auth','rust/services/auth')]:
            declarations.append(name+' = { path = '+json.dumps(str(ROOT/path))+' }')
    with tempfile.TemporaryDirectory(prefix='application-ownership-rust-') as temporary:
        directory=Path(temporary)
        manifest='[package]\nname="application-ownership-contract"\nversion="0.0.0"\nedition="2021"\npublish=false\n[workspace]\n[lib]\npath="lib.rs"\n[dependencies]\n'+'\n'.join(declarations)+'\n'
        if gateway_contract:
            for target,patches in workspace.get('patch',{}).items():
                manifest+='\n[patch.'+json.dumps(target)+']\n'
                for name,value in patches.items():
                    value=dict(value)
                    if 'path' in value:value['path']=str((ROOT/'rust'/value['path']).resolve())
                    manifest+=name+' = '+render(value)+'\n'
        (directory/'Cargo.toml').write_text(manifest)
        shutil.copyfile(ROOT/'rust/Cargo.lock',directory/'Cargo.lock')
        module=ROOT/'rust/services/issuance/src/application_ownership.rs'
        modules={'application_ownership':module,
            'application_ownership_schema':ROOT/'rust/services/issuance/src/application_ownership_schema.rs',
            'application_ownership_startup':ROOT/'rust/services/issuance/src/application_ownership_startup.rs',
            'application_ownership_http':ROOT/'rust/services/issuance/src/application_ownership_http.rs',
            'external_association':ROOT/'rust/services/issuance/src/external_association.rs',
            'external_association_schema':ROOT/'rust/services/issuance/src/external_association_schema.rs',
            'external_association_startup':ROOT/'rust/services/issuance/src/external_association_startup.rs',
            'external_association_http':ROOT/'rust/services/issuance/src/external_association_http.rs',
            'gateway_ownership_guard':ROOT/'rust/services/gateway/src/external_observation.rs'}
        modules['gateway_association_guard']=ROOT/'rust/services/gateway/src/external_association.rs'
        composition=ROOT/('tests/rust/external-association/source.rs' if source_contract else 'tests/rust/application-ownership/composition.rs')
        if gateway_contract:composition=ROOT/'tests/rust/external-association/gateway.rs'
        (directory/'lib.rs').write_text(''.join('#[path='+json.dumps(str(path))+']\npub mod '+name+';\n' for name,path in modules.items())
            +'#[cfg(test)]\n#[path='+json.dumps(str(composition))+']\nmod ownership_composition;\n')
        environment=os.environ.copy()
        target=Path.home()/'.cache/codex-application-ownership/rust-target'
        target.mkdir(parents=True,exist_ok=True)
        environment.update(CARGO_TARGET_DIR=str(target),RUSTFLAGS='-D warnings')
        if gateway_contract:
            environment.update(CARGO_TARGET_DIR=str(Path.home()/'.cache/codex-application-ownership/native-target'),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0')
            environment.pop('RUSTFLAGS',None)
        metadata=subprocess.run(['cargo','metadata','--offline','--format-version','1'],cwd=directory,env=environment,text=True,capture_output=True)
        if metadata.returncode:
            print(metadata.stderr[-8000:],file=sys.stderr)
            metadata.check_returncode()
        expected={(p['name'],p['version'],p.get('source'),p.get('checksum')) for p in tomllib.loads((ROOT/'rust/Cargo.lock').read_text())['package'] if 'source' in p}
        actual={(p['name'],p['version'],p.get('source'),p.get('checksum')) for p in tomllib.loads((directory/'Cargo.lock').read_text())['package'] if 'source' in p}
        assert actual<=expected,'ownership harness resolved dependencies outside production lock'
        subprocess.run(['cargo','test','--offline','--locked','--lib'],cwd=directory,env=environment,check=True,stderr=subprocess.STDOUT)
        subprocess.run(['cargo','clippy','--offline','--locked','--lib','--','-D','warnings'],cwd=directory,env=environment,check=True,stderr=subprocess.STDOUT)
    print('Exact ownership Rust module original-byte decode/validation contract PASS; production registry lock preserved')

if __name__=='__main__':main()
