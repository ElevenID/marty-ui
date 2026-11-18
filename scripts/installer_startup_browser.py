"""Run the fixed real browser against native-bound public origins.

The customer guest is never used as a browser/runtime installer. A verified
controller runtime and fixed signed harness sources are prerequisites.
"""
from __future__ import annotations

import re
from pathlib import Path
import time

import installer_release as r
import installer_startup_observation as observation
from installer_candidate_authorize import write_exclusive
from installer_candidate_hosting import HeldInput
from installer_startup_process import command

SCHEMA = 'elevenid.installer-startup-browser/v1'
INPUT_SCHEMA = 'elevenid.installer-startup-browser-input/v1'
MAX_BYTES = 65536


def request(native_raw, native, runtime):
    return dict(schema=INPUT_SCHEMA,request=native['request'],native_sha256=r.digest(native_raw),
        installation_id=native['installation_id'],engine_id=native['engine_id'],
        operator_sha256=native['operator_sha256'],context_sha256=native['context_sha256'],
        selection_sha256=r.digest(r.encode(native['selection'])),
        canonical_origin=native['hosting']['public_origin'],public_entry_origin=native['hosting']['public_entry_origin'],
        certificate_der_sha256=native['trust']['certificate_der_sha256'],app_name=native['page']['app_name'],
        assets=native['page']['assets'],runtime=dict(runtime))


def validate(raw, *, native_raw, native, now):
    import installer_browser_runtime
    value = r.decode(raw)
    r.exact(value, {'schema','request','native_sha256','installation_id','engine_id','operator_sha256','context_sha256',
        'selection_sha256','runtime','canonical_origin','public_entry_origin','landing','actions','observations',
        'started_at','completed_at','https_errors_ignored','installation_ready','functional_recovery_qualified','load_characterized'},
        'installed browser owner')
    r.require(value['schema']==SCHEMA and value['request']==native['request']
        and value['native_sha256']==r.digest(native_raw)
        and all(value[key]==native[key] for key in ('installation_id','engine_id','operator_sha256','context_sha256'))
        and value['selection_sha256']==r.digest(r.encode(native['selection']))
        and value['canonical_origin']==native['hosting']['public_origin']
        and value['public_entry_origin']==native['hosting']['public_entry_origin']
        and all(value[key] is False for key in ('https_errors_ignored','installation_ready','functional_recovery_qualified','load_characterized')),
        'installed browser scope differs')
    installer_browser_runtime.validate_identity(value['runtime'])
    observation.integer(value['started_at'],minimum=native['completed_at'])
    observation.integer(value['completed_at'],minimum=value['started_at'],maximum=min(now,value['started_at']+150))
    counters = r.exact(value['observations'], {'ip_requests','ip_session_requests','ip_credential_headers',
        'ip_response_cookies','ip_stored_cookies','page_errors','failed_asset_requests'}, 'browser event counters')
    observation.integer(counters['ip_requests'],minimum=len(native['page']['assets']),maximum=512)
    r.require(all(type(number) is int and number==0 for key,number in counters.items() if key!='ip_requests'),
              'IP authentication, cookies, script or asset failures were observed')
    landing = r.exact(value['landing'], {'url','heading_count','branding_visible','image_count','images_loaded',
        'screenshot_sha256','assets','certificate_der_sha256'}, 'actual landing rendering')
    r.require(landing['url']==native['hosting']['public_entry_origin']+'/' and landing['branding_visible'] is True
        and landing['images_loaded'] is True and landing['certificate_der_sha256']==native['trust']['certificate_der_sha256'],
        'actual IP landing or browser certificate differs')
    observation.integer(landing['heading_count'],minimum=1,maximum=32)
    observation.integer(landing['image_count'],maximum=512);r.sha(landing['screenshot_sha256'],64)
    expected = {item['path']:item for item in native['page']['assets']}
    r.require(type(landing['assets']) is list and len(landing['assets'])==len(expected), 'browser asset closure differs')
    actual = {}
    for item in landing['assets']:
        r.exact(item,{'path','status','media_type','size_bytes','sha256'},'actual rendered asset')
        r.require(item['path'] in expected and item['path'] not in actual and type(item['status']) is int
            and item['status']==200 and {k:v for k,v in item.items() if k!='status'}==expected[item['path']],
            'browser received different or missing shipped assets')
        actual[item['path']] = item
    r.exact(value['actions'],{'sign_in','console'},'actual canonical actions')
    for name, selector, first_path in [('sign_in','login-button','/v1/auth/login'),('console','public-entry-console','/console')]:
        action = r.exact(value['actions'][name], {'selector','source_url','document_requests','final_origin',
            'final_path','certificate_der_sha256'}, 'actual canonical navigation')
        r.require(action['selector']==selector and action['source_url']==native['hosting']['public_entry_origin']+'/'
            and action['final_origin']==native['hosting']['public_origin']
            and action['certificate_der_sha256']==native['trust']['certificate_der_sha256'], 'canonical action binding differs')
        path = lambda item: type(item) is str and item.startswith('/') and len(item)<=2048 and re.search(r'[\x00-\x20?#\\]',item) is None
        r.require(path(action['final_path']), 'canonical landing path differs')
        requests = action['document_requests']
        r.require(type(requests) is list and 1<=len(requests)<=16, 'actual navigation missing')
        for item in requests:
            r.exact(item,{'origin','path','method'},'actual document request')
            r.require(item['origin']==native['hosting']['public_origin'] and item['method']=='GET' and path(item['path']),
                      'navigation escaped canonical authority')
        r.require(requests[0]['path']==first_path, 'actual action did not request its canonical endpoint')
    return value


def run(*, runtime_root: Path, native_raw: bytes, native: dict, harness: Path, output: Path,
        unchanged, clock=time.time, execute=command):
    import installer_browser_runtime
    # These paths are fixed inputs from the controller; no executable or URL
    # override can enter through the report or the browser command line.
    output.mkdir(mode=0o700)
    input_path, result_path = output/'input.json', output/'browser.json'
    with installer_browser_runtime.admit(runtime_root) as runtime:
        expected=request(native_raw,native,runtime.identity)
        write_exclusive(input_path,r.encode(expected))
        with HeldInput(input_path,MAX_BYTES) as held:
            unchanged(); runtime.check(); held.check()
            execute([str(runtime.node),str(harness),'--input',str(input_path),
                '--runtime-root',str(runtime_root),'--output',str(result_path)],
                env=dict(HOME=str(output),PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',
                         XDG_CONFIG_HOME=str(output),XDG_CACHE_HOME=str(output)),timeout=180,limit=MAX_BYTES)
            runtime.check(); held.check(); unchanged()
            with HeldInput(result_path,MAX_BYTES) as result:
                raw=result.check()
                value=validate(raw,native_raw=native_raw,native=native,now=int(clock()))
                r.require(value['runtime']==dict(runtime.identity),'browser executed another runtime')
                result.check(); runtime.check(); unchanged()
    return raw
