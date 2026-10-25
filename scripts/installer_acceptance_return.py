"""Authenticate a same-invocation controller checkpoint, never acceptance evidence.

The grant must have been consumed while valid. Completion observation may arrive
later, bounded to two hours from consumption; this does not extend authorization
or permit a second dispatch. The workflow signs this distinct incomplete schema.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import time
import installer_release as r
import installer_promote as promotion
import installer_candidate_rendezvous as transport
import installer_acceptance_runner as runner
from installer_candidate_authorize import read_record,write_exclusive


def asset(items,approved,receipt):
    r.require(isinstance(items,list) and 1<=len(items)<=2,'checkpoint transport closure differs')
    r.require({item.get('name') for item in items if isinstance(item,dict)} in
        ({transport.RECEIPT},{transport.RECEIPT,runner.NAME}),'checkpoint transport names differ')
    original=[i for i in items if i.get('name')==transport.RECEIPT]
    bound=transport.receipt_asset(original,approved)
    r.require(bound['size']==len(receipt) and bound['digest']=='sha256:'+r.digest(receipt),'original controller receipt changed')
    found=[i for i in items if i.get('name')==runner.NAME]
    if not found:return None
    # Same bounded uploader/digest policy as the original controller receipt.
    copy=dict(found[0]);copy['name']=transport.RECEIPT
    checked=transport.receipt_asset([copy],approved);checked['name']=runner.NAME
    return checked


def receive(*,client,authorization,inventory,receipt,descriptor,output,harness_source_sha,
            run_id,run_attempt,controller_user_id,clock=time.time,sleep=time.sleep):
    auth,inv,consumed=read_record(authorization),read_record(inventory),read_record(receipt)
    recorded=r.decode(consumed);when=recorded.get('consumed_at');r.positive(when)
    r.require(when<=int(clock())<when+7200,'checkpoint return window expired')
    # Historical consumption binding only: no renewed execution authorization.
    a,i,context,grant=transport.inputs(authorization,inventory,harness_source_sha=harness_source_sha,
        run_id=run_id,run_attempt=run_attempt,now=when)
    bound=r.bind_controller_consumption(consumed,a,i,expected=context,expected_engine=recorded.get('engine_id'),now=when)
    target={key:bound[key] for key in runner.dispatch.TARGET_FIELDS}
    d=r.decode(read_record(descriptor));approved=transport.controller_id(controller_user_id)
    r.exact(d,{'schema','authorization_sha256','inventory_sha256','context_sha256','controller_user_id',
        'nonce','run_id','run_attempt','harness_source_sha','release'},'checkpoint descriptor')
    r.require(d['schema']==transport.SCHEMA and d['authorization_sha256']==r.digest(a)
        and d['inventory_sha256']==r.digest(i) and d['context_sha256']==r.candidate_context_sha256(context)
        and d['controller_user_id']==approved and all(d[k]==context[k] for k in ('nonce','run_id','run_attempt','harness_source_sha')),
        'checkpoint descriptor binding differs')
    owned=transport.identity(grant,d['release'].get('id'),d['release'].get('author_id'))
    r.require(d['release']==owned,'checkpoint release differs')
    api=client.request('GET',transport.REPO+'/actions/runs/'+str(run_id))
    promotion.check_run(api,run_id=run_id,attempt=run_attempt,workflow=r.acceptance.WORKFLOW,source=harness_source_sha,active=True)
    endpoint=transport.REPO+'/releases/'+str(owned['id'])
    deadline=min(int(clock())+1800,when+7200)
    while int(clock())<deadline:
        transport.check_release(client.request('GET',endpoint),owned)
        selected=asset(client.request('GET',endpoint+'/assets?per_page=100'),approved,consumed)
        if selected is None:
            sleep(min(5,max(0,deadline-int(clock()))));continue
        raw=client.download(selected['id'],selected['size'])
        r.require(r.digest(raw)==selected['digest'][7:],'checkpoint digest differs')
        transport.check_release(client.request('GET',endpoint),owned)
        r.require(asset(client.request('GET',endpoint+'/assets?per_page=100'),approved,consumed)==selected,'checkpoint changed during download')
        value=r.decode(raw)
        runner.validate(value,context=context,target=target,authorization=a,receipt=consumed,inventory=i)
        r.require(when<=value['observed_at']<=int(clock())<deadline,'checkpoint timing differs')
        r.require(read_record(authorization)==auth and read_record(inventory)==inv and read_record(receipt)==consumed,
            'checkpoint local inputs changed')
        evidence=dict(schema='elevenid.installer-acceptance-checkpoint-transport/v1',release_id=owned['id'],
            checkpoint_sha256=r.digest(raw),receipt_sha256=r.digest(consumed),context_sha256=r.candidate_context_sha256(context),
            controller_user_id=approved,verified_at=int(clock()),asset={k:selected[k] for k in ('id','name','size','digest','created_at','updated_at')},
            acceptance=False)
        write_exclusive(Path(str(output)+'.transport.json'),r.encode(evidence))
        write_exclusive(output,raw);return value
    raise ValueError('checkpoint return deadline expired')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('authorization','inventory','receipt','descriptor','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--harness-source-sha',required=True)
    for name in ('run-id','run-attempt','controller-user-id'):parser.add_argument('--'+name,type=int,required=True)
    try:receive(**vars(parser.parse_args(argv)),client=transport.Client(os.environ.get('GH_TOKEN')))
    except (ValueError,OSError,KeyError,TypeError):parser.exit(1,'Installed checkpoint return refused; preserve transport and controller evidence.\n')


if __name__=='__main__':main()
