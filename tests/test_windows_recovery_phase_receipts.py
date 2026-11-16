"""Partial or rebound producer evidence cannot qualify a recovery candidate."""
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from selfhost_windows_staging_recovery import RECOVERY_PHASES, recovery_phase_receipts
from selfhost_windows_selection import packed, decode

PROJECT='marty-production-synthetic'
CYCLE='a'*32

def receipts():
    raw={f'{phase}.{event}.json':packed({'phase':phase,'event':event,'metadata':{}})
         for phase in RECOVERY_PHASES for event in ('started','completed')}
    for phase in ('prepare','tls','keycloak'):
        item={'phase':phase,'event':'helper','metadata':{
            'id':{'prepare':'b','tls':'c','keycloak':'d'}[phase]*64,
            'name':PROJECT+'-renew-'+phase+'-'+CYCLE,'image':'services' if phase=='tls' else 'helper'}}
        raw[phase+'.helper.json']=packed(item)
        if phase=='tls':raw['tls.created.json']=packed(dict(item,event='created'))
    return raw

def test_complete_canonical_receipts_bind_three_retired_helper_identities():
    raw=receipts()
    hashes,helpers=recovery_phase_receipts(raw,PROJECT,CYCLE,'helper','services')
    assert len(hashes)==18 and len({v['id'] for v in helpers.values()})==3

@pytest.mark.parametrize('fault',['missing','empty','extra','metadata','name','image','rebound','duplicate','encoding'])
def test_partial_or_rebound_receipts_refuse(fault):
    raw=receipts()
    if fault=='missing':del raw['candidate.completed.json']
    elif fault=='empty':raw['export.completed.json']=b''
    elif fault=='extra':raw['unexpected.json']=b'{}'
    elif fault=='metadata':raw['candidate.completed.json']=packed({'phase':'candidate','event':'completed','metadata':{'override':True}})
    elif fault=='encoding':raw['prepare.completed.json']+=b' '
    else:
        item=decode(raw['tls.helper.json'])
        item['metadata'][{'name':'name','image':'image','rebound':'id','duplicate':'id'}[fault]]= {
            'name':'foreign','image':'other','rebound':'e'*64,'duplicate':'b'*64}[fault]
        raw['tls.helper.json']=packed(item)
        if fault=='duplicate':raw['tls.created.json']=packed(dict(item,event='created'))
    with pytest.raises((ValueError,KeyError)):
        recovery_phase_receipts(raw,PROJECT,CYCLE,'helper','services')
