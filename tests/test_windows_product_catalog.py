"""Catalog evidence only; actual native DDL is exercised in the owned PG fixture."""
from pathlib import Path
import re
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_product_catalog as catalog


def pair(bootstrap=False, triggered=False):
    before=dict(schema=catalog.SCHEMA,side='before',parent_oid=17001,parent_has_triggers=triggered,
        parent_owner_oid=10 if bootstrap else 16500,parent_owner_bootstrap=bootstrap,
        catalog_sha256='a'*64,dependencies_sha256='b'*64,shared_dependencies_sha256='c'*64,annotations_sha256='0'*64,
        new_objects_absent=True,parent_key_valid=True,owner_defaults_empty=True,supported=True)
    after={k:v for k,v in before.items() if k not in ['new_objects_absent','parent_key_valid','owner_defaults_empty','supported']}
    after.update(side='after',parent_has_triggers=True,shape_sha256=catalog.SHAPE_SHA256[bootstrap],
        raw_catalog_sha256='d'*64,raw_dependencies_sha256='e'*64,raw_shared_dependencies_sha256='f'*64,raw_annotations_sha256='1'*64,
        new_row_count=0,unsupported_objects=False,storage_distinct=True)
    return before,after


@pytest.mark.parametrize('bootstrap',[False,True])
@pytest.mark.parametrize('triggered',[False,True])
def test_qualified_shape_preserves_raw_after_without_granting_admission(bootstrap,triggered):
    before,after=pair(bootstrap,triggered)
    receipt=catalog.validate_delta(before,after)
    assert receipt['raw_after']=={key:after['raw_'+key]for key in ('catalog_sha256','dependencies_sha256','shared_dependencies_sha256','annotations_sha256')}
    assert receipt['native_admission']is False and receipt['product_transition_admission']is False
    for sql in [catalog.statement(),catalog.statement(before),catalog.statement(before,debug_shape=True)]:
        assert not re.search(r'\b(UPDATE|INSERT|DELETE|ALTER|CREATE|DROP|TRUNCATE)\b',sql,re.I)


@pytest.mark.parametrize('field,value',[
    ('parent_oid',True),('parent_oid',"1;DELETE"),('parent_oid',0),
    ('parent_has_triggers',1),('parent_owner_oid',True),('parent_owner_oid',6171),
    ('parent_owner_bootstrap',True),('new_objects_absent',False),('parent_key_valid',False),
    ('owner_defaults_empty',False),('supported',False),('catalog_sha256','unknown')])
def test_invalid_before_cannot_inject_or_weaken_exclusion(field,value):
    before,_=pair();before[field]=value
    with pytest.raises(ValueError):catalog.statement(before)


@pytest.mark.parametrize('field,value',[
    ('catalog_sha256','e'*64),('dependencies_sha256','e'*64),('shared_dependencies_sha256','e'*64),
    ('shape_sha256','e'*64),('raw_catalog_sha256','not-a-digest'),('parent_oid',17002),
    ('raw_dependencies_sha256','not-a-digest'),('raw_shared_dependencies_sha256','not-a-digest'),
    ('annotations_sha256','e'*64),('raw_annotations_sha256','not-a-digest'),
    ('parent_owner_oid',16501),('parent_owner_bootstrap',True),('parent_has_triggers',False),
    ('new_row_count',True),('new_row_count',1),('unsupported_objects',True),('storage_distinct',False)])
def test_wrong_closure_retained_metadata_or_new_storage_never_passes(field,value):
    before,after=pair();after[field]=value
    with pytest.raises(ValueError):catalog.validate_delta(before,after)


def test_unbound_fields_and_catalog_builder_drift_fail_closed(monkeypatch):
    before,after=pair();after['unbound_metadata']='extra'
    with pytest.raises(ValueError):catalog.validate_delta(before,after)
    monkeypatch.setattr(catalog.probe,'CATALOG_SQL','unsupported catalog shape')
    with pytest.raises(ValueError):catalog.statement(before)
