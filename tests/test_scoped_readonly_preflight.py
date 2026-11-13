"""Closed read-only preflight controls; never execute a subprocess or journal."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from scoped_linux_journal import LinuxBuildJournal
from scoped_d12_native_execution import D12CurrentExecution
from scoped_native_database import D12CurrentDatabasePhase, CURRENT_TEN_TENANT_READ_ONLY_SQL


def phase():
    value=D12CurrentDatabasePhase.__new__(D12CurrentDatabasePhase)
    value.read_only_preflight=True
    value.rollout_profile='d05-membership-current-functional'
    value.identity={'containerId':'a'*64}
    value.tenant_id='00000000-0000-0000-0000-000000000001'
    return value


def tenant_args(value):
    return ['docker','exec','-i',value.identity['containerId'],'psql','-X','-qAt','-U','postgres',
            '-d','marty','-v','ON_ERROR_STOP=1','-v','tenant='+value.tenant_id,'-f','-']


def test_preflight_mode_denies_apply_and_any_durable_record_before_accessing_journal():
    journal=LinuxBuildJournal.__new__(LinuxBuildJournal);journal.read_only=True
    value=D12CurrentExecution({}, {'runId':'run','rolloutProfile':'d05-membership-current-functional'},
                              journal,read_only_preflight=True)
    with pytest.raises(ValueError,match='D12_READ_ONLY_PREFLIGHT_NO_APPLY'):value.run()
    with pytest.raises(ValueError,match='D12_READ_ONLY_PREFLIGHT_NO_INTENT'):value.record('APPLY_INTENT_DURABLE')
    with pytest.raises(ValueError,match='D12_READ_ONLY_PREFLIGHT_NO_INTENT'):
        value.command(None,'STOP_gateway',['docker','stop','a'*64])


@pytest.mark.parametrize('operation',['exclusive','state','initialize'])
def test_readonly_typed_journal_refuses_before_request_or_helper_creation(operation):
    journal=LinuxBuildJournal.__new__(LinuxBuildJournal);journal.read_only=True
    with pytest.raises(ValueError,match='JOURNAL_READ_ONLY_OPERATION_REFUSED'):
        journal.invoke(operation,'build-apply-intent.json',{})


def test_only_exact_identity_and_selected_tenant_transaction_are_admitted():
    value=phase()
    value._require_read_only_preflight_command(['docker','info','--format','{{.ID}}'],None)
    value._require_read_only_preflight_command(['docker','inspect','a'*64],None)
    value._require_read_only_preflight_command(tenant_args(value),CURRENT_TEN_TENANT_READ_ONLY_SQL)


@pytest.mark.parametrize('change',['start','stop','create','rm','wrong-cid','wrong-tenant','extra-sql','write-sql'])
def test_mutating_or_unbound_commands_are_rejected_before_transport(change):
    value=phase();args=tenant_args(value);stdin=CURRENT_TEN_TENANT_READ_ONLY_SQL
    if change in ['start','stop','create','rm']:args=['docker',change,'a'*64];stdin=None
    if change=='wrong-cid':args[3]='b'*64
    if change=='wrong-tenant':args[-3]='tenant=00000000-0000-0000-0000-000000000002'
    if change=='extra-sql':stdin+=b'SELECT 1;'
    if change=='write-sql':stdin=b'CREATE TABLE forbidden(x int);'
    with pytest.raises(ValueError,match='D12_READ_ONLY_PREFLIGHT_COMMAND_REFUSED'):value.result(args,input=stdin)


def test_readonly_database_cannot_persist_or_render_mutation_sql():
    value=phase()
    with pytest.raises(ValueError,match='D12_READ_ONLY_PREFLIGHT_NO_DATABASE_INTENT'):value.persist()
    with pytest.raises(ValueError,match='D12_READ_ONLY_PREFLIGHT_METADATA_MODE_REFUSED'):
        value.node('render',name='passport-beta-fence-install.sql')


def test_default_executor_remains_effect_mode_and_readonly_mode_requires_readonly_store():
    inputs={'runId':'run','rolloutProfile':'d05-membership-current-functional'}
    assert D12CurrentExecution({},inputs,object()).read_only_preflight is False
    with pytest.raises(ValueError,match='D12_READ_ONLY_OPERATION_JOURNAL_REQUIRED'):
        D12CurrentExecution({},inputs,object(),read_only_preflight=True)
