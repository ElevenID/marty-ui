"""Bounded known-order continuation, with mocked SSH and active-run observations."""
import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_installer_startup_observation import startup_case, staged
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import installer_release as r
import installer_startup_continuation as continuation
import installer_candidate_dispatch as dispatch


def pending(case, next_poll=100010):
    installation='/home/installer/marty-install-'+case.target['installation_id']
    return dict(schema=continuation.SCHEMA,installation_id=case.target['installation_id'],outcome='enrollment_pending',
        application_started=False,installation_ready=False,
        continuation=[installation+'/marty-deploy','acme','continue','--install-dir',installation,'--docker-bin','/usr/bin/docker'],
        enrollment=dict(environment='production',cycle=0,sequence=8,stage='awaiting_order',account_url_recorded=True,
            order_url_recorded=True,order_outcome_unknown=False,candidate_admitted=False,next_attempt_at=None,failure=None,
            next_poll_at=next_poll,candidate_currently_valid='not_assessed',ordinary_phase_budget_reserved=False,
            initial_terminal_retry_at=None,initial_terminal_withdrawal_confirmed=False,activation_performed=False,
            installation_ready=False,automatic_renewal=False,public_reachability='not_assessed',boot_recovery_qualification='not_assessed'))


@pytest.fixture
def waiting(startup_case):
    c=startup_case
    output=c.root/'continuation';output.mkdir(mode=0o700)
    class Clock:
        wall=100005
        elapsed=10
        waits=[]
        def sleep(self,seconds):
            self.waits.append(seconds);self.wall+=seconds;self.elapsed+=seconds
    clock=Clock()
    class Client:
        reads=0
        on_read=None
        def request(self,method,path):
            assert method=='GET' and path.endswith('/actions/runs/99')
            self.reads+=1
            if self.on_read:self.on_read()
            return copy.deepcopy(c.active)
    client=Client();calls=[]
    def execute(argv,**kwargs):
        calls.append((argv,kwargs,clock.wall));clock.wall+=2;clock.elapsed+=2
        return r.encode(c.before)
    options=dict(pending_raw=r.encode(pending(c)),context=c.context,target=c.target,authorization=c.authorization,
        receipt=c.receipt,inventory=c.inventory,pins=c.pins,output=output,ledger=c.options['ledger'],
        ssh=c.options['ssh'],key=c.options['key'],known_hosts=c.options['known_hosts'],host=c.options['host'],
        port=c.options['port'],user=c.options['user'],home=c.options['home'],client=client,
        unchanged=lambda:None,execute=execute,clock=lambda:clock.wall,monotonic=lambda:clock.elapsed,sleep=clock.sleep)
    return c,clock,client,calls,options


def test_normal_async_issuance_continues_exact_retained_owner_and_obeys_both_retry_floors(waiting):
    c,clock,client,calls,options=waiting
    first=pending(c,100011);first['enrollment']['next_attempt_at']=100015
    options['pending_raw']=r.encode(first)
    def execute(argv,**kwargs):
        calls.append((argv,kwargs,clock.wall));clock.wall+=2;clock.elapsed+=2
        return r.encode(pending(c,100025)) if len(calls)==1 else r.encode(c.before)
    options['execute']=execute
    result=continuation.continue_pending(**options)
    assert result['status']=='startup_observed' and result['installation_ready'] is False
    assert [when for _,_,when in calls]==[100015,100025]
    assert all(0<delay<=5 for delay in clock.waits)
    assert client.reads>=4
    for argv,kwargs,_ in calls:
        remote=argv[-1]
        assert ' acme continue --install-dir /home/installer/marty-install-'+c.target['installation_id'] in remote
        assert 'install-candidate' not in remote and 'new-order' not in remote
        assert c.context['operator_sha256'] in remote and '/usr/bin/setpriv --no-new-privs --' in remote
        assert set(kwargs['env'])=={'HOME','PATH','LANG','LC_ALL'} and kwargs['limit']==65536 and kwargs['timeout']<=300
    assert (options['output']/'startup-continuation-0001-pending.json').exists()
    assert (options['output']/'startup-continuation-0002-observed.json').exists()


@pytest.mark.parametrize('mutation',['unknown-order','terminal','account-pending','candidate','replacement','blocking','scope','command',
    'foreign-operator','production-substitution','extra-field','wrong-boolean','future-retry'])
def test_unknown_terminal_or_unbound_pending_never_authorizes_an_automatic_call(waiting,mutation):
    c,clock,client,calls,options=waiting
    value=pending(c)
    if mutation=='unknown-order':value['enrollment']['order_outcome_unknown']=True
    elif mutation=='terminal':value['enrollment']['stage']='terminal'
    elif mutation=='account-pending':value['enrollment']['stage']='account_pending'
    elif mutation=='candidate':value['enrollment']['candidate_admitted']=True
    elif mutation=='replacement':value['outcome']='certificate_replacement_pending'
    elif mutation=='blocking':value['enrollment']['blocking_dependency']='acme_finalize_status_regression'
    elif mutation=='scope':value['installation_id']='11111111-1111-4111-8111-111111111111'
    elif mutation=='command':value['continuation'][2]='status'
    elif mutation=='foreign-operator':value['continuation'][0]='/tmp/arbitrary-program'
    elif mutation=='production-substitution':value['enrollment']['environment']='staging'
    elif mutation=='extra-field':value['force']=True
    elif mutation=='wrong-boolean':value['enrollment']['order_url_recorded']=1
    elif mutation=='future-retry':value['enrollment']['next_attempt_at']=200000
    options['pending_raw']=r.encode(value)
    with pytest.raises(ValueError):continuation.continue_pending(**options)
    assert calls==[] and not list(options['output'].iterdir())


@pytest.mark.parametrize('mutation',['grant-expired','expires-during-api','inactive-run','wrong-run','monotonic-deadline','clock-rollback'])
def test_original_grant_and_exact_active_invocation_are_rechecked_before_each_mutation(waiting,mutation):
    c,clock,client,calls,options=waiting
    if mutation=='grant-expired':clock.wall=r.decode(c.authorization)['expires_at']
    elif mutation=='expires-during-api':client.on_read=lambda:setattr(clock,'wall',r.decode(c.authorization)['expires_at'])
    elif mutation=='inactive-run':c.active.update(status='completed',conclusion='success')
    elif mutation=='wrong-run':c.active['run_attempt']+=1
    elif mutation=='clock-rollback':client.on_read=lambda:setattr(clock,'wall',99999)
    else:client.on_read=lambda:setattr(clock,'elapsed',clock.elapsed+1000)
    with pytest.raises(ValueError):continuation.continue_pending(**options)
    assert calls==[]


def test_lost_continue_response_retains_intent_and_never_replays_even_if_later_retry_requested(waiting):
    c,clock,client,calls,options=waiting
    def lost(argv,**kwargs):
        calls.append(argv);raise ValueError('simulated accepted continuation, response lost')
    options['execute']=lost
    with pytest.raises(ValueError):continuation.continue_pending(**options)
    assert len(calls)==1
    assert [path.name for path in options['output'].iterdir()]==['startup-continuation-0001-intent.json']
    with pytest.raises(FileExistsError):continuation.continue_pending(**options)
    assert len(calls)==1


def test_zero_exit_without_typed_native_success_does_not_authorize_more_mutations(waiting):
    _,_,_,calls,options=waiting
    def arbitrary(argv,**kwargs):calls.append(argv);return b'{"passed":true}\n'
    options['execute']=arbitrary
    with pytest.raises(ValueError):continuation.continue_pending(**options)
    assert len(calls)==1


def test_dispatch_preserves_typed_known_pending_without_claiming_startup(startup_case):
    c=startup_case;options=dict(c.options)
    options.update(clock=lambda:100005,verifier=c.verifier,
        run=lambda argv,**_:r.encode(pending(c)) if 'install-candidate' in argv[-1] else b'')
    result=dispatch.dispatch(**options)
    assert result['schema']=='elevenid.installer-candidate-dispatch-result/v2'
    assert result['completion']=='acme_pending' and result['installation_ready'] is result['acceptance_report'] is False
    retained=options['ledger'].parent/result['native_startup_observation_name']
    assert retained.read_bytes()==r.encode(pending(c))
    assert result['native_startup_observation_sha256']==r.digest(retained.read_bytes())
