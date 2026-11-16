"""Bounded continuation of a known pending ACME order under the original grant.

This invokes only the exact retained operator's existing `acme continue` owner.
It never retries installation, authorizes a new order itself, infers success
from exit codes, or continues unknown/terminal outcomes. The customer can still
use the explicit retained local operation after controller authority expires.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import shlex
import tempfile
import time

import installer_acceptance_startup as startup
import installer_candidate_dispatch as dispatch
import installer_candidate_rendezvous as transport
import installer_release as r
import installer_startup_observation as observation
from installer_candidate_authorize import write_exclusive

SCHEMA = 'elevenid.installer-acme-installation/v1'
MAX_SECONDS = 900
MAX_CALLS = 180
KNOWN_ORDER_STAGES = {'order_bound','publication_pending','challenges_published','challenge_ready_pending',
                      'awaiting_order','finalize_pending','certificate_pending'}
ENROLMENT_FIELDS = {'environment','cycle','sequence','stage','account_url_recorded','order_url_recorded',
    'order_outcome_unknown','candidate_admitted','next_attempt_at','failure','next_poll_at','candidate_currently_valid',
    'ordinary_phase_budget_reserved','initial_terminal_retry_at','initial_terminal_withdrawal_confirmed',
    'activation_performed','installation_ready','automatic_renewal','public_reachability','boot_recovery_qualification'}


def pending(raw, *, context, target, installation, now):
    value=r.decode(raw)
    r.exact(value,{'schema','installation_id','outcome','enrollment','application_started','installation_ready','continuation'},
            'typed ACME startup pending result')
    hosting=context.get('hosting')
    r.require(type(hosting) is dict and hosting['certificate_source']=='acme'
        and hosting['acme_environment']=='production' and hosting['public_entry_origin'] is not None
        and hosting['staging_trust'] is None,'pending startup needs signed production IP hosting')
    r.require(value['schema']==SCHEMA and value['installation_id']==target['installation_id']
        and value['outcome']=='enrollment_pending' and value['application_started'] is False
        and value['installation_ready'] is False and value['continuation']==[
            installation+'/marty-deploy','acme','continue','--install-dir',installation,'--docker-bin','/usr/bin/docker'],
        'pending startup scope or fixed continuation differs')
    state=r.exact(value['enrollment'],ENROLMENT_FIELDS,'known pending ACME owner')
    r.require(state['environment']=='production' and state['stage'] in KNOWN_ORDER_STAGES
        and state['account_url_recorded'] is True and state['order_url_recorded'] is True
        and all(state[key] is False for key in ('order_outcome_unknown','candidate_admitted','ordinary_phase_budget_reserved',
            'initial_terminal_withdrawal_confirmed','activation_performed','installation_ready','automatic_renewal'))
        and state['initial_terminal_retry_at'] is None and state['candidate_currently_valid']=='not_assessed'
        and state['public_reachability']=='not_assessed' and state['boot_recovery_qualification']=='not_assessed',
        'ACME continuation is unknown, terminal, replaced or outside ordinary pending work')
    observation.integer(state['cycle']);observation.integer(state['sequence'])
    r.require(state['failure'] is None or type(state['failure']) is str and 0<len(state['failure'])<=96
        and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in state['failure']), 'pending failure code differs')
    deadlines=[]
    for name in ('next_poll_at','next_attempt_at'):
        if state[name] is not None:deadlines.append(observation.integer(state[name]))
    return value,max([now+5,*deadlines])


def continue_pending(*, pending_raw, context, target, authorization, receipt, inventory, pins,
                     output, ledger, ssh, key, known_hosts, host, port, user, home,
                     client, unchanged, execute, clock=time.time, monotonic=time.monotonic, sleep=time.sleep):
    installation=home+'/marty-install-'+target['installation_id']
    # Validate the same fixed guest-account/path grammar as initial dispatch.
    r.require(home=='/home/'+user and user!='root' and dispatch.re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',user),
              'startup continuation account differs')
    raw=pending_raw
    _,next_at=pending(raw,context=context,target=target,installation=installation,now=int(clock()))
    deadline=monotonic()+MAX_SECONDS
    parent=dispatch._directory(ledger.parent)
    operator=installation+'/marty-deploy'
    remote=('set -eu; PATH=/usr/bin:/bin; export PATH; test "$(id -un)" = '+shlex.quote(user)+'; '
        'printf "%s  %s\\n" '+shlex.quote(context['operator_sha256'])+' '+shlex.quote(operator)
        +' | /usr/bin/sha256sum --check --status --strict; exec env -i HOME='+shlex.quote(home)
        +' PATH=/usr/bin:/bin /usr/bin/setpriv --no-new-privs -- '+shlex.quote(operator)
        +' acme continue --install-dir '+shlex.quote(installation)+' --docker-bin /usr/bin/docker')

    def admitted():
        unchanged();dispatch.registry_unchanged(parent,ledger.parent)
        r.require(monotonic()<deadline,'startup continuation elapsed bound exceeded')
        now=int(clock())
        grant=r.bind_controller_consumption(receipt,authorization,inventory,expected=context,
            expected_engine=target['engine_id'],now=now)
        r.require(all(grant[k]==target[k] for k in dispatch.TARGET_FIELDS),'startup continuation target differs')
        observation.authority(context=context,target=target,authorization=authorization,receipt=receipt,
                              inventory=inventory,pins=pins,now=now)
        startup.validate_active_run(client.request('GET',transport.REPO+'/actions/runs/'+str(context['run_id'])),context)
        unchanged();dispatch.registry_unchanged(parent,ledger.parent)
        fresh=int(clock())
        r.require(monotonic()<deadline,'startup continuation elapsed bound exceeded')
        r.bind_controller_consumption(receipt,authorization,inventory,expected=context,
                                      expected_engine=target['engine_id'],now=fresh)
        return fresh

    try:
        fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for index in range(1,MAX_CALLS+1):
            now=admitted()
            expires=r.decode(authorization)['expires_at']
            r.require(next_at<expires and next_at-now<deadline-monotonic(),
                      'native pending delay exceeds original signed controller window')
            while int(clock())<next_at:
                r.require(monotonic()<deadline and int(clock())<expires,'startup continuation wait expired')
                sleep(min(5,max(0,next_at-int(clock())),max(0,deadline-monotonic())))
            now=admitted()
            name=f'startup-continuation-{index:04}'
            intent=dict(schema='elevenid.installer-startup-continuation/v1',installation_id=target['installation_id'],
                engine_id=target['engine_id'],context_sha256=r.candidate_context_sha256(context),
                authorization_sha256=r.digest(authorization),controller_consumption_sha256=r.digest(receipt),
                prior_pending_sha256=r.digest(raw),ordinal=index,invoked_at=now,grant_expires_at=expires,
                command='retained-acme-continue',installation_ready=False)
            write_exclusive(output/(name+'-intent.json'),r.encode(intent))
            # The fixed read-only gate is repeated after the durable intent and
            # immediately before the sole remote mutation. Any lost response
            # leaves the intent and stops; this loop never retries uncertainty.
            admitted()
            with tempfile.TemporaryDirectory(prefix='marty-startup-continue-') as private:
                raw=execute([str(ssh),*dispatch.ssh_options(key,known_hosts,port),'-T',user+'@'+host,remote],
                    env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),
                    timeout=max(1,min(300,int(deadline-monotonic()))),limit=65536)
            unchanged();dispatch.registry_unchanged(parent,ledger.parent)
            r.require(monotonic()<deadline,'startup continuation elapsed bound exceeded')
            value=r.decode(raw)
            if value.get('schema')==observation.NATIVE_SCHEMA:
                result=observation.native(raw,context=context,target=target,authorization=authorization,receipt=receipt,
                    inventory=inventory,pins=pins,observed_at=int(clock()))
                write_exclusive(output/(name+'-observed.json'),raw)
                return result
            _,next_at=pending(raw,context=context,target=target,installation=installation,now=int(clock()))
            write_exclusive(output/(name+'-pending.json'),raw)
        raise ValueError('startup continuation invocation bound exceeded')
    finally:
        os.close(parent)
