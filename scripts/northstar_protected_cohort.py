"""Closed Northstar census. Global IDs remain raw; unrelated churn is recorded."""
import hashlib
import json
import re
import subprocess
from pathlib import Path
import yaml

SCHEMA = 'marty.northstar-protected-cohort/v1'
CID = re.compile(r'^[a-f0-9]{64}$')
CENSUS_LIMIT = 2 * 1024 * 1024
MAX_ROWS = 2048
CENSUS_FORMAT = '{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Config.Labels}},"Networks":{{json .NetworkSettings.Networks}},"Generation":{"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}},"OOMKilled":{{json .State.OOMKilled}},"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}}}'
STOCK_NAMES = {'/marty-canvas-oss-web','/marty-canvas-oss-jobs','/marty-canvas-oss-edge'}
PAUSE_SOURCE_SHA256 = '0c89e8b9bac629901b921eba6b597cdbb9262e4c5fd45b204fb143ed2cff37cc'
PAUSE_CONTROLLER_SHA256 = '085601273459d4f1222a7d0ffe86762296309b38029492e8e07dd6d89e80bf03'


def require(ok, code):
    if not ok:
        raise AssertionError(code)


def parse_census(raw, ids):
    require(type(raw) is bytes and len(raw) <= CENSUS_LIMIT, 'CENSUS_OVERSIZE')
    require(len(ids) <= MAX_ROWS and all(CID.fullmatch(cid) for cid in ids), 'CENSUS_IDS_INVALID')
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == len(ids), 'CENSUS_INCOMPLETE')
    found = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'Id','Name','Labels','Networks','Generation'}, 'CENSUS_ROW_SCHEMA')
        cid = row['Id']
        require(type(cid) is str and CID.fullmatch(cid) and cid not in found, 'CENSUS_DUPLICATE_ID')
        require(type(row['Name']) is str and row['Name'].startswith('/'), 'CENSUS_NAME_SCHEMA')
        require(row['Labels'] is None or type(row['Labels']) is dict and all(type(k) is str and type(v) is str for k,v in row['Labels'].items()), 'CENSUS_LABEL_SCHEMA')
        generation=row['Generation']
        require(type(generation) is dict and set(generation)=={'Running','Paused','Restarting','OOMKilled','Pid','StartedAt'}
                and all(type(generation[key]) is bool for key in ('Running','Paused','Restarting','OOMKilled'))
                and type(generation['Pid']) is int and generation['Pid']>=0
                and type(generation['StartedAt']) is str and bool(generation['StartedAt']), 'CENSUS_GENERATION_SCHEMA')
        require(type(row['Networks']) is dict, 'CENSUS_NETWORK_SCHEMA')
        for name, network in row['Networks'].items():
            require(type(name) is str and type(network) is dict and type(network.get('NetworkID')) is str
                    and (network['NetworkID'] == '' or CID.fullmatch(network['NetworkID'])), 'CENSUS_NETWORK_SCHEMA')
        found[cid] = row
    require(set(found) == set(ids), 'CENSUS_IDS_CHANGED')
    return found


def collect(transport, stem):
    lines = transport.observe_lines(['ps','-aq','--no-trunc'], stem)
    require(len(lines) == len(set(lines)), 'CENSUS_DUPLICATE_ID')
    ids = set(lines)
    require(ids and len(ids) <= MAX_ROWS and all(CID.fullmatch(cid) for cid in ids), 'CENSUS_IDS_INVALID')
    # Only this typed, ENV-free census gets a larger output budget. The
    # transport retains its stderr bound, timeout, intents and exit checks.
    output = transport.command(['inspect','--format',CENSUS_FORMAT,*sorted(ids)], stem+'-classification', limit=CENSUS_LIMIT)
    with Path(output).open('rb') as stream:
        raw=stream.read(CENSUS_LIMIT+1)
    return ids, parse_census(raw, ids)


def native_projection(config, core):
    """Select only transport provenance from the actual fixture input, never its authority flags."""
    selected=config['protectedCohort']['nativeTransport']
    require(set(selected)=={'fixtureInput','recorderRepository'},'SCOPE_NATIVE_BINDING_FIELDS')
    fixture=core.load(selected['fixtureInput']);receipt=core.load(config['fixtureAuthority'])
    require(fixture['runId']==receipt['runId']==config['runId']
            and fixture['driverRevision']==receipt['driverSource']
            and fixture['recorderRevision']==receipt['recorderSource']==config['currentSourceAuthority']['recorder'],
            'SCOPE_NATIVE_FIXTURE_SOURCE_CHANGED')
    for name in ('profile','observation'):
        expected=config['runtimeAuthority'][name]
        require(fixture[name]['sha256']==expected['sha256']
                and core.read_ref(fixture[name])==core.read_ref(expected),'SCOPE_NATIVE_RUNTIME_CHANGED')
    for name in ('dockerTransport','dockerCanary'):
        core.read_ref(fixture[name])
    descriptor=core.load(fixture['dockerTransport'])
    require(descriptor['engineId']==config['engineId'],'SCOPE_NATIVE_ENGINE_CHANGED')
    repository=selected['recorderRepository'];revision=fixture['recorderRevision']
    for relative in ('src/externalQualification.js','src/canvasDockerTransport.js'):
        require((Path(repository)/relative).read_bytes().replace(b'\r\n',b'\n')
                ==core.git_blob(repository,revision,relative).replace(b'\r\n',b'\n'),'SCOPE_NATIVE_SOURCE_CHANGED')
    return {'recorder':{'repository':repository,'revision':revision},
            'dockerTransport':fixture['dockerTransport'],'dockerCanary':fixture['dockerCanary'],'engineId':config['engineId']}


def runtime_authority(config, core, *, live):
    scope = config['protectedCohort']
    require(scope['schema'] == SCHEMA and scope['profile'] == config['runtimeAuthority']['profile'], 'SCOPE_PROFILE_CHANGED')
    repo, revision = config['sourceRepository'], config['currentSourceAuthority']['ui']
    bridge = Path(repo)/'scripts/northstar_runtime_scope.cjs'
    for relative in ('scripts/northstar_runtime_scope.cjs','scripts/northstar_protected_cohort.py',
                     'tests/scripts/functional-debug-runtime.js','tests/scripts/beta-resource-runtime.js',
                     'tests/scripts/beta-retained-runtime-resume.js'):
        require((Path(repo)/relative).read_bytes().replace(b'\r\n',b'\n') == core.git_blob(repo, revision, relative).replace(b'\r\n',b'\n'), 'SCOPE_SOURCE_NOT_COMMITTED')
    require(Path(__file__).read_bytes() == (Path(repo)/'scripts/northstar_protected_cohort.py').read_bytes(), 'SCOPE_HELPER_CHANGED')
    node = core.read_executable_ref(config['nodeExecutable'])
    request = {'profile':scope['profile'],'verifyLive':live,**native_projection(config,core)}
    completed = subprocess.run([str(node),str(bridge)],input=json.dumps(request).encode(),
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=600,check=False)
    require(len(completed.stdout) <= 32768, 'SCOPE_RUNTIME_AUTHORITY_OVERSIZE')
    if completed.returncode != 0:
        code='SCOPE_RUNTIME_AUTHORITY_FAILED'
        bridge_class='Error'
        try:
            failure=json.loads(completed.stdout)
            if (failure.get('schema')=='marty.northstar-runtime-scope-failure/v1'
                    and re.fullmatch(r'[A-Z][A-Z0-9_]{1,79}',failure.get('code',''))):
                code=failure['code']
                if failure.get('errorClass') in ('Error','AssertionError','TypeError','RangeError','SyntaxError'):
                    bridge_class=failure['errorClass']
        except (ValueError,TypeError,AttributeError):
            pass
        error=ValueError(code)
        error.scopeFailure={'errorClass':bridge_class,'code':code,'exitCode':completed.returncode,
                            'stdoutBytes':len(completed.stdout)}
        raise error
    result = json.loads(completed.stdout)
    require(set(result) == {'schema','profileSha256','rows','off'} and result['schema'] == 'marty.northstar-resource-scope/v1'
            and result['profileSha256'] == scope['profile']['sha256'], 'SCOPE_AUTHORITY_SCHEMA')
    rows=result['rows']
    require(len(rows)==28 and len({r['role'] for r in rows})==28 and len({r['cid'] for r in rows})==28
            and all(set(r)=={'role','cid'} and CID.fullmatch(r['cid']) for r in rows), 'SCOPE_AUTHORITY_ROLES')
    off=result['off']
    require(set(off)=={'snapshot','rows'} and len(off['rows'])==14,'SCOPE_OFF_AUTHORITY_SCHEMA')
    before=core.load(off['snapshot'])
    stopped={}
    roles={r['role']:r['cid'] for r in rows}
    for r in off['rows']:
        require(set(r)=={'role','cid'} and CID.fullmatch(r['cid']) and r['role'] not in roles
                and r['cid'] not in stopped and r['cid'] not in roles.values(),'SCOPE_OFF_AUTHORITY_COLLISION')
        row=before[r['cid']];labels=row['Config']['Labels'];state=row['State']
        require(row['Id']==r['cid'] and labels.get('com.docker.compose.project')=='elevenid-beta'
                and labels.get('com.docker.compose.service')==r['role']
                and state['Running'] is False and state['Pid']==0
                and state['Paused'] is False and state['Restarting'] is False and state['OOMKilled'] is False,
                'SCOPE_OFF_PREIMAGE_CHANGED')
        roles[r['role']]=r['cid'];stopped[r['cid']]=row
    require(len(roles)==42 and len(stopped)==14,'SCOPE_OFF_AUTHORITY_COUNT')
    return RuntimeRoles(roles,stopped=stopped)


class RuntimeRoles(dict):
    def __init__(self, roles, *, stopped):
        super().__init__(roles)
        self.stopped=stopped


def spec(row):
    value={key:row[key] for key in ('Config','HostConfig','Mounts')}
    value['Mounts']=sorted(value['Mounts'],key=lambda m:m['Destination'])
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def pause_authority(scope, core):
    from scoped_northstar_fixture import _terminal_job
    proof=scope['stockPause']
    require(set(proof)=={'operator','controller','request','job'},'SCOPE_PAUSE_REFS_CHANGED')
    require(proof['operator']['sha256']==PAUSE_SOURCE_SHA256
            and proof['controller']['sha256']==PAUSE_CONTROLLER_SHA256,'SCOPE_PAUSE_SOURCE_CHANGED')
    operator,controller=core.read_ref(proof['operator']),core.read_ref(proof['controller'])
    request,job=core.load(proof['request']),core.load(proof['job'])
    parent=operator.parent
    require(operator.name=='operate.py' and controller==parent/'run-contained.cjs'
            and core.read_ref(scope['stockBefore'])==parent/'before.json'
            and core.read_ref(scope['stockPaused'])==parent/'paused.json'
            and Path(request['cwd'])==parent
            and len(request['command'])==4 and request['command'][1]=='-B'
            and Path(request['command'][2])==operator and request['command'][3]=='pause'
            and Path(request['receiptFile'])==core.read_ref(proof['job'])
            and core.read_ref(proof['request']).parent==parent
            and core.read_ref(proof['job']).parent==parent
            and request['schema']=='marty.windows-job-request/v1'
            and job['schema']=='marty.windows-job-result/v1','SCOPE_PAUSE_JOB_CHANGED')
    _terminal_job(request,job,success=True)


def stock_model_peers(config, core):
    scope=config['protectedCohort']
    before=core.load(scope['stockBefore'])
    targets={cid:before['rows'][cid] for cid in before['targets']}
    require(len(targets)==3 and {row['name'] for row in targets.values()}==STOCK_NAMES, 'SCOPE_STOCK_TARGETS_CHANGED')
    # Parse the same tracked Compose source used by repository packaging.
    # Explicit container_name alone omits declared profile/one-shot peers.
    model=yaml.safe_load(core.git_blob(config['sourceRepository'],config['currentSourceAuthority']['ui'],
                                       'docker-compose.canvas-oss-acceptance.yml'))
    services=model['services']
    require(type(services) is dict and all(type(role) is str and type(service) is dict for role,service in services.items()),
            'SCOPE_STOCK_MODEL_CHANGED')
    named={role:'/'+service['container_name'] for role,service in services.items() if 'container_name' in service}
    names=set(named.values())
    require(STOCK_NAMES <= names and len(names)==6,'SCOPE_STOCK_MODEL_CHANGED')
    stock={cid:row for cid,row in before['rows'].items() if row['name'] in names}
    require(len(stock)==6 and {row['name'] for row in stock.values()}==names,'SCOPE_STOCK_PEERS_MISSING')
    anchor=core.load(scope['stockModelAnchor'])
    require(type(anchor) is list and len(anchor)==1,'SCOPE_STOCK_ANCHOR_SCHEMA')
    anchor=anchor[0];expected=before['rows'].get(anchor['Id'])
    require(anchor['Id'] in targets and expected is not None and anchor['Name']==expected['name']
            and anchor['Image']==expected['image'] and spec(anchor)==expected['spec'], 'SCOPE_STOCK_ANCHOR_CHANGED')
    project=anchor['Config']['Labels'].get('com.docker.compose.project')
    require(type(project) is str and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}',project),
            'SCOPE_STOCK_PROJECT_REQUIRED')
    stock_roles={cid:next(role for role,name in named.items() if name==row['name']) for cid,row in stock.items()}
    require(anchor['Config']['Labels'].get('com.docker.compose.service')==stock_roles[anchor['Id']],
            'SCOPE_STOCK_ANCHOR_SERVICE_CHANGED')
    for role,service in services.items():
        if role in named:continue
        require(type(service.get('profiles')) is list and service['profiles'],'SCOPE_STOCK_PROFILE_REQUIRED')
        pattern=re.compile(r'^/'+re.escape(project)+'-'+re.escape(role)+r'-[1-9][0-9]*$')
        for cid,row in before['rows'].items():
            if pattern.fullmatch(row['name']):
                require(cid not in stock and row['live']['Running'] is False and row['live']['Pid']==0,
                        'SCOPE_STOCK_PROFILE_NOT_STOPPED')
                stock[cid]=row;stock_roles[cid]=role
    paused=set(targets)
    return stock,stock_roles,project,paused


class ProtectedCohort:
    def __init__(self, config, core, identities):
        self.config, self.core = config, core
        scope=config['protectedCohort']
        require(set(scope)=={'schema','profile','stockBefore','stockPaused','stockPause','nativeTransport','stockModelAnchor'}, 'SCOPE_FIELDS_CHANGED')
        pause_authority(scope,core)
        self.roles=runtime_authority(config,core,live=False)
        self.stopped=self.roles.stopped
        require(len(self.roles)==42 and len(self.stopped)==14,'SCOPE_OFF_AUTHORITY_COUNT')
        require(all(self.roles.get(role)==row['containerId'] for role,row in identities.items()), 'SCOPE_RETAINED22_CHANGED')
        paused=core.load(scope['stockPaused'])
        require(paused['state']=='ONLY_STOCK_CANVAS_WEB_JOBS_EDGE_STOPPED'
                and paused['allOtherRowsUnchanged'] is True and paused['specsUnchanged'] is True, 'SCOPE_STOCK_PAUSE_NOT_VERIFIED')
        self.stock,self.stock_roles,self.stock_project,self.paused=stock_model_peers(config,core)
        self.fixed=set(self.roles.values())|set(self.stock)
        require(len(self.fixed)==len(self.roles)+len(self.stock), 'SCOPE_ID_COLLISION')
        self.initial=None
        self.observations=[]

    def snapshot(self, transport, stem, target_ids):
        require(self.roles==runtime_authority(self.config,self.core,live=True), 'SCOPE_RUNTIME_CHANGED')
        ids,rows=collect(transport,stem)
        required=self.fixed|set(target_ids)
        require(required<=ids, 'SCOPE_PROTECTED_ID_MISSING')
        for cid,expected in self.stopped.items():
            actual=transport.old_guard(expected,running=False)
            require(all(actual['State'][key]==expected['State'][key] for key in
                    ('Running','Paused','Restarting','OOMKilled','Pid','StartedAt','FinishedAt'))
                    and actual['NetworkSettings']==expected['NetworkSettings'],'SCOPE_STOPPED_ROLE_CHANGED')
        for cid,expected in self.stock.items():
            actual=transport.inspect(cid)
            require(actual['Id']==cid and actual['Name']==expected['name'] and actual['Image']==expected['image']
                    and spec(actual)==expected['spec']
                    and actual['State']['Running'] is (False if cid in self.paused else expected['live']['Running'])
                    and actual['State']['Pid']==(0 if cid in self.paused else expected['live']['Pid'])
                    and actual['State']['StartedAt']==expected['live']['StartedAt']
                    and actual['State']['Paused'] is expected['live']['Paused']
                    and actual['State']['Restarting'] is expected['live']['Restarting']
                    and actual['State']['OOMKilled'] is False, 'SCOPE_STOCK_CHANGED')
        self.classify(rows,required)
        fixed={cid:rows[cid] for cid in self.fixed}
        if self.initial is None: self.initial=fixed
        require(fixed==self.initial,'SCOPE_PROTECTED_METADATA_CHANGED')
        self.observations.append({'schema':SCHEMA,'profileSha256':self.config['protectedCohort']['profile']['sha256'],
            'allIds':sorted(ids),'protectedIds':sorted(required),'outsideScopeIds':sorted(ids-required),
            'classification':rows,'globalUnchangedClaimed':False})
        return ids

    def classify(self, rows, required):
        for role,cid in self.roles.items():
            labels=rows[cid]['Labels'] or {}
            require(labels.get('com.docker.compose.service')==role
                    and labels.get('com.docker.compose.project')==('elevenid-beta-ui' if role=='ui-prod' else 'elevenid-beta'),
                    'SCOPE_MANAGED_ROLE_LABEL_CHANGED')
        require(all(rows[cid]['Name']==expected['name'] for cid,expected in self.stock.items()),'SCOPE_STOCK_NAME_CHANGED')
        require(all((rows[cid]['Labels'] or {}).get('com.docker.compose.project')==self.stock_project
                    and (rows[cid]['Labels'] or {}).get('com.docker.compose.service')==self.stock_roles[cid]
                    for cid in self.stock),'SCOPE_STOCK_SERVICE_CHANGED')
        protected={cid:rows[cid] for cid in required}
        projects={row['Labels']['com.docker.compose.project'] for row in protected.values()
                  if (row['Labels'] or {}).get('com.docker.compose.project')}
        # Docker's shared built-ins are not owned project networks. Exact role
        # network/config guards still apply to protected rows using a built-in.
        names={name for row in protected.values() for name in row['Networks'] if name not in ('none','host','bridge')}
        networks={n['NetworkID'] for row in protected.values() for name,n in row['Networks'].items()
                  if name in names and n['NetworkID']}
        for cid,row in rows.items():
            if cid in required: continue
            require((row['Labels'] or {}).get('com.docker.compose.project') not in projects
                    and not names.intersection(row['Networks'])
                    and not networks.intersection(n['NetworkID'] for n in row['Networks'].values()), 'SCOPE_MANAGED_COLLISION')
    def assert_cohort(self, actual, expected, code, *, phase, known_ids):
        owned=self.fixed|set(known_ids)
        require((set(actual)&owned)==(set(expected)&owned),code)
        require(self.observations and set(self.observations[-1]['allIds'])==set(actual),'SCOPE_SNAPSHOT_REQUIRED')

    def bind_previous(self, proof):
        require(proof['schema']==SCHEMA
                and proof['profileSha256']==self.config['protectedCohort']['profile']['sha256']
                and proof['globalUnchangedClaimed'] is False and proof['observations'],'SCOPE_PREVIOUS_PROOF_CHANGED')
        previous=proof['observations'][-1]
        targets=set(previous['protectedIds'])-self.fixed
        require(len(targets)==1,'SCOPE_PREVIOUS_TARGET_CHANGED')
        self.validate_proof(proof,next(iter(targets)),minimum_observations=1)
        require(self.fixed<=set(previous['protectedIds']),'SCOPE_PREVIOUS_PROOF_CHANGED')
        self.initial={cid:previous['classification'][cid] for cid in self.fixed}

    def proof(self):
        require(self.observations,'SCOPE_SNAPSHOT_REQUIRED')
        return {'schema':SCHEMA,'profileSha256':self.config['protectedCohort']['profile']['sha256'],
                'observations':list(self.observations),'globalUnchangedClaimed':False}

    def validate_proof(self, proof, target, *, minimum_observations=2):
        require(set(proof)=={'schema','profileSha256','observations','globalUnchangedClaimed'}
                and proof['schema']==SCHEMA and proof['profileSha256']==self.config['protectedCohort']['profile']['sha256']
                and proof['globalUnchangedClaimed'] is False and len(proof['observations'])>=minimum_observations,'SCOPE_PROOF_SCHEMA')
        for observed in proof['observations']:
            ids=observed['allIds']
            require(len(ids)==len(set(ids)) and observed['schema']==SCHEMA
                    and observed['profileSha256']==proof['profileSha256'] and observed['globalUnchangedClaimed'] is False,
                    'SCOPE_PROOF_SCHEMA')
            rows=parse_census(b'\n'.join(json.dumps(row).encode() for row in observed['classification'].values()),set(ids))
            require(set(observed['classification'])==set(ids)
                    and all(cid==row['Id'] for cid,row in observed['classification'].items()),'SCOPE_PROOF_CLASSIFICATION')
            protected=set(observed['protectedIds'])
            require(len(protected)==len(observed['protectedIds']) and self.fixed<=protected
                    and protected<=set(ids) and len(protected)==len(self.fixed)+1
                    and set(observed['outsideScopeIds'])==set(ids)-protected,'SCOPE_PROOF_MEMBERSHIP')
            self.classify(rows,protected)
        require(set(proof['observations'][-1]['protectedIds'])==self.fixed|{target},'SCOPE_PROOF_TARGET_CHANGED')
        first=proof['observations'][0]['classification']
        require(all(all(observed['classification'][cid]==first[cid] for cid in self.fixed)
                    for observed in proof['observations']),'SCOPE_PROOF_PROTECTED_DRIFT')
