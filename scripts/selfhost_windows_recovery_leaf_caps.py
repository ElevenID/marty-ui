"""One explicit cap-only continuation; original failed receipts stay immutable.

Only a stopped Keycloak assembler with a fully assembled but unbounded leaf
generation is eligible. No producer replay, key/CA replacement, activation,
guard removal, or retry after the new durable intent is admitted here.
"""

import hashlib
import re
from pathlib import Path

import selfhost_windows_selection as selection

require = selection.require
PREFIX = "cap-reconciliation."
PHASES = ("helper", "export", "materialize", "candidate")
CAP_RECEIPTS = frozenset(
    {PREFIX + "intent.json", PREFIX + "helper.json"}
    | {
        PREFIX + phase + "." + event + ".json"
        for phase in PHASES
        for event in ("started", "completed")
    }
)


def receipt_names(names):
    """Closed alternatives for ordinary or separately reconciled stage proofs."""
    from selfhost_windows_staging_recovery import RECOVERY_RECEIPTS

    return set(names) in (set(RECOVERY_RECEIPTS), set(RECOVERY_RECEIPTS) | CAP_RECEIPTS)


def partial_receipts(raws, project, cycle, helper_image, services_image):
    from selfhost_windows_staging_recovery import RECOVERY_RECEIPTS

    require(set(raws) == RECOVERY_RECEIPTS and re.fullmatch(r"[0-9a-f]{32}", cycle))
    complete = {
        phase + "." + event + ".json"
        for phase in ("authority", "prepare", "tls")
        for event in ("started", "completed")
    } | {"keycloak.started.json"}
    helper_names = {"prepare.helper.json", "tls.created.json", "tls.helper.json"}
    helpers = {}
    for name, raw in raws.items():
        require(type(raw) is bytes)
        if name not in complete | helper_names:
            require(raw == b"")
            continue
        phase, event, _ = name.split(".")
        item = selection.decode(raw)
        require(
            raw == selection.packed(item)
            and set(item) == {"phase", "event", "metadata"}
            and (item["phase"], item["event"]) == (phase, event)
        )
        metadata = item["metadata"]
        if name in complete:
            require(metadata == {})
        else:
            require(
                type(metadata) is dict
                and set(metadata) == {"id", "name", "image"}
                and type(metadata["id"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", metadata["id"])
                and metadata["name"] == project + "-renew-" + phase + "-" + cycle
                and metadata["image"]
                == (services_image if phase == "tls" else helper_image)
            )
            helpers[name] = metadata
    require(
        helpers["tls.created.json"] == helpers["tls.helper.json"]
        and helpers["prepare.helper.json"]["id"] != helpers["tls.helper.json"]["id"]
    )
    return {name: selection.digest(raw) for name, raw in raws.items()}, helpers


def helper_proof(item, config, cycle, *, reconciled):
    import selfhost_windows_renewal_native as native

    phase = "cap-reconcile" if reconciled else "keycloak"
    expected = config["project"] + "-renew-" + phase + "-" + cycle
    state = item["State"]
    host = item["HostConfig"]
    cfg = item["Config"]
    require(
        re.fullmatch(r"[0-9a-f]{64}", item["Id"])
        and item["Name"] == "/" + expected
        and state["Status"] == "exited"
        and state["Running"] is False
        and state["ExitCode"] == (0 if reconciled else 1)
        and state["OOMKilled"] is False
        and not state["Error"]
        and item["RestartCount"] == 0
        and cfg["Image"] == config["native"]["helper_image"]
        and cfg["Labels"].get("marty.windows.renewal") == cycle
        and cfg["Entrypoint"] == ["python"]
        and cfg["Cmd"] == ["-c", CAP_WORKER if reconciled else native.PRODUCER_ASSEMBLE]
        and host["NetworkMode"] == config["native"]["network"]
        and host["LogConfig"]["Type"] == "none"
        and host["ReadonlyRootfs"] is True
        and host["RestartPolicy"]["Name"] == "no"
        and host["Privileged"] is False
        and host["CapDrop"] == ["ALL"]
        and host.get("CapAdd") in (None, [])
        and host["SecurityOpt"] == ["no-new-privileges"]
        and host["Memory"] == 512 * 1024 * 1024
        and host["NanoCpus"] == 1000000000
    )
    mounts = {m["Destination"]: m for m in item["Mounts"]}
    require(
        len(item["Mounts"]) == 3
        and set(mounts) == {"/control", "/operator/tool", "/input/ca.crt"}
    )
    volume = mounts["/control"]
    require(
        volume["Type"] == "volume"
        and volume["Name"] == config["native"]["control_volume"]
        and volume["RW"] is True
    )
    for dest, field in [("/operator/tool", "binary"), ("/input/ca.crt", "ca_file")]:
        mount = mounts[dest]
        require(
            mount["Type"] == "bind"
            and mount["RW"] is False
            and selection.renewal.windows_mount_path_equal(
                mount["Source"], config["native"][field]
            )
        )
    return {
        "id": item["Id"],
        "name": expected,
        "image": cfg["Image"],
        "inspection_sha256": selection.digest(
            selection.packed(
                {
                    key: item[key]
                    for key in (
                        "Config",
                        "HostConfig",
                        "Mounts",
                        "State",
                        "RestartCount",
                    )
                }
            )
        ),
    }


def checked_helpers(items, helpers, config, cycle, *, complete):
    retired_ids = {x["id"] for x in helpers.values()}
    retired_names = {"/" + x["name"] for x in helpers.values()}
    require(
        not any(x["Id"] in retired_ids or x.get("Name") in retired_names for x in items)
    )
    names = {config["project"] + "-renew-keycloak-" + cycle}
    if complete:
        names.add(config["project"] + "-renew-cap-reconcile-" + cycle)
    related = [
        x
        for x in items
        if (x.get("Config", {}).get("Labels") or {}).get("marty.windows.renewal")
        == cycle
        or x.get("Name") in {"/" + name for name in names}
    ]
    require(
        len(related) == len(names)
        and {x["Name"] for x in related} == {"/" + n for n in names}
    )
    proofs = {}
    for item in related:
        repaired = (
            item["Name"] == "/" + config["project"] + "-renew-cap-reconcile-" + cycle
        )
        proofs["reconciled" if repaired else "failed"] = helper_proof(
            item, config, cycle, reconciled=repaired
        )
    return proofs


def completed_receipts(raws, original, helpers, config, cycle, guard_sha, data_sha):
    require(set(raws) == CAP_RECEIPTS)
    require(set(helpers) == {"failed", "reconciled"})
    for key, phase in [("failed", "keycloak"), ("reconciled", "cap-reconcile")]:
        helper = helpers[key]
        require(
            type(helper) is dict
            and set(helper) == {"id", "name", "image", "inspection_sha256"}
            and type(helper["id"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", helper["id"])
            and helper["name"] == config["project"] + "-renew-" + phase + "-" + cycle
            and helper["image"] == config["native"]["helper_image"]
            and type(helper["inspection_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", helper["inspection_sha256"])
        )
    require(helpers["failed"]["id"] != helpers["reconciled"]["id"])
    intent = selection.decode(raws[PREFIX + "intent.json"])
    require(
        raws[PREFIX + "intent.json"] == selection.packed(intent)
        and intent
        == {
            "schema": "marty.windows-staged-leaf-cap-reconciliation/v1",
            "guard_sha256": guard_sha,
            "original_receipt_sha256": original,
            "failed_helper": helpers["failed"],
            "binary_sha256": config["native"]["binary_sha256"],
            "data_sha256": data_sha,
            "credential_admission": False,
            "producer_replay": False,
        }
    )
    require(raws[PREFIX + "helper.json"] == selection.packed(helpers["reconciled"]))
    for phase in PHASES:
        for event in ("started", "completed"):
            require(
                raws[PREFIX + phase + "." + event + ".json"]
                == selection.packed({"phase": phase, "event": event, "metadata": {}})
            )
    return {name: selection.digest(raw) for name, raw in raws.items()}


def reconcile(config_path, output_dir, *, operator_successor=None):
    from selfhost_windows_staging_recovery import _recovery_candidate_inputs
    import selfhost_windows_renewal_native as native

    renewal = selection.renewal
    with _recovery_candidate_inputs(
        config_path, output_dir, operator_successor, _failed_keycloak=True
    ) as lease:
        root, cfg, stack = lease["root"], lease["config"], lease["stack"]
        intent = {
            "schema": "marty.windows-staged-leaf-cap-reconciliation/v1",
            "guard_sha256": lease["guard_sha256"],
            "original_receipt_sha256": lease["original_receipts"],
            "failed_helper": lease["failed_helper"],
            "binary_sha256": cfg["native"]["binary_sha256"],
            "data_sha256": lease["data_sha256"],
            "credential_admission": False,
            "producer_replay": False,
        }
        # Exclusive creation is the new no-retry boundary, before any mint.
        selection._new_private(
            root / (PREFIX + "intent.json"), selection.packed(intent)
        )
        lease["names"].add(PREFIX + "intent.json")
        stack.enter_context(renewal.hold_private_input(root / (PREFIX + "intent.json")))
        for name in sorted(CAP_RECEIPTS - {PREFIX + "intent.json"}):
            selection._new_private(root / name, b"")
            lease["names"].add(name)

        def checkpoint(phase, event):
            path = root / (PREFIX + phase + "." + event + ".json")
            renewal.write_empty_private_file(
                path,
                selection.packed(
                    {"phase": phase, "event": event, "metadata": {}}
                ).decode(),
            )
            stack.enter_context(renewal.hold_private_input(path))

        checkpoint("helper", "started")
        proof = run_cap_helper(cfg, lease["old_bytes"], lease["cycle"])
        renewal.write_empty_private_file(
            root / (PREFIX + "helper.json"), selection.packed(proof).decode()
        )
        stack.enter_context(renewal.hold_private_input(root / (PREFIX + "helper.json")))
        checkpoint("helper", "completed")
        checkpoint("export", "started")
        values = native.export_generation(cfg, cfg["native"]["renewed"])
        require(
            set(values) == set(lease["old_bytes"])
            and sum(values[n] != lease["old_bytes"][n] for n in values) == 39
        )
        checkpoint("export", "completed")
        checkpoint("materialize", "started")
        candidate = Path(cfg["renewed_secrets"])
        for name, value in values.items():
            selection._new_private(candidate / name, value)
            lease["expected_candidate_names"].add(name)
        held = stack.enter_context(
            renewal.hold_private_generation(candidate, sorted(values))
        )
        require(held == values)
        checkpoint("materialize", "completed")
        checkpoint("candidate", "started")
        native.preflight_recovery(
            cfg["native"],
            cfg["project"],
            lease["old_bytes"],
            held,
            lease["observed"]["docker"].prefix,
        )
        checkpoint("candidate", "completed")
        # Final fresh helper census and every held-file exit must also pass.
        helpers = checked_helpers(
            lease["observed"]["context"].check(before_intent=True),
            {},
            cfg,
            lease["cycle"],
            complete=True,
        )
        require(
            helpers["failed"] == lease["failed_helper"]
            and helpers["reconciled"] == proof
        )
        result = {
            "result": "provisional-cap-reconciled-candidate",
            "guards_retained": True,
            "producer_replay": False,
            "credential_admission": False,
            "generation_sha256": selection.fingerprint(held),
        }
    return result


def run_cap_helper(config, current, cycle):
    from selfhost_windows_inputs import hold_private_input
    from selfhost_windows_renewal import Docker, run_owned_mutation

    native = config["native"]
    project = config["project"]
    require(
        re.fullmatch(r"[0-9a-f]{32}", cycle)
        and native["control_volume"] == project + "-renewal-control"
        and native["network"] == project + "_default"
        and native["bao_addr"] == "https://openbao:8200"
        and native["renewed"] == "/control/windows-renewal-" + cycle + "/generation"
        and native["token_file"] == "/control/recovery-session-" + cycle + "/token"
        and 3600 <= native["minimum_ttl"] <= 28800
    )
    docker = Docker(config["docker_host"], config["engine_id"])
    name = project + "-renew-cap-reconcile-" + cycle
    with hold_private_input(Path(native["binary"]), max_bytes=256 * 1024 * 1024) as raw:
        require(hashlib.sha256(raw).hexdigest() == native["binary_sha256"])
        with hold_private_input(Path(native["ca_file"])):
            body = {
                k: native[k]
                for k in (
                    "binary_sha256",
                    "source_sha",
                    "release_tag",
                    "bao_addr",
                    "minimum_ttl",
                )
            }
            body.update(
                root="/control/windows-renewal-" + cycle,
                authority=native["token_file"],
                source_sha256={
                    name: hashlib.sha256(value).hexdigest()
                    for name, value in current.items()
                },
            )
            args = [
                *docker.prefix,
                "run",
                "--pull",
                "never",
                "-i",
                "--name",
                name,
                "--label",
                "marty.windows.renewal=" + cycle,
                "--log-driver",
                "none",
                "--network",
                native["network"],
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--mount",
                f"type=volume,src={native['control_volume']},dst=/control,volume-nocopy",
                "--mount",
                f"type=bind,src={native['binary']},dst=/operator/tool,readonly",
                "--mount",
                f"type=bind,src={native['ca_file']},dst=/input/ca.crt,readonly",
                "--entrypoint",
                "python",
                native["helper_image"],
                "-c",
                CAP_WORKER,
            ]
            p = run_owned_mutation(
                args, stdin_bytes=selection.packed(body), timeout=240
            )
            require(
                p.returncode == 0
                and selection.decode(p.stdout)
                == {"bounded_tokens": 21, "changed_files": 39}
            )
            items = docker.json(["inspect", name])
            require(len(items) == 1)
            return helper_proof(items[0], config, cycle, reconciled=True)


CAP_WORKER = r"""
import contextlib,hashlib,http.client,json,os,pathlib,stat,subprocess,sys,ssl,urllib.error,urllib.request
d=json.load(sys.stdin);os.umask(0o077);root=pathlib.Path(d['root']);binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
assert 3600<=d['minimum_ttl']<=28800
assert d['bao_addr']=='https://openbao:8200'
token=pathlib.Path(d['authority']).read_text().strip()
def call(op,body,network=False):
 args=[binary,'operator',op]+([d['bao_addr'],'/input/ca.crt'] if network else [])
 p=subprocess.run(args,input=json.dumps(body).encode(),capture_output=True,timeout=90)
 assert p.returncode==0
 return json.loads(p.stdout)
ctx=ssl.create_default_context(cafile='/input/ca.crt')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  raise urllib.error.HTTPError(req.full_url,code,'OpenBao redirect refused',headers,fp)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ctx),NoRedirect())
def request(path,body,custody=None):
 assert path in ('auth/token/lookup','auth/token/create/selfhost-renew-leaf')
 req=urllib.request.Request(d['bao_addr']+'/v1/'+path,data=json.dumps(body).encode(),
     headers={'X-Vault-Token':token,'Content-Type':'application/json'})
 try:response=opener.open(req,timeout=10)
 except urllib.error.HTTPError as error:response=error
 with response:
  incomplete=False
  try:raw=response.read(131073)
  except http.client.IncompleteRead as error:raw=error.partial[:131073];incomplete=True
  if custody is not None:
   custody.write(raw);custody.flush();os.fsync(custody.fileno())
  assert not incomplete and response.status==200 and len(raw)<=131072
  length=response.headers.get('Content-Length')
  assert length is None or (length.isascii() and length.isdecimal() and int(length)==len(raw))
  return raw
def private(path,raw):
 assert len(raw)<=131072
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
with contextlib.ExitStack() as held:
 def read_dir(path):
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.callback(os.close,fd)
  m=os.fstat(fd);assert m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o700
  names=sorted(os.listdir(fd));values={}
  def verify_directory():assert sorted(os.listdir(fd))==names
  held.callback(verify_directory)
  for name in names:
   h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
   f=held.enter_context(os.fdopen(h,'rb'));before=os.fstat(h)
   assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
   assert stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=65536
   raw=f.read(65537);assert len(raw)<=65536 and b'\0' not in raw and b'PRIVATE KEY' not in raw
   raw.decode('utf-8');values[name]=raw
   def identity(m):return (m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
   def verify_file(f=f,before=before,fd=fd,name=name):
    assert identity(os.fstat(f.fileno()))==identity(before)==identity(os.stat(name,dir_fd=fd,follow_symlinks=False))
   held.callback(verify_file)
  return values
 source=read_dir(root/'source');previous=read_dir(root/'generation')
 assert {n:hashlib.sha256(v).hexdigest() for n,v in source.items()}==d['source_sha256']
 assert set(source)==set(previous) and sum(source[n]!=previous[n] for n in source)==39
 verify={'operation':'verify','current':str(root/'source'),'candidate':str(root/'generation'),
         'ca_overlap':False,'ca_retire':False}
 assert call('generation',verify)=={'value':[len(source),39]}
 assert call('retained-certificates',{'token':token,'generation':str(root/'source'),'minimum_ttl':d['minimum_ttl']},True)=={'value':None}
 fresh={'token':token,'old':str(root/'generation'),'new':str(root/'generation'),
        'minimum_ttl':d['minimum_ttl'],'require_orphan_new':True,'require_orphan_old':True,
        'replacement':None,'retiring':False}
 for op in ['activation-tokens','activation-certificates']:assert call(op,fresh,True)=={'value':None}
 proof={'token':token,'old':str(root/'source'),'new':str(root/'generation'),'minimum_ttl':d['minimum_ttl']}
 assert call('recovery-candidate',proof,True)=={'error':'renewed OpenBao token has additional authority or an unbounded lifetime'}
 names=sorted({p.name for folder in ['tls','keycloak'] for p in (root/folder).iterdir() if p.name.endswith('_token')})
 assert len(names)==21 and set(names)<=set(source)
 previous_tokens=[];policies={}
 for name in names:
  leaf=previous[name].decode().strip();previous_tokens.append(leaf)
  lookup=json.loads(request('auth/token/lookup',{'token':leaf}));meta=lookup['data']
  assert meta['explicit_max_ttl']==0 and meta['type']=='service' and meta['num_uses']==0
  assert meta['orphan'] is True and meta['path']=='auth/token/create/selfhost-renew-leaf'
  assert len(meta['policies'])==1 and meta['policies'][0] not in ('default','root')
  assert meta.get('identity_policies') in (None,[]) and meta.get('period') in (None,0)
  assert meta.get('token_period') in (None,0) and d['minimum_ttl']<=meta['ttl']<=meta['creation_ttl']<=28800
  policies[name]=meta['policies'][0]
 assert len(set(previous_tokens))==len(set(policies.values()))==21
 output=root/'cap-reconciliation';output.mkdir(mode=0o700);sync(root)
 candidate=output/'generation';candidate.mkdir(mode=0o700);sync(output)
 values=dict(previous);issued=set()
 for name in names:
  # Save every response under exclusive custody before validating it. An
  # uncertain mint is never replayed; the host intent and these files remain.
  response=output/(name+'.response.private.json')
  fd=os.open(response,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb') as custody:
    raw=request('auth/token/create/selfhost-renew-leaf',{'policies':[policies[name]],
       'no_default_policy':True,'ttl':'8h','explicit_max_ttl':'8h'},custody=custody)
  finally:
   sync(output)
  created=json.loads(raw)
  leaf=created['auth']['client_token']
  assert isinstance(leaf,str) and len(leaf)>=20 and leaf not in previous_tokens and leaf not in issued
  assert leaf!=token and leaf not in {source[n].decode().strip() for n in names}
  issued.add(leaf)
  lookup=json.loads(request('auth/token/lookup',{'token':leaf}));meta=lookup['data']
  assert meta['explicit_max_ttl']==28800 and meta['type']=='service' and meta['num_uses']==0
  assert meta['orphan'] is True and meta['path']=='auth/token/create/selfhost-renew-leaf'
  assert meta['policies']==[policies[name]] and meta.get('identity_policies') in (None,[])
  assert meta.get('period') in (None,0) and meta.get('token_period') in (None,0)
  assert d['minimum_ttl']<=meta['ttl']<=meta['creation_ttl']<=28800
  values[name]=leaf.encode()
 for name,raw in values.items():private(candidate/name,raw)
 sync(candidate);sync(output)
 verify['candidate']=str(candidate)
 assert call('generation',verify)=={'value':[len(source),39]}
 proof['new']=str(candidate)
 assert call('recovery-candidate',proof,True)=={'value':None}
 # Keep the original unbounded generation and its response receipts intact.
 # Either rename failing is an uncertain publication, never automatic rollback.
 assert not (root/'generation-unbounded-retained').exists()
 os.rename(root/'generation',root/'generation-unbounded-retained');sync(root)
 os.rename(candidate,root/'generation');sync(output);sync(root)
 proof['new']=str(root/'generation')
 assert call('recovery-candidate',proof,True)=={'value':None}
print(json.dumps({'bounded_tokens':21,'changed_files':39}))
"""
