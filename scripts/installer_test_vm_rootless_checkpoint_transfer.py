"""One-shot, fixed host-to-guest package evidence transfer for a disposable VM.

This dormant controller stages only historical signed package bytes and exact
records. It never calls the package executor, creates confirmation, or grants
product authority. A root-private pre-import source admission is required.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import time

from installer_candidate_controller import ControllerLease
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_release as release
import installer_test_vm_probe as probe
import installer_test_vm_rootless_checkpoint as checkpoint
import installer_test_vm_rootless_checkpoint_resume as resumed
import installer_test_vm_rootless_package_admission as archive
import installer_test_vm_rootless_package_admission_controller as admission
import installer_test_vm_rootless_source_admission as source_admission
import installer_test_vm_rootless_setup as setup
from installer_host_probe import command

SCHEMA = "elevenid.installer-only-rootless-package-transfer/v1"
INTENT_SUFFIX = ".rootless-package-transfer-intent.json"
RESULT_SUFFIX = ".rootless-package-transfer-result.json"
GUEST_PARENT = "/var/lib/marty-installer-only-rootless-install"
HOST_MODULES = ("installer_test_vm_rootless_checkpoint_transfer.py",
                "installer_test_vm_rootless_checkpoint_resume.py",
                "installer_test_vm_rootless_source_admission.py")
GUEST_MODULES = ("installer_test_vm_rootless_package_install.py",
                 "installer_test_vm_rootless_package_admission.py")

# This fixed script is sent only over the pinned fixture-admin SSH identity.
# Its sole root mutation is an O_EXCL copy into the fixed disposable VM tree.
GUEST_COPY = r'''
import hashlib,json,os,stat,sys
vm,manifest_raw,mode,expected_admin=sys.argv[1:]
expected_admin=int(expected_admin)
assert expected_admin>0
assert len(vm)==36 and all(c in '0123456789abcdef-' for c in vm)
rows=json.loads(manifest_raw)
assert type(rows)==list and 1<=len(rows)<=32
names=[r['name'] for r in rows]
assert len(names)==len(set(names))
assert all(type(r)==dict and set(r)=={'name','sha256','size'} and
           type(r['name'])==str and r['name'].isascii() and
           r['name'].replace('.','').replace('-','').replace('_','').isalnum() and
           type(r['size'])==int and 0<r['size']<=67108864 and
           type(r['sha256'])==str and len(r['sha256'])==64 and
           all(c in '0123456789abcdef' for c in r['sha256']) for r in rows)
stage='/home/fixture-admin/.marty-rootless-package-'+vm
parent='/var/lib/marty-installer-only-rootless-install'
target=parent+'/'+vm
def stamp(p,uid,mode):
    s=os.lstat(p)
    assert stat.S_ISDIR(s.st_mode) and s.st_uid==uid and stat.S_IMODE(s.st_mode)==mode
    return s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode
home=os.lstat('/home/fixture-admin')
assert stat.S_ISDIR(home.st_mode) and home.st_uid==expected_admin and not (home.st_mode&0o022)
admin=expected_admin
stage_stamp=stamp(stage,admin,0o700)
assert set(os.listdir(stage))==set(names)
if mode=='create':
    try: os.mkdir(parent,0o700)
    except FileExistsError: pass
    stamp(parent,0,0o700)
    os.mkdir(target,0o700)
    rootfd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    os.mkdir('bundle',0o700,dir_fd=rootfd)
    os.mkdir('code',0o700,dir_fd=rootfd)
    os.mkdir('transaction',0o700,dir_fd=rootfd)
elif mode=='verify':
    stamp(parent,0,0o700)
    rootfd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
else: raise ValueError('unsupported transfer mode')
try:
    assert stamp(target,0,0o700)
    expected_root={'bundle','code','transaction','admission-intent.json',
      'admission.json','checkpoint.json','bundle-manifest.json'}
    if mode=='verify': assert set(os.listdir(target))==expected_root
    for sub in ('bundle','code','transaction'): stamp(target+'/'+sub,0,0o700)
    assert not os.listdir(target+'/transaction')
    if mode=='verify':
        assert set(os.listdir(target+'/bundle'))=={r['name'] for r in rows if r['name'].endswith(('.deb','.xz','.inrelease'))}
        assert set(os.listdir(target+'/code'))=={r['name'] for r in rows if r['name'].endswith('.py')}
    for row in rows:
        name=row['name']
        src=stage+'/'+name
        fd=os.open(src,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd)
            assert stat.S_ISREG(a.st_mode) and a.st_uid==admin and a.st_nlink==1 and a.st_size==row['size']
            reader=os.open('/proc/self/fd/%d'%fd,os.O_RDONLY|os.O_CLOEXEC)
            try:
                b=os.fstat(reader)
                assert (a.st_dev,a.st_ino,a.st_uid,a.st_mode,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_uid,b.st_mode,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
                h=hashlib.sha256();left=a.st_size
                if mode=='create':
                    folder='code' if name.endswith('.py') else ('bundle' if name.endswith(('.deb','.xz','.inrelease')) else '')
                    dest=target+'/'+folder+'/'+name if folder else target+'/'+name
                    out=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                else:
                    folder='code' if name.endswith('.py') else ('bundle' if name.endswith(('.deb','.xz','.inrelease')) else '')
                    dest=target+'/'+folder+'/'+name if folder else target+'/'+name
                    out=None
                try:
                    while left:
                        part=os.read(reader,min(left,65536));assert part
                        h.update(part);left-=len(part)
                        if out is not None:
                            view=memoryview(part)
                            while view:
                                n=os.write(out,view);assert n>0;view=view[n:]
                    assert os.read(reader,1)==b'' and h.hexdigest()==row['sha256']
                    c=os.fstat(reader);d=os.lstat(src)
                    assert (a.st_dev,a.st_ino,a.st_uid,a.st_mode,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(c.st_dev,c.st_ino,c.st_uid,c.st_mode,c.st_size,c.st_mtime_ns,c.st_ctime_ns)==(d.st_dev,d.st_ino,d.st_uid,d.st_mode,d.st_size,d.st_mtime_ns,d.st_ctime_ns)
                    if out is not None: os.fsync(out)
                finally:
                    if out is not None: os.close(out)
                destfd=os.open(dest,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    s=os.fstat(destfd)
                    assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size==a.st_size
                    rr=os.open('/proc/self/fd/%d'%destfd,os.O_RDONLY|os.O_CLOEXEC)
                    try:
                        hh=hashlib.sha256();left=s.st_size
                        while left:
                            part=os.read(rr,min(left,65536));assert part
                            hh.update(part);left-=len(part)
                        assert os.read(rr,1)==b'' and hh.hexdigest()==row['sha256']
                    finally: os.close(rr)
                    assert (os.lstat(dest).st_dev,os.lstat(dest).st_ino)==(s.st_dev,s.st_ino)
                finally: os.close(destfd)
            finally: os.close(reader)
        finally: os.close(fd)
    assert stamp(stage,admin,0o700)==stage_stamp
    assert set(os.listdir(target))==expected_root
    assert set(os.listdir(target+'/bundle'))=={r['name'] for r in rows if r['name'].endswith(('.deb','.xz','.inrelease'))}
    assert set(os.listdir(target+'/code'))=={r['name'] for r in rows if r['name'].endswith('.py')}
    if mode=='create':
        for sub in ('bundle','code','transaction'):
            f=os.open(target+'/'+sub,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(f);os.close(f)
        os.fsync(rootfd)
        p=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(p);os.close(p)
    print(json.dumps({'schema':'elevenid.rootless-package-guest-copy/v1','vm_id':vm,
      'manifest_sha256':hashlib.sha256(manifest_raw.encode()).hexdigest(),
      'files':len(rows),'mode':mode},sort_keys=True,separators=(',',':')))
finally: os.close(rootfd)
'''


def _manifest(stage: Path, admission_result: dict, source_dir: Path,
              admitted: dict[str, str]) -> tuple[list[dict], list[tuple[Path, str]]]:
    names = ([f"{p}.inrelease" for p in archive.POCKETS]
             + [f"{p}.{c}.packages.xz" for p in archive.POCKETS
                for c in archive.COMPONENTS]
             + [f"{p}.deb" for p in archive.TARGETS])
    sources = [(stage / "bundle" / name, name) for name in names]
    sources += [(source_dir / name, name) for name in GUEST_MODULES]
    result = []
    for path, name in sources:
        limit = (archive.MAX_INRELEASE if name.endswith(".inrelease") else
                 archive.MAX_INDEX if name.endswith(".xz") else
                 archive.MAX_DEB if name.endswith(".deb") else 1024 * 1024)
        raw = archive.private_file(path, limit,
                                   uid=0 if name.endswith(".py") else 65534)
        digest = hashlib.sha256(raw).hexdigest()
        if name.endswith(".py"):
            release.require(admitted[name] == digest,
                            "fixture transfer source module differs")
        release.require(0 < len(raw) <= 67108864,
                        "fixture transfer source size invalid")
        result.append({"name": name, "sha256": digest, "size": len(raw)})
    records = {
        "admission-intent.json": "admission_intent",
        "admission.json": "admission_result",
        "checkpoint.json": "checkpoint"}
    for name, field in records.items():
        raw = admission_result[field]
        release.require(len(raw) <= 65536,
                        "fixture transfer record oversized")
        result.append({"name": name, "sha256": release.digest(raw),
                       "size": len(raw)})
    bundle_manifest = release.encode({"packages": admission_result["packages"]})
    result.append({"name": "bundle-manifest.json",
                   "sha256": release.digest(bundle_manifest),
                   "size": len(bundle_manifest)})
    return result, sources


def _loaded_closure(source_dir: Path, admitted: dict[str, str]) -> None:
    """Rebind already imported local modules to the admitted root snapshot."""
    for name, module in tuple(sys.modules.items()):
        filename = name + ".py"
        if filename not in admitted or module is None:
            continue
        location = getattr(module, "__file__", None)
        release.require(type(location) is str
                        and Path(location) == source_dir / filename,
                        "fixture transfer imported source differs")
        raw = archive.private_file(source_dir / filename, 1024 * 1024, uid=0)
        release.require(release.digest(raw) == admitted[filename],
                        "fixture transfer imported bytes differ")


def _ssh_admin(binding: dict, script: str, *, limit: int = 1024,
               timeout: int = 30) -> bytes:
    options = probe._pinned(binding)
    output = command([str(probe.SSH), *options, "-p", str(binding["port"]),
                      "fixture-admin@127.0.0.1", script],
                     env=launch.ENV, limit=limit, timeout=timeout)
    probe._pinned(binding)
    return output


def _guest_copy(binding: dict, vm_id: str, manifest: list[dict],
                mode: str, admin_uid: int) -> dict:
    release.require(mode in ("create", "verify"),
                    "fixture transfer guest mode unsupported")
    raw = release.encode(manifest)
    release.require(len(raw) <= 8192,
                    "fixture transfer manifest oversized")
    invocation = ("/usr/bin/sudo -n /usr/bin/python3 -I -B -c "
                  + shlex.quote(GUEST_COPY) + " " + shlex.quote(vm_id)
                  + " " + shlex.quote(raw.decode("ascii"))
                  + " " + mode + " " + str(admin_uid))
    output = _ssh_admin(binding, invocation, limit=512, timeout=180)
    value = release.decode(output)
    release.exact(value, {"schema", "vm_id", "manifest_sha256",
                          "files", "mode"}, "fixture guest transfer")
    release.require(value == {
        "schema": "elevenid.rootless-package-guest-copy/v1",
        "vm_id": vm_id, "manifest_sha256": release.digest(raw),
        "files": len(manifest), "mode": mode},
        "fixture guest transfer differs")
    return value


def _guest_baseline(binding: dict, readiness: dict) -> tuple[bytes, ...]:
    ordinary_raw = setup._ssh_as(binding, "installer",
                                  setup._installer_command(), limit=2048)
    ordinary = setup._decode_installer(ordinary_raw)
    admin_raw = setup._ssh_as(binding, "fixture-admin",
                              setup._admin_identity_command(), limit=512)
    admin = setup._decode_admin(admin_raw, ordinary["uid"])
    engine_raw = setup._ssh_as(binding, "fixture-admin",
                               setup.SETUP_ENGINE_COMMAND, limit=256)
    engine = json.loads(engine_raw)
    status = admission._guest_status(binding)
    release.require(ordinary["uid"] == readiness["ordinary_uid"]
                    and admin["uid"] == readiness["setup_uid"]
                    and engine == readiness["setup_engine_id"]
                    and archive.sha(status) == readiness["dpkg_status_sha256"],
                    "fixture transfer current guest baseline differs")
    return ordinary_raw, admin_raw, engine_raw, status


def transfer_once(*, source: Path, registry: Path, runtime_parent: Path,
                  source_git: Path, source_dir: Path, source_commit: str,
                  vm_id: str, copy_vm_id: str) -> dict:
    """Copy a fixed admitted bundle once, without invoking APT or product code.

    The root-owned bootstrap must admit this module before importing it; this
    repeat closure check does not make an unchecked import safe. An existing
    transfer intent is always manual recovery, never an automatic retry.
    """
    release.require(os.geteuid() == 0 and all(p.is_absolute() for p in
                    (source, registry, runtime_parent, source_git, source_dir)),
                    "fixture transfer controller custody invalid")
    probe._uuid(vm_id)
    probe._uuid(copy_vm_id)
    admitted = source_admission.admit(git_dir=source_git,
                                      commit=source_commit,
                                      source_dir=source_dir)
    _loaded_closure(source_dir, admitted)
    for name in HOST_MODULES + GUEST_MODULES:
        release.require(name in admitted, "fixture transfer module absent")
    with ControllerLease(registry) as lease:
        for suffix in (INTENT_SUFFIX, RESULT_SUFFIX,
                       ".rootless-transfer-bundle-manifest.json"):
            try:
                os.stat(vm_id + suffix, dir_fd=lease.parent,
                        follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("fixture transfer already attempted")
        before = resumed.bound_resumed(
            source=source, registry=registry, runtime_parent=runtime_parent,
            vm_id=vm_id, copy_vm_id=copy_vm_id, _lease=lease)
        readiness_raw, readiness = create._read_record(
            lease.parent, vm_id + resumed.READINESS_SUFFIX)
        release.exact(readiness,
                      {"schema", "phase", "vm_id", "copy_vm_id",
                       "resume_receipt_sha256", "checkpoint_sha256",
                       "admission_result_sha256", "pid", "start_ticks",
                       "boot_id", "ordinary_uid", "setup_uid",
                       "setup_engine_id", "dpkg_status_sha256",
                       "observed_at", "package_install_authorized",
                       "product_dispatch_authorized"},
                      "fixture transfer current readiness")
        release.require(readiness["schema"] == resumed.SCHEMA
                        and readiness["phase"] == "current_readiness_observed"
                        and readiness["vm_id"] == vm_id
                        and readiness["copy_vm_id"] == copy_vm_id
                        and all(readiness[field] == before[expected]
                                for field, expected in (
                                ("resume_receipt_sha256", "resume_receipt_sha256"),
                                ("checkpoint_sha256", "checkpoint_sha256"),
                                ("pid", "pid"), ("start_ticks", "start_ticks"),
                                ("boot_id", "boot_id"),
                                ("ordinary_uid", "guest_uid"),
                                ("setup_engine_id", "historical_engine_id")))
                        and readiness["package_install_authorized"] is False
                        and readiness["product_dispatch_authorized"] is False
                        and type(readiness["setup_uid"]) is int
                        and readiness["setup_uid"] > 0
                        and readiness["setup_uid"] != before["guest_uid"],
                        "fixture transfer current readiness differs")
        intent_raw, intent_record = create._read_record(
            lease.parent, vm_id + admission.INTENT_SUFFIX)
        result_raw, result_record = create._read_record(
            lease.parent, vm_id + admission.RESULT_SUFFIX)
        checkpoint_raw, checkpoint_record = create._read_record(
            lease.parent, vm_id + checkpoint.SUFFIX)
        release.require(checkpoint_record["admission_result_sha256"]
                        == release.digest(result_raw)
                        and release.digest(checkpoint_raw)
                        == before["checkpoint_sha256"]
                        and readiness["admission_result_sha256"]
                        == release.digest(result_raw),
                        "fixture transfer historical admission differs")
        release.require(result_record["intent_sha256"]
                        == release.digest(intent_raw)
                        and result_record["engine_id"]
                        == before["historical_engine_id"]
                        == readiness["setup_engine_id"]
                        and result_record["dpkg_status_sha256"]
                        == readiness["dpkg_status_sha256"],
                        "fixture transfer admission identity differs")
        current_guest = _guest_baseline(before, readiness)
        source_module = archive.private_file(
            source_dir / "installer_test_vm_rootless_package_admission.py",
            1024 * 1024, uid=0)
        checkpoint._stage_recheck(result_record, source_module)
        stage = admission.STAGE_PARENT / (
            "package-admission-" + result_record["observation_id"])
        raw_records = {"admission_intent": intent_raw,
                       "admission_result": result_raw,
                       "checkpoint": checkpoint_raw,
                       "packages": result_record["packages"]}
        manifest, sources = _manifest(stage, raw_records, source_dir, admitted)
        bundle_manifest = release.encode({"packages": result_record["packages"]})
        release.require(len(manifest) <= 32 and len(release.encode(manifest)) <= 8192,
                        "fixture transfer file set invalid")
        manifest_sha = release.digest(release.encode(manifest))
        transfer_intent = {
            "schema": SCHEMA, "phase": "transfer_intent", "vm_id": vm_id,
            "copy_vm_id": copy_vm_id, "source_commit": source_commit,
            "source_closure_sha256": release.digest(release.encode(admitted)),
            "readiness_sha256": release.digest(readiness_raw),
            "resume_receipt_sha256": before["resume_receipt_sha256"],
            "checkpoint_sha256": release.digest(checkpoint_raw),
            "admission_intent_sha256": release.digest(intent_raw),
            "admission_result_sha256": release.digest(result_raw),
            "manifest_sha256": manifest_sha,
            "pid": before["pid"], "start_ticks": before["start_ticks"],
            "engine_id": before["historical_engine_id"],
            "requested_at": int(time.time()),
            "package_install_authorized": False,
            "product_dispatch_authorized": False}
        written = create._write(lease.parent, vm_id + INTENT_SUFFIX,
                                transfer_intent)
        release.require(written == release.encode(transfer_intent),
                        "fixture transfer intent changed")
        manifest_name = vm_id + ".rootless-transfer-bundle-manifest.json"
        create._write(lease.parent, manifest_name,
                      {"packages": result_record["packages"]})
        sources += [(registry / (vm_id + admission.INTENT_SUFFIX),
                     "admission-intent.json"),
                    (registry / (vm_id + admission.RESULT_SUFFIX),
                     "admission.json"),
                    (registry / (vm_id + checkpoint.SUFFIX), "checkpoint.json"),
                    (registry / manifest_name, "bundle-manifest.json")]
        directory = "/home/fixture-admin/.marty-rootless-package-" + vm_id
        release.require(_ssh_admin(before,
                        "umask 077; /usr/bin/mkdir -m 700 -- " + directory)
                        == b"", "fixture transfer guest staging refused")
        for path, name in sources:
            row = next(item for item in manifest if item["name"] == name)
            uid = 65534 if path.parent == stage / "bundle" else 0
            raw = archive.private_file(path, 67108864, uid=uid)
            release.require(len(raw) == row["size"]
                            and release.digest(raw) == row["sha256"],
                            "fixture transfer source changed")
            options = probe._pinned(before)
            command([str(probe.SCP), *options, "-P", str(before["port"]),
                     "--", str(path), "fixture-admin@127.0.0.1:"
                     + directory + "/" + name], env=launch.ENV,
                    limit=4096, timeout=300)
            probe._pinned(before)
        created = _guest_copy(before, vm_id, manifest, "create",
                              readiness["setup_uid"])
        verified = _guest_copy(before, vm_id, manifest, "verify",
                               readiness["setup_uid"])
        release.require(created["manifest_sha256"]
                        == verified["manifest_sha256"] == manifest_sha
                        and resumed.bound_resumed(
                            source=source, registry=registry,
                            runtime_parent=runtime_parent, vm_id=vm_id,
                            copy_vm_id=copy_vm_id, _lease=lease) == before
                        and create._read_record(
                            lease.parent, vm_id + resumed.READINESS_SUFFIX)[0]
                        == readiness_raw
                        and create._read_record(
                            lease.parent, vm_id + INTENT_SUFFIX)[0] == written,
                        "fixture transfer changed during copy")
        release.require(_guest_baseline(before, readiness) == current_guest,
                        "fixture transfer guest baseline changed")
        result = {**transfer_intent, "phase": "copied_observed",
                  "intent_sha256": release.digest(written),
                  "guest_copy_schema": created["schema"],
                  "observed_at": int(time.time())}
        create._write(lease.parent, vm_id + RESULT_SUFFIX, result)
        return result

