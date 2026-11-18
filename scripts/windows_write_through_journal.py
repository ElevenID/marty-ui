"""Candidate NTFS-only durable private writer; NOT admitted by the build gate.

Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
The write-through request plus FlushFileBuffers covers NTFS file/metadata writes.
This is not a claim to withstand hardware that dishonors flushes. No volume flush,
privilege change, directory replacement, service operation or fallback is used.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import re
import weakref

MAX_BYTES = 8 * 1024 * 1024
MAX_EVENT = 128 * 1024
SCHEMA = "marty.windows-private-journal/v1"


def require(value, code):
    if not value:
        raise ValueError(code)


def complete_write(stream, raw, flush):
    require(stream.write(raw) == len(raw), "WINDOWS_PRIVATE_SHORT_WRITE")
    require(flush(), "WINDOWS_PRIVATE_FLUSH_FAILED")


def decode_events(raw, identity):
    require(raw and len(raw) <= MAX_BYTES and raw.endswith(b"\n"), "WINDOWS_JOURNAL_INCOMPLETE")
    previous = None
    last = None
    for index, line in enumerate(raw.splitlines(), 1):
        require(line and len(line) <= MAX_EVENT, "WINDOWS_JOURNAL_EVENT_SIZE")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, "WINDOWS_JOURNAL_DUPLICATE_FIELD")
                result[key] = value
            return result
        try:
            event = json.loads(line, object_pairs_hook=unique)
        except (ValueError, UnicodeError) as error:
            raise ValueError("WINDOWS_JOURNAL_INVALID_JSON") from error
        require(set(event) == {"schema", "sequence", "previousSha256", "identity", "payload"}, "WINDOWS_JOURNAL_FIELDS")
        require(event["schema"] == SCHEMA and type(event["sequence"]) is int and event["sequence"] == index,
                "WINDOWS_JOURNAL_SEQUENCE")
        require(event["identity"] == identity and event["previousSha256"] == previous and isinstance(event["payload"], dict),
                "WINDOWS_JOURNAL_IDENTITY_OR_CHAIN")
        previous = hashlib.sha256(line).hexdigest()
        last = event
    return last, previous


_VERIFIED_ROOTS = weakref.WeakSet()


class _OwnedRunDirectory:
    __slots__ = ("_path", "_root", "_root_identity", "_identity", "__weakref__")

    def __init__(self, root, path, root_identity, identity):
        self._root = root
        self._path = path
        self._root_identity = (root_identity["device"], root_identity["inode"])
        self._identity = (identity["device"], identity["inode"])

    @property
    def path(self):
        return self._path


def _directory_identity(directory):
    info = os.lstat(directory)
    require(stat.S_ISDIR(info.st_mode) and info.st_ino != 0 and not (info.st_file_attributes & 0x400),
            "WINDOWS_OWNED_DIRECTORY_IDENTITY_REQUIRED")
    return {"device": info.st_dev, "inode": info.st_ino}


def _read_acl(directory):
    # Read-only supported ACL/SID APIs; never change the shared private root.
    quoted = str(directory).replace("'", "''")
    script = "$ErrorActionPreference='Stop';$a=Get-Acl -LiteralPath '"+quoted+"';@{owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value;user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;protected=$a.AreAccessRulesProtected;principals=@($a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])|ForEach-Object{@{sid=$_.IdentityReference.Value;kind=$_.AccessControlType.ToString();rights=[int]$_.FileSystemRights;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags;inherited=$_.IsInherited}})}|ConvertTo-Json -Depth 4 -Compress"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, timeout=10, check=True)
    require(len(result.stdout) <= 8192, "WINDOWS_ACL_RESPONSE_BOUND")
    return json.loads(result.stdout)


def prove_owned_run_directory(expected):
    """Expected IDs/SID come from separately frozen controller inputs, not a journal."""
    require(os.name == "nt", "WINDOWS_HOST_REQUIRED")
    run_id = expected.get("runId", "")
    require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", run_id),
            "WINDOWS_OWNED_RUN_ID_REQUIRED")
    root = Path.home() / ".codex/private"
    require(root.resolve() == root, "WINDOWS_PRIVATE_ROOT_ALIAS_CHANGED")
    directory = root / ("marty-d12-build-" + run_id)
    require(Path(expected["root"]) == root and Path(expected["directory"]) == directory
            and directory.resolve() == directory and root.resolve() == root, "WINDOWS_PRIVATE_RUN_ALIAS_CHANGED")
    require(_directory_identity(root) == expected["rootIdentity"] and _directory_identity(directory) == expected["directoryIdentity"],
            "WINDOWS_PRIVATE_RUN_GENERATION_CHANGED")
    for path in (root, directory):
        acl = _read_acl(path)
        require(acl["owner"] == acl["user"] == expected["ownerSid"], "WINDOWS_PRIVATE_RUN_OWNER_CHANGED")
        allowed = {expected["ownerSid"], "S-1-5-18", "S-1-5-32-544"}
        rules = acl["principals"]
        require(len(rules) == 3 and {rule["sid"] for rule in rules} == allowed
                and all(rule["kind"] == "Allow" and rule["rights"] == 2032127 for rule in rules),
                "WINDOWS_PRIVATE_RUN_ACL_CHANGED")
        if path == directory:
            require(acl["protected"] is True and all(rule["inheritance"] == 3 and rule["propagation"] == 0 and rule["inherited"] is False for rule in rules), "WINDOWS_PRIVATE_RUN_ACL_MUST_BE_PROTECTED")
    proof = _OwnedRunDirectory(root, directory, expected["rootIdentity"], expected["directoryIdentity"])
    _VERIFIED_ROOTS.add(proof)
    return proof


def _check_owned_root(proof):
    require(isinstance(proof, _OwnedRunDirectory) and proof in _VERIFIED_ROOTS, "VERIFIED_PRIVATE_RUN_CAPABILITY_REQUIRED")
    root = _directory_identity(proof._root)
    directory = _directory_identity(proof.path)
    require((root["device"], root["inode"]) == proof._root_identity and (directory["device"], directory["inode"]) == proof._identity, "WINDOWS_PRIVATE_RUN_GENERATION_CHANGED")


class NTFSWriteThroughFile:
    def __init__(self, file, owned_root, *, create_new):
        require(os.name == "nt", "WINDOWS_HOST_REQUIRED")
        import msvcrt
        from ctypes import wintypes
        _check_owned_root(owned_root)
        self.owned_root = owned_root
        file, parent = Path(file), owned_root.path
        require(file.is_absolute() and file.parent == parent and parent.is_dir() and file.drive.upper() in {"C:", "D:"},
                "EXACT_OWNED_WINDOWS_FILE_REQUIRED")
        require(parent.resolve() == parent and not parent.is_symlink() and ":" not in file.name and ".." not in file.parts,
                "WINDOWS_PRIVATE_PATH_ALIAS")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.api.CreateFileW.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.api.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        self.api.FlushFileBuffers.restype = wintypes.BOOL
        self.api.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        self.api.GetVolumePathNameW.restype = wintypes.BOOL
        self.api.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR, wintypes.DWORD]
        self.api.GetVolumeInformationW.restype = wintypes.BOOL
        volume = ctypes.create_unicode_buffer(32768)
        self._ok(self.api.GetVolumePathNameW(str(parent), volume, len(volume)), "WINDOWS_VOLUME_PATH")
        filesystem = ctypes.create_unicode_buffer(64)
        serial, limit, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        self._ok(self.api.GetVolumeInformationW(volume.value, None, 0, ctypes.byref(serial), ctypes.byref(limit),
                  ctypes.byref(flags), filesystem, len(filesystem)), "WINDOWS_VOLUME_INFO")
        require(filesystem.value == "NTFS", "NTFS_REQUIRED_NO_DURABILITY_FALLBACK")
        # Read/write; readers allowed, concurrent writer/delete denied. Open the
        # last reparse point itself so the regular-file check cannot follow it.
        handle = self.api.CreateFileW(str(file), 0xC0000000, 1, None, 1 if create_new else 3,
                                      0x80000000 | 0x00200000 | 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            self._ok(False, "WINDOWS_EXCLUSIVE_CREATE" if create_new else "WINDOWS_JOURNAL_OPEN")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            self.api.CloseHandle(handle)
            raise
        self.stream = os.fdopen(fd, "r+b", buffering=0)
        self.file = file
        self.handle = msvcrt.get_osfhandle(fd)
        try:
            self.identity = self._identity()
            self.mode = None
            self.position = 0
            self.previous = None
            if not create_new:
                raw = self.stream.read(MAX_BYTES + 1)
                last, self.previous = decode_events(raw, self.identity)
                self.position = last["sequence"]
                self.mode = "journal"
            self.stream.seek(0, os.SEEK_END)
        except BaseException:
            self.stream.close()
            raise

    @staticmethod
    def _ok(value, code):
        if not value:
            error = ctypes.WinError(ctypes.get_last_error())
            error.code = code
            raise error

    def _identity(self):
        _check_owned_root(self.owned_root)
        info = os.fstat(self.stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not (info.st_file_attributes & 0x400),
                "WINDOWS_REGULAR_SINGLE_LINK_FILE_REQUIRED")
        require(info.st_ino != 0, "WINDOWS_FILE_ID_REQUIRED")
        current = os.lstat(self.file)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "WINDOWS_PRIVATE_PATH_REPLACED")
        return {"device": info.st_dev, "inode": info.st_ino}

    def _write(self, raw):
        require(len(raw) <= MAX_EVENT and self.stream.tell() + len(raw) <= MAX_BYTES, "WINDOWS_PRIVATE_WRITE_BOUND")
        require(self._identity() == self.identity, "WINDOWS_PRIVATE_IDENTITY_CHANGED")
        def flush():
            self._ok(self.api.FlushFileBuffers(self.handle), "WINDOWS_PRIVATE_FLUSH_FAILED")
            return True
        complete_write(self.stream, raw, flush)
        require(self._identity() == self.identity, "WINDOWS_PRIVATE_IDENTITY_CHANGED")
        return {"backend": "WINDOWS_NTFS_WRITE_THROUGH_CANDIDATE_V1", "createNewOrVerifiedIdentity": True,
            "writeThrough": True, "flushFileBuffers": True, "completeBytes": True, "sameFileIdentity": True,
            "identity": self.identity, "acceptedByBuildGate": False}

    def intent(self, payload):
        require(self.mode is None and self.position == 0 and self.stream.tell() == 0, "EXCLUSIVE_INTENT_ALREADY_WRITTEN")
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        proof = self._write(raw)
        self.position = 1
        self.mode = "intent"
        return proof

    def append(self, payload):
        require(self.mode != "intent", "INTENT_CANNOT_BECOME_A_JOURNAL")
        require(isinstance(payload, dict), "WINDOWS_JOURNAL_PAYLOAD_REQUIRED")
        event = {"schema": SCHEMA, "sequence": self.position + 1, "previousSha256": self.previous,
                 "identity": self.identity, "payload": payload}
        raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        proof = self._write(raw + b"\n")
        self.position += 1
        self.mode = "journal"
        self.previous = hashlib.sha256(raw).hexdigest()
        return {**proof, "sequence": self.position, "chainSha256": self.previous}

    def close(self):
        self.stream.close()
