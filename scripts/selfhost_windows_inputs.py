"""Read or initialize a bounded NTFS input through its verified, held handle.

This does not stage generations, change ACLs, enable activation, or admit a
Windows installer. POSIX mode bits cannot establish Windows confidentiality.
Win32 references: CreateFileW (read sharing only), GetSecurityInfo (handle-bound
owner/DACL), GetFileInformationByHandle and GetVolumeInformationByHandleW:
https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 64 * 1024
REFUSAL = "Windows operator input is absent or not private"
WRITE_REFUSAL = "Windows private input initialization failed; inspect before retrying"
FULL_CONTROL = 0x1F01FF


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(REFUSAL)


def checked_acl(owner: str, user: str, aces: list[tuple[str, int, int, int]]) -> None:
    """Fail closed on broader or unfamiliar authority; do not rewrite the DACL."""
    require(isinstance(user, str) and re.fullmatch(r"S-1-\d+(?:-\d+)+", user) is not None)
    require(owner == user and 1 <= len(aces) <= 3)
    allowed = {user, "S-1-5-18", "S-1-5-32-544"}
    seen: set[str] = set()
    for sid, kind, flags, rights in aces:
        # Only ordinary effective ALLOW ACEs. Object/conditional/deny ACEs and
        # inherit-only ACEs are not interpreted as a private-file capability.
        # MS-DTYP OWNER_RIGHTS denotes this object's owner, already proven
        # equal to the current user above. Treat both spellings as one principal.
        principal = user if sid == "S-1-3-4" else sid
        require(principal in allowed and principal not in seen and kind == 0
                and flags & ~0x13 == 0 and rights == FULL_CONTROL)
        seen.add(principal)
    require(user in seen)


def checked_identity(volume: int, index: int, expected: tuple[int, int]) -> None:
    # File indices are volume-local: an index match alone cannot bind the handle.
    require((volume, index) == expected)


def _path_identities(path: Path, *, directory: bool = False) -> list[tuple[int, int]]:
    require(path.is_absolute() and re.fullmatch(r"[A-Za-z]:", path.drive) is not None)
    require(all(part not in {".", ".."} and ":" not in part
                and part.rstrip(" .") == part for part in path.parts[1:]))
    require(path.name.split(".", 1)[0].upper() not in
            {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))})
    result = []
    for item in [*reversed(path.parents), path]:
        info = item.lstat()
        require(not info.st_file_attributes & 0x400 and info.st_ino != 0)
        require(stat.S_ISREG(info.st_mode) if item == path and not directory
                else stat.S_ISDIR(info.st_mode))
        result.append((info.st_dev, info.st_ino))
    return result


def read_private_file(path: Path) -> str:
    """Read UTF-8 with the shared owner's universal-newline text contract."""
    try:
        return read_private_bytes(path).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError(REFUSAL) from None


def read_private_bytes(path: Path) -> bytes:
    """Read exact bounded bytes for generation comparison, without text decoding.

    The held handle has the same NTFS identity, privacy and sharing proofs as
    the text reader. This proves one read, not generation immutability after
    returning, concurrent activation safety or permission to activate it.
    """
    require(os.name == "nt")
    # Native errors deliberately do not expose filenames, input bytes or SIDs.
    try:
        return _private_file_bytes(path)
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError(REFUSAL) from None


@contextmanager
def hold_storage_namespace(path: Path):
    """Hold a data source's names without reading content or blocking writes.

    This is identity/sharing only, not a private-input or immutable-data proof.
    Reparse ancestors are refused. Files must have one link; directories may
    keep receiving normal application writes while their names are held.
    """
    require(os.name == 'nt')
    body_error = None
    try:
        path = Path(path)
        with ExitStack() as stack:
            for parent in reversed(path.parents):
                stack.enter_context(_held_private_input(parent, directory=True, ancestor=True))
            stack.enter_context(_held_private_input(path, directory=path.is_dir(), ancestor=True))
            try:
                yield
            except BaseException as error:
                body_error = error
                raise
    except (OSError, ValueError, TypeError) as error:
        if error is body_error:
            raise
        raise ValueError(REFUSAL) from None


@contextmanager
def hold_private_input(path: Path, *, max_bytes: int = MAX_BYTES, exclusive: bool = False):
    """Hold one bounded private asset; explicit exclusive mode is a process lock.

    Larger bounds are for retained Compose assets, never a change to the secret
    reader's 64KiB limit. Exclusive mode obtains write access without writing;
    another coordinator cannot acquire it even when its lock file is empty.
    """
    require(os.name == "nt")
    body_error = None
    try:
        path = Path(path)
        require(type(max_bytes) is int and 0 < max_bytes <= 256 * 1024 * 1024
                and type(exclusive) is bool)
        with ExitStack() as stack:
            for parent in reversed(path.parents):
                stack.enter_context(_held_private_input(parent, directory=True, ancestor=True))
            data = stack.enter_context(_held_private_input(
                path, max_bytes=max_bytes, exclusive=exclusive))
            try:
                yield data
            except BaseException as error:
                body_error = error
                raise
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        if error is body_error:
            raise
        raise ValueError(REFUSAL) from None


@contextmanager
def hold_public_input(path: Path, *, max_bytes: int = MAX_BYTES):
    """Hold an explicitly classified PUBLIC file immutable, without a privacy claim.

    Preserve NTFS identity, no-reparse, single-link, bounded reads and read-only
    sharing. The caller supplies the public classification and expected hash.
    This API neither admits secrets nor changes an ACL.
    """
    require(os.name == "nt")
    body_error = None
    try:
        path = Path(path)
        require(type(max_bytes) is int and 0 < max_bytes <= 256 * 1024 * 1024)
        with ExitStack() as stack:
            for parent in reversed(path.parents):
                stack.enter_context(_held_private_input(parent, directory=True, ancestor=True))
            data = stack.enter_context(_held_private_input(path,max_bytes=max_bytes,public_file=True))
            try:
                yield data
            except BaseException as error:
                body_error = error
                raise
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        if error is body_error:
            raise
        raise ValueError("Windows public immutable input is absent or changed") from None


@contextmanager
def hold_private_generation(root: Path, names: list[str]):
    """Hold every declared input and its private directory for one bounded action.

    Windows denies ordinary writes, deletion and replacement of held inputs.
    Recheck identity, privacy, directory membership and metadata on exit. This
    supplies a read boundary only: callers still own native generation checks,
    Compose scope/mount proof, rollback and activation/recovery qualification.
    No file is created or rewritten and no ACL is changed.
    """
    require(os.name == "nt")
    body_error = None
    try:
        root = Path(root)
        require(isinstance(names, list) and 0 < len(names) <= 512
                and all(isinstance(name, str) and re.fullmatch(
                    r"[a-z][a-z0-9_]{0,127}", name) is not None for name in names)
                and len(set(names)) == len(names))
        with ExitStack() as stack:
            # Ancestors need identity and no-delete sharing, not private ACLs:
            # system directories legitimately have broader authority. Permit
            # normal writes there while preventing namespace replacement.
            for parent in reversed(root.parents):
                stack.enter_context(_held_private_input(parent, directory=True, ancestor=True))
            stack.enter_context(_held_private_input(root, directory=True))
            require({p.name for p in root.iterdir()} == set(names))
            data = {name: stack.enter_context(_held_private_input(root / name))
                    for name in names}
            try:
                try:
                    yield data
                except BaseException as error:
                    body_error = error
                    raise
            finally:
                require({p.name for p in root.iterdir()} == set(names))
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        if error is body_error:
            raise
        raise ValueError(REFUSAL) from None


def write_empty_private_file(path: Path, value: str, *, expected_identities=None) -> None:
    """Initialize an existing empty private file through one verified writer.

    Never creates a file or changes its ACL. A failure after writing can leave
    partial material: preserve it for operator inspection, never retry blindly.
    Optional expected identities bind the whole path to an earlier held output
    allocation; a replacement is refused before the verified handle is written.
    """
    try:
        require(os.name == "nt")
        require(isinstance(value, str))
        payload = value.encode("utf-8")
        require(0 < len(payload) <= MAX_BYTES and b"\0" not in payload)
        if expected_identities is None:
            _private_file_bytes(path, payload)
        else:
            with _held_private_input(path,payload,_expected_identities=expected_identities):
                pass
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError(WRITE_REFUSAL) from None


def _private_file_bytes(path: Path, write_value: bytes | None = None) -> bytes:
    with _held_private_input(path, write_value) as data:
        return data


@contextmanager
def _held_private_input(path: Path, write_value: bytes | None = None, *, directory=False,
                        ancestor=False, max_bytes=MAX_BYTES, exclusive=False, public_file=False,
                        mutable_directory=False, _rename_to=None, _expected_identities=None):
    from ctypes import wintypes as w

    path = Path(path)
    if _rename_to is not None:
        _rename_to=Path(_rename_to)
        require(not directory and not ancestor and write_value is None and not exclusive
                and _rename_to.is_absolute() and _rename_to.parent==path.parent and _rename_to!=path)
    require(type(mutable_directory) is bool and (not mutable_directory or
            (directory and not ancestor and write_value is None and not exclusive)))
    before = _path_identities(path, directory=directory)
    if _expected_identities is not None:require(before==_expected_identities)
    require(not directory or write_value is None)
    require(not ancestor or write_value is None)
    require(type(public_file) is bool and (not public_file or
            (not directory and not ancestor and write_value is None and exclusive is False
             and not mutable_directory and _rename_to is None)))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    pp = ctypes.POINTER(pointer)

    class Info(ctypes.Structure):
        _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                    ("accessed", w.FILETIME), ("written", w.FILETIME),
                    ("volume", w.DWORD), ("size_high", w.DWORD),
                    ("size_low", w.DWORD), ("links", w.DWORD),
                    ("index_high", w.DWORD), ("index_low", w.DWORD)]

    class AclSize(ctypes.Structure):
        _fields_ = [("count", w.DWORD), ("used", w.DWORD), ("free", w.DWORD)]

    class FileId(ctypes.Structure):
        _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]

    def bind(dll, name, arguments, result):
        function = getattr(dll, name)
        function.argtypes, function.restype = arguments, result
        return function

    create = bind(kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, pointer,
                                         w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
    close = bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
    free = bind(kernel, "LocalFree", [pointer], pointer)
    info = bind(kernel, "GetFileInformationByHandle", [w.HANDLE, ctypes.POINTER(Info)], w.BOOL)
    extended_info = bind(kernel, "GetFileInformationByHandleEx",
                         [w.HANDLE, w.DWORD, pointer, w.DWORD], w.BOOL)
    volume = bind(kernel, "GetVolumeInformationByHandleW", [w.HANDLE, w.LPWSTR, w.DWORD,
                  ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD),
                  w.LPWSTR, w.DWORD], w.BOOL)
    read = bind(kernel, "ReadFile", [w.HANDLE, pointer, w.DWORD, ctypes.POINTER(w.DWORD), pointer], w.BOOL)
    write = bind(kernel, "WriteFile", [w.HANDLE, pointer, w.DWORD, ctypes.POINTER(w.DWORD), pointer], w.BOOL)
    flush = bind(kernel, "FlushFileBuffers", [w.HANDLE], w.BOOL)
    seek = bind(kernel, "SetFilePointerEx", [w.HANDLE, ctypes.c_longlong, pointer, w.DWORD], w.BOOL)
    descriptor = bind(security, "GetSecurityInfo", [w.HANDLE, w.DWORD, w.DWORD,
                      pp, pp, pp, pp, pp], w.DWORD)
    acl_info = bind(security, "GetAclInformation", [pointer, pointer, w.DWORD, w.DWORD], w.BOOL)
    ace = bind(security, "GetAce", [pointer, w.DWORD, pp], w.BOOL)
    sid_valid = bind(security, "IsValidSid", [pointer], w.BOOL)
    sid_size = bind(security, "GetLengthSid", [pointer], w.DWORD)
    sid_string = bind(security, "ConvertSidToStringSidW", [pointer, ctypes.POINTER(w.LPWSTR)], w.BOOL)
    process = bind(kernel, "GetCurrentProcess", [], w.HANDLE)
    open_token = bind(security, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
    token_info = bind(security, "GetTokenInformation", [w.HANDLE, w.DWORD, pointer,
                      w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)

    def sid_text(sid):
        require(bool(sid) and bool(sid_valid(sid)))
        text = w.LPWSTR()
        require(bool(sid_string(sid, ctypes.byref(text))))
        try:
            return text.value
        finally:
            free(ctypes.cast(text, pointer))

    token = w.HANDLE()
    require(bool(open_token(process(), 8, ctypes.byref(token))))
    try:
        needed = w.DWORD()
        token_info(token, 1, None, 0, ctypes.byref(needed))
        require(0 < needed.value <= 4096)
        buffer = ctypes.create_string_buffer(needed.value)
        require(bool(token_info(token, 1, buffer, len(buffer), ctypes.byref(needed))))
        user = sid_text(ctypes.cast(buffer, pp)[0])
    finally:
        close(token)

    # OPEN_EXISTING, OPEN_REPARSE_POINT, and no write/delete sharing. Hold this
    # exact handle for ACL proof, bounds checks and the entire read.
    # READ_ATTRIBUTES alone does not participate in all Windows sharing checks.
    # Request real read access even for namespace-only handles, while never
    # issuing a data read for them. RW sharing still permits application writes.
    access = 0x80000080 if ancestor else 0x80020080 | (
        0x40000000 if write_value is not None or exclusive else 0)
    if _rename_to is not None:access |= 0x00010000  # DELETE for rename of this verified handle.
    handle = create(str(path), access, 3 if ancestor else 1, None, 3,
                    0x00200000 | (0x02000000 if directory else 0), None)
    require(handle not in (None, ctypes.c_void_p(-1).value))
    try:
        def file_info():
            result = Info()
            require(bool(info(handle, ctypes.byref(result))))
            require(not result.attributes & 0x400)
            if directory:
                require(bool(result.attributes & 0x10))
            else:
                require(not result.attributes & 0x10 and result.links == 1
                        and (ancestor or result.size_high == 0 and result.size_low <= max_bytes))
            return result

        def file_identity(legacy):
            # CPython 3.12 changed Windows st_dev/st_ino to the full 64/128-bit
            # FILE_ID_INFO values. Earlier versions use BY_HANDLE_FILE_INFORMATION.
            # Compare the complete representation, never truncated volume bits.
            require(sys.implementation.name == "cpython")
            if sys.version_info >= (3, 12):
                full = FileId()
                require(bool(extended_info(handle, 18, ctypes.byref(full), ctypes.sizeof(full))))
                return full.volume, int.from_bytes(bytes(full.identifier), "little")
            return legacy.volume, legacy.index_high << 32 | legacy.index_low

        first = file_info()
        identity = file_identity(first)
        checked_identity(*identity, before[-1])
        filesystem = ctypes.create_unicode_buffer(32)
        require(bool(volume(handle, None, 0, None, None, None, filesystem, len(filesystem))))
        require(filesystem.value == "NTFS")

        def prove_acl():
            owner, dacl, allocated = pointer(), pointer(), pointer()
            require(descriptor(handle, 1, 5, ctypes.byref(owner), None,
                               ctypes.byref(dacl), None, ctypes.byref(allocated)) == 0)
            try:
                require(bool(dacl))  # A null DACL grants everyone full access.
                size = AclSize()
                require(bool(acl_info(dacl, ctypes.byref(size), ctypes.sizeof(size), 2)))
                require(1 <= size.count <= 3 and size.used <= 65535)
                entries = []
                for index in range(size.count):
                    entry = pointer()
                    require(bool(ace(dacl, index, ctypes.byref(entry))))
                    header = ctypes.string_at(entry, 8)
                    length = int.from_bytes(header[2:4], "little")
                    require(header[0] == 0 and length >= 16)
                    sid = entry.value + 8
                    require(bool(sid_valid(sid)) and sid_size(sid) <= length - 8)
                    entries.append((sid_text(sid), header[0], header[1],
                                    int.from_bytes(header[4:8], "little")))
                checked_acl(sid_text(owner), user, entries)
                return entries
            finally:
                free(allocated)

        initial_acl = None if ancestor or public_file else prove_acl()
        if write_value is not None:
            require(first.size_low == 0 and _path_identities(path) == before)
            buffer = ctypes.create_string_buffer(write_value)
            written = w.DWORD()
            require(bool(write(handle, buffer, len(write_value), ctypes.byref(written), None))
                    and written.value == len(write_value) and bool(flush(handle)))
            updated = file_info()
            require(updated.size_low == len(write_value)
                    and updated.attributes == first.attributes
                    and bytes(updated.created) == bytes(first.created)
                    and file_identity(updated) == identity
                    and prove_acl() == initial_acl)
            first = updated
            require(bool(seek(handle, 0, None, 0)))
        data = ctypes.create_string_buffer(first.size_low + 1 if not directory and not ancestor else 1)
        count = w.DWORD()
        if not directory and not ancestor:
            require(bool(read(handle, data, first.size_low + 1, ctypes.byref(count), None))
                    and count.value == first.size_low)
        last = file_info()
        def stable(value):
            if ancestor or mutable_directory:
                return (value.attributes, bytes(value.created), value.volume,
                        value.index_high, value.index_low)
            return (value.attributes, bytes(value.created), bytes(value.written),
                    value.volume, value.size_high, value.size_low, value.links,
                    value.index_high, value.index_low)
        require(stable(first) == stable(last) and file_identity(last) == identity
                and (ancestor or public_file or prove_acl() == initial_acl)
                and _path_identities(path, directory=directory) == before)
        if write_value is not None:
            require(data.raw[:count.value] == write_value)
        completed=False
        try:
            yield data.raw[:count.value]
            completed=True
        finally:
            # Recheck even if the bounded caller action raises. Ordinary
            # write/delete sharing was never granted in the interim.
            last = file_info()
            require(stable(first) == stable(last) and file_identity(last) == identity
                    and (ancestor or public_file or prove_acl() == initial_acl)
                    and _path_identities(path, directory=directory) == before)
            if completed and _rename_to is not None:
                destination=str(_rename_to)
                class RenameInfo(ctypes.Structure):
                    _fields_=[('replace',w.BOOL),('root',w.HANDLE),('length',w.DWORD),
                              ('name',ctypes.c_wchar*(len(destination)+1))]
                request=RenameInfo()
                request.replace=False;request.root=None
                request.length=len(destination.encode('utf-16-le'));request.name=destination
                rename=bind(kernel,'SetFileInformationByHandle',[w.HANDLE,ctypes.c_int,pointer,w.DWORD],w.BOOL)
                require(bool(rename(handle,3,ctypes.byref(request),ctypes.sizeof(request))))
                require(file_identity(file_info())==identity and prove_acl()==initial_acl
                        and _path_identities(_rename_to)==before)
    finally:
        close(handle)
