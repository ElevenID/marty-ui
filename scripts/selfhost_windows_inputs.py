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
        require(sid in allowed and sid not in seen and kind == 0
                and flags & ~0x13 == 0 and rights == FULL_CONTROL)
        seen.add(sid)
    require(user in seen)


def checked_identity(volume: int, index: int, expected: tuple[int, int]) -> None:
    # File indices are volume-local: an index match alone cannot bind the handle.
    require((volume, index) == expected)


def _path_identities(path: Path) -> list[tuple[int, int]]:
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
        require(stat.S_ISREG(info.st_mode) if item == path else stat.S_ISDIR(info.st_mode))
        result.append((info.st_dev, info.st_ino))
    return result


def read_private_file(path: Path) -> str:
    require(os.name == "nt")
    # Native errors deliberately do not expose filenames, input bytes or SIDs.
    try:
        return _read_private_file(path)
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError(REFUSAL) from None


def write_empty_private_file(path: Path, value: str) -> None:
    """Initialize an existing empty private file through one verified writer.

    Never creates a file or changes its ACL. A failure after writing can leave
    partial material: preserve it for operator inspection, never retry blindly.
    """
    try:
        require(os.name == "nt")
        require(isinstance(value, str))
        payload = value.encode("utf-8")
        require(0 < len(payload) <= MAX_BYTES and b"\0" not in payload)
        _read_private_file(path, payload)
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError(WRITE_REFUSAL) from None


def _read_private_file(path: Path, write_value: bytes | None = None) -> str:
    from ctypes import wintypes as w

    path = Path(path)
    before = _path_identities(path)
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
    access = 0x80020080 | (0x40000000 if write_value is not None else 0)
    handle = create(str(path), access, 1, None, 3, 0x00200000, None)
    require(handle not in (None, ctypes.c_void_p(-1).value))
    try:
        def file_info():
            result = Info()
            require(bool(info(handle, ctypes.byref(result))))
            require(not result.attributes & (0x400 | 0x10)
                    and result.links == 1 and result.size_high == 0
                    and result.size_low <= MAX_BYTES)
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

        initial_acl = prove_acl()
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
        data = ctypes.create_string_buffer(first.size_low + 1)
        count = w.DWORD()
        require(bool(read(handle, data, first.size_low + 1, ctypes.byref(count), None))
                and count.value == first.size_low)
        last = file_info()
        def stable(value):
            return (value.attributes, bytes(value.created), bytes(value.written),
                    value.volume, value.size_high, value.size_low, value.links,
                    value.index_high, value.index_low)
        require(stable(first) == stable(last) and file_identity(last) == identity
                and prove_acl() == initial_acl
                and _path_identities(path) == before)
        if write_value is not None:
            require(data.raw[:count.value] == write_value)
        # Match Path.read_text's universal-newline contract at the shared owner.
        return data.raw[:count.value].decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    finally:
        close(handle)
