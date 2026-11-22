#!/usr/bin/env python3
"""Run only synthetic NTFS source tests with a scoped current-user default owner.

Hosted runners use an elevated token whose default owner can be Administrators.
This test-process setup never changes the production input guard, account policy,
existing file owners or ACLs. Its original token owner is restored before success.
"""
import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

from probe_windows_source_environment import inspect_environment

NATIVE_SUITES = ('tests/test_windows_source_install_ntfs.py',
                 'tests/test_windows_source_caller_ntfs.py')
CHILD_PAYLOAD = b'PUBLIC_SYNTHETIC_ISOLATED_CHILD\n'


def require(value, message='Synthetic current-user owner proof failed'):
    if not value:
        raise RuntimeError(message)


class ProcessTokenOwner:
    """Retain native SID storage while changing only this process TokenOwner."""
    def __init__(self):
        from ctypes import wintypes as w

        require(os.name == 'nt')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        security = ctypes.WinDLL('advapi32', use_last_error=True)

        def bind(dll, name, arguments, result):
            function = getattr(dll, name)
            function.argtypes, function.restype = arguments, result
            return function

        pointer = ctypes.c_void_p
        current = bind(kernel, 'GetCurrentProcess', [], w.HANDLE)
        open_token = bind(security, 'OpenProcessToken',
                          [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
        self._close = bind(kernel, 'CloseHandle', [w.HANDLE], w.BOOL)
        self._query = bind(security, 'GetTokenInformation',
                           [w.HANDLE, w.DWORD, pointer, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)
        self._set = bind(security, 'SetTokenInformation',
                         [w.HANDLE, w.DWORD, pointer, w.DWORD], w.BOOL)
        self._valid_sid = bind(security, 'IsValidSid', [pointer], w.BOOL)
        self._sid_size = bind(security, 'GetLengthSid', [pointer], w.DWORD)
        self.handle = w.HANDLE()
        self._check(open_token(current(), 0x0008 | 0x0080, ctypes.byref(self.handle)), 'open')
        try:
            self.user_buffer, self.user_sid, self.user = self._read(1)  # TokenUser.
            self.owner_buffer, self.owner_sid, self.original = self._read(4)  # TokenOwner.
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(value, operation):
        require(bool(value), f'Synthetic TokenOwner {operation} failed (Win32 {ctypes.get_last_error()})')

    def _read(self, information_class):
        from ctypes import wintypes as w

        needed = w.DWORD()
        self._query(self.handle, information_class, None, 0, ctypes.byref(needed))
        require(0 < needed.value <= 4096)
        buffer = ctypes.create_string_buffer(needed.value)
        self._check(self._query(self.handle, information_class, buffer, len(buffer), ctypes.byref(needed)), 'query')
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        require(sid is not None and ctypes.addressof(buffer) <= sid < ctypes.addressof(buffer) + len(buffer))
        self._check(self._valid_sid(sid), 'validate SID')
        length = self._sid_size(sid)
        require(0 < length <= 68 and sid + length <= ctypes.addressof(buffer) + len(buffer))
        return buffer, sid, ctypes.string_at(sid, length)

    def owner(self):
        return self._read(4)[2]

    def _set_owner(self, sid):
        # TOKEN_OWNER contains one pointer to a SID already retained above.
        request = ctypes.c_void_p(sid)
        self._check(self._set(self.handle, 4, ctypes.byref(request), ctypes.sizeof(request)), 'set')

    def use_user(self):
        self._set_owner(self.user_sid)

    def restore_original(self):
        self._set_owner(self.owner_sid)

    def close(self):
        self._check(self._close(self.handle), 'close')


@contextmanager
def synthetic_current_user_owner(token_factory=ProcessTokenOwner):
    token = token_factory()
    try:
        # Restoration is protected before either setup or its verification.
        token.use_user()
        require(token.owner() == token.user)
        yield
    finally:
        try:
            token.restore_original()
            require(token.owner() == token.original, 'Synthetic process default owner was not restored exactly')
        finally:
            token.close()


def prove_parent_and_isolated_child_creation():
    from test_selfhost_windows_inputs import private_fixture, windows

    with private_fixture() as (root, parent_file):
        with windows.hold_private_input(parent_file) as body:
            require(body == parent_file.read_bytes())
        child_file = root / 'isolated-child.token'
        command = (
            "import pathlib,sys; assert sys.flags.isolated and sys.dont_write_bytecode; "
            "path=pathlib.Path(sys.argv[1]); "
            "stream=path.open('xb'); stream.write(b'PUBLIC_SYNTHETIC_ISOLATED_CHILD\\n'); stream.close()"
        )
        subprocess.run([sys.executable, '-I', '-B', '-c', command, str(child_file)],
                       capture_output=True, check=True, timeout=15)
        with windows.hold_private_input(child_file) as body:
            require(body == CHILD_PAYLOAD)


def execute_suite(report, *, token_factory=ProcessTokenOwner):
    import pytest

    before = inspect_environment()
    print(json.dumps({'phase': 'original-token', **before}, sort_keys=True), flush=True)
    with synthetic_current_user_owner(token_factory):
        configured = inspect_environment()
        print(json.dumps({'phase': 'synthetic-current-user-token', **configured}, sort_keys=True), flush=True)
        require(all(item['passed'] for item in configured['probes']))
        prove_parent_and_isolated_child_creation()
        print('Unchanged NTFS custody verified fresh parent and isolated child outputs', flush=True)
        result = pytest.main(['-q', *NATIVE_SUITES, '--junitxml=' + str(report)])
    # A successful pytest report cannot override restoration or close failure.
    print('Synthetic test process default owner restored exactly', flush=True)
    return int(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--junitxml', type=Path, required=True)
    args = parser.parse_args()
    require(os.name == 'nt' and sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12))
    require(args.junitxml.is_absolute() and not args.junitxml.exists())
    return execute_suite(args.junitxml)


if __name__ == '__main__':
    raise SystemExit(main())
