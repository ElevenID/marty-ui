#!/usr/bin/env python3
"""Diagnose the synthetic Windows test fixture; never alter token or input policy."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def probe(label, context):
    failures = []
    previous = sys.gettrace()

    def trace(frame, event, _argument):
        if (event == 'exception' and frame.f_code.co_name == 'require'
                and Path(frame.f_code.co_filename).name == 'selfhost_windows_inputs.py'
                and len(failures) < 8):
            caller = frame.f_back
            failures.append({'function': caller.f_code.co_name, 'line': caller.f_lineno,
                             'win32_last_error': ctypes.get_last_error()})
        return trace

    result = {'probe': label, 'passed': False, 'failed_checks': failures}
    try:
        sys.settrace(trace)
        with context:
            pass
        result['passed'] = True
    except (OSError, ValueError, TypeError) as error:
        result['error_type'] = type(error).__name__
    finally:
        sys.settrace(previous)
    return result


def fixture_metadata(root, token):
    quoted_root = str(root).replace("'", "''")
    quoted_token = str(token).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop';$data=@{metadata_query_succeeded=$false};$stage='identity';"
        "try{$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$user=$identity.User.Value;"
        "$data.token_owner_matches_user=($identity.Owner.Value -eq $user);"
        "$rootPath='" + quoted_root + "';$filePath='" + quoted_token + "';"
        "$stage='root-owner';$rootAcl=[IO.Directory]::GetAccessControl($rootPath);"
        "$rootOwner=$rootAcl.GetOwner([Security.Principal.SecurityIdentifier]);"
        "$data.root_owner_matches_user=($rootOwner.Value -eq $user);"
        "$stage='file-owner';$fileAcl=[IO.File]::GetAccessControl($filePath);"
        "$fileOwner=$fileAcl.GetOwner([Security.Principal.SecurityIdentifier]);"
        "$data.file_owner_matches_user=($fileOwner.Value -eq $user);"
        "$data.file_owner_is_administrators=($fileOwner.Value -eq 'S-1-5-32-544');"
        "$stage='filesystem';$drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($rootPath));"
        "$data.filesystem=$drive.DriveFormat;$data.metadata_query_succeeded=$true"
        "}catch{$data.metadata_error_stage=$stage;"
        "$data.metadata_error_type=$_.Exception.GetType().FullName;"
        "$data.metadata_error_id=$_.FullyQualifiedErrorId};$data | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                                capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            return {'metadata_query_succeeded': False, 'metadata_process_exit': result.returncode,
                    'metadata_error_type': 'PowerShellProcessFailure'}
        if len(result.stdout) > 8192:
            raise ValueError('Metadata exceeded diagnostic bound')
        value = json.loads(result.stdout)
        if type(value) is not dict or type(value.get('metadata_query_succeeded')) is not bool:
            raise ValueError('Metadata did not return a diagnostic record')
        return value
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return {'metadata_query_succeeded': False, 'metadata_error_type': type(error).__name__}


def inspect_environment():
    if os.name != 'nt':
        raise SystemExit('Synthetic NTFS environment probe requires Windows')
    sys.path.insert(0, str(ROOT / 'tests'))
    from test_selfhost_windows_inputs import private_fixture, windows

    # The helper creates and removes a dedicated synthetic directory only.
    # Read-only tracing records failed policy callsites, never frame locals,
    # exception messages, SIDs, token handles, or fixture payloads.
    with private_fixture() as (root, token):
        result = {'schema': 'marty.synthetic-windows-source-environment/v1',
                  'guard_sha256': hashlib.sha256(Path(windows.__file__).read_bytes()).hexdigest()}
        result['probes'] = [
            probe('private-directory', windows._held_private_input(root, directory=True)),
            probe('namespace', windows.hold_storage_namespace(root)),
            probe('public-file', windows.hold_public_input(token)),
            probe('private-file', windows.hold_private_input(token)),
        ]
        result.update(fixture_metadata(root, token))
    return result


def main():
    result = inspect_environment()
    print(json.dumps(result, sort_keys=True))
    if not all(item['passed'] for item in result['probes']):
        raise SystemExit('Synthetic Windows test environment does not satisfy unchanged NTFS custody')


if __name__ == '__main__':
    main()
