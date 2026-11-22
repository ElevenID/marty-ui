"""Public native qualification must execute the retained NTFS source cases."""
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/windows-owner-source.yml'
NATIVE_CASES = {
    'test_native_install_publishes_private_source_and_refuses_overwrite',
    'test_native_source_inventory_refuses_unsafe_placement[broad-acl]',
    'test_native_source_inventory_refuses_unsafe_placement[hardlink]',
    'test_native_source_inventory_refuses_unsafe_placement[untracked-bytecode]',
    'test_native_source_inventory_refuses_unsafe_placement[junction]',
    'test_native_allocation_replacement_is_rejected_before_source_write',
    'test_native_late_source_acl_failure_preserves_pending_without_ready',
    'test_isolated_generated_runner_resolves_original_anchor_and_refuses_late_source_failure',
}


def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))


def native_step():
    return workflow()['jobs']['source-custody']['steps'][-1]


def test_windows_source_workflow_uses_only_public_native_synthetic_execution():
    document = workflow()
    events = document.get('on') or document[True]
    assert events == {'pull_request': None, 'merge_group': {'types': ['checks_requested']}}
    assert document['permissions'] == {'contents': 'read'}
    assert document['concurrency'] == {
        'group': '${{ github.workflow }}-${{ github.event.pull_request.number || github.event.merge_group.head_sha || github.ref }}',
        'cancel-in-progress': "${{ github.event_name == 'pull_request' }}",
    }
    assert set(document['jobs']) == {'source-custody'}
    job = document['jobs']['source-custody']
    assert job['if'] == 'github.event.repository.private == false'
    assert job['runs-on'] == 'windows-2022' and 0 < job['timeout-minutes'] <= 10
    assert job['defaults']['run']['shell'] == 'pwsh'
    assert 'permissions' not in job and 'environment' not in job
    assert not job.get('continue-on-error')
    steps = job['steps']
    assert [step['uses'] for step in steps if 'uses' in step] == [
        'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
        'actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0',
    ]
    assert steps[0]['with'] == {'persist-credentials': False}
    assert steps[1]['with'] == {'python-version': '3.12'}
    assert all(not step.get('continue-on-error') and 'if' not in step for step in steps)
    source = WORKFLOW.read_text(encoding='utf-8')
    assert 'secrets.' not in source and 'github.token' not in source
    commands = '\n'.join(step.get('run', '') for step in steps)
    assert "assert os.name == 'nt'" in commands
    assert "assert revision == os.environ['GITHUB_SHA']" in commands
    assert "'HEAD^{tree}'" in commands and "print('Native Windows source tree:', tree)" in commands
    assert re.findall(r'\btests/[^\s`]+\.py', commands) == [
        'tests/test_windows_owner_source_bundle.py',
        'tests/test_windows_source_install.py',
        'tests/test_windows_source_install_ntfs.py',
    ]
    assert '--junitxml=$report' in native_step()['run']
    assert "if ($LASTEXITCODE -ne 0)" in native_step()['run']


@pytest.mark.parametrize('fault', [None, 'additional-case', 'missing', 'empty', 'skipped',
                                  'failure', 'error', 'duplicate', 'wrong-module', 'counter'])
def test_native_completion_gate_executes_and_rejects_missing_or_skipped_evidence(tmp_path, fault):
    root = ET.Element('testsuites')
    suite = ET.SubElement(root, 'testsuite', tests=str(len(NATIVE_CASES)),
                          errors='0', failures='0', skipped='0')
    for name in sorted(NATIVE_CASES):
        ET.SubElement(suite, 'testcase', classname='tests.test_windows_source_install_ntfs', name=name)
    first = suite[0]
    if fault == 'additional-case':
        ET.SubElement(suite, 'testcase', classname='tests.test_windows_source_install_ntfs', name='test_future_case')
        suite.set('tests', str(len(NATIVE_CASES) + 1))
    elif fault == 'missing':
        suite.remove(first)
        suite.set('tests', str(len(NATIVE_CASES) - 1))
    elif fault == 'empty':
        suite.clear()
        suite.attrib.update(tests='0', errors='0', failures='0', skipped='0')
    elif fault in {'skipped', 'failure', 'error'}:
        # Tags alone must refuse even if a counter falsely claims zero.
        ET.SubElement(first, fault)
    elif fault == 'duplicate':
        ET.SubElement(suite, 'testcase', **first.attrib)
        suite.set('tests', str(len(NATIVE_CASES) + 1))
    elif fault == 'wrong-module':
        first.set('classname', 'tests.unrelated')
    elif fault == 'counter':
        suite.set('skipped', '1')
    ET.ElementTree(root).write(tmp_path / 'windows-owner-source-native.xml', encoding='utf-8')
    code = re.search(r"@'\n(.*?)\n'@ \| python -", native_step()['run'], re.DOTALL)
    assert code is not None
    result = subprocess.run([sys.executable, '-c', code.group(1)], capture_output=True, text=True,
                            env={**os.environ, 'RUNNER_TEMP': str(tmp_path)}, timeout=10)
    if fault in {None, 'additional-case'}:
        assert result.returncode == 0, result.stderr
        assert 'Qualified ' in result.stdout
    else:
        assert result.returncode != 0 and result.stdout == ''
        assert 'zero skips or failures' in result.stderr
