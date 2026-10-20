from __future__ import annotations

from unittest.mock import patch
from pathlib import Path
import pytest

from scripts.prepare_canvas_source_builder import GIB, main, require_capacity, require_hosted_vm


def environment() -> dict[str, str]:
    return dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', ImageOS='ubuntu24',
                GITHUB_REPOSITORY='ElevenID/marty-ui', GITHUB_REF='refs/heads/main',
                GITHUB_EVENT_NAME='workflow_dispatch')


@pytest.mark.parametrize('change', [dict(RUNNER_ENVIRONMENT='self-hosted'), dict(ImageOS='ubuntu22'),
                                  dict(GITHUB_REF='refs/heads/feature'), dict(GITHUB_EVENT_NAME='pull_request'),
                                  dict(GITHUB_REPOSITORY='other/fork'), dict(GITHUB_ACTIONS='false')])
def test_reclamation_rejects_non_disposable_or_unreviewed_context(change):
    with pytest.raises(RuntimeError, match='reviewed disposable'):
        require_hosted_vm(environment() | change, 'linux', 'ID=ubuntu\nVERSION_ID="24.04"\n')


def test_local_invocation_never_reaches_docker_or_sdk_removal(tmp_path):
    with patch('sys.argv', ['prepare', '--reclaim-hosted-sdks', '--output', str(tmp_path / 'receipt.json')]), \
            patch.dict('os.environ', {}, clear=True), \
            patch('scripts.prepare_canvas_source_builder.Path.read_text', return_value='ID=ubuntu\nVERSION_ID="24.04"\n'), \
            patch('scripts.prepare_canvas_source_builder.docker') as docker, \
            patch('scripts.prepare_canvas_source_builder.subprocess.run') as remove:
        assert main() == 1
        docker.assert_not_called()
        remove.assert_not_called()


def test_source_builder_is_separate_from_beta_runtime_qualification():
    root = Path(__file__).resolve().parents[1]
    source = (root / '.github/workflows/canvas-oss-image.yml').read_text(encoding='utf-8')
    runtime = (root / '.github/workflows/canvas-oss-portability.yml').read_text(encoding='utf-8')
    assert 'runs-on: ubuntu-24.04' in source
    assert 'prepare_canvas_source_builder.py --reclaim-hosted-sdks' in source
    assert 'check_canvas_oss_runner.py' not in source
    assert 'canvas-oss-wsl2' in runtime
    assert 'check_canvas_oss_runner.py' in runtime
    assert 'prepare_canvas_source_builder.py' not in runtime


def test_capacity_checks_real_free_space_and_preserves_existing_bounds():
    require_capacity(80 * GIB, 12 * GIB)
    with pytest.raises(RuntimeError, match='80 GiB'):
        require_capacity(80 * GIB - 1, 16 * GIB)
    with pytest.raises(RuntimeError, match='12 GiB'):
        require_capacity(100 * GIB, 12 * GIB - 1)
