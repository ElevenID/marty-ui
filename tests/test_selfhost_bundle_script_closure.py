"""Bundled operator scripts must carry their local Python imports."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_frozen_cli_bundle_assets_match_the_published_asset_contract():
    manifest=json.loads((ROOT/'deploy-config/bundles/selfhost.json').read_bytes())
    corpus=json.loads((ROOT/'contracts/deployment-catalog-cli-behavior.json').read_bytes())
    cases=[case for case in corpus['cases'] if case['args']==['bundle-assets','selfhost']]
    assert len(cases)==1
    assert cases[0]['exit_code']==0 and cases[0]['stderr']==''
    assert cases[0]['stdout']==''.join('$REPO_ROOT/'+name+'\n' for name in manifest['assets'])


def test_bundled_operator_scripts_include_local_import_closure() -> None:
    manifest = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text(
        encoding="utf-8"))
    assets = set(manifest["assets"])
    missing: set[tuple[str, str]] = set()
    for asset in assets:
        if not asset.startswith("scripts/") or not asset.endswith(".py"):
            continue
        source = ast.parse((ROOT / asset).read_text(encoding="utf-8"))
        for node in ast.walk(source):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            elif isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            else:
                continue
            for module in modules:
                candidate = f"scripts/{module.split('.')[0]}.py"
                if (ROOT / candidate).is_file() and candidate not in assets:
                    missing.add((asset, candidate))
    assert not missing, f"bundled scripts omit local imports: {sorted(missing)}"


def export_manifest_assets(destination):
    """Export only catalog-owned assets, never the checkout's other helpers."""
    manifest = json.loads((ROOT/'deploy-config/bundles/selfhost.json').read_bytes())
    destination.mkdir()
    for name in manifest['assets']:
        source = ROOT/name;target = destination/name
        assert source.is_relative_to(ROOT) and not Path(name).is_absolute() and '..' not in Path(name).parts
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():shutil.copytree(source, target, dirs_exist_ok=True)
        else:shutil.copyfile(source, target)
    return destination


ISOLATED_READER = r'''
import importlib,json,pathlib,sys
scripts=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(scripts))
for name in ['selfhost_windows_selection','selfhost_windows_website','selfhost_windows_website_store',
             'selfhost_windows_website_guard','selfhost_windows_website_stage','selfhost_windows_website_edge',
             'selfhost_windows_website_verify',
             'selfhost_windows_website_reconcile',
             'selfhost_windows_website_abort_release',
             'selfhost_windows_website_backout',
             'selfhost_windows_website_forward','selfhost_windows_website_owner','selfhost_windows_website_current_backout',
             'selfhost_windows_product_journal',
             'selfhost_windows_product','selfhost_windows_product_probe','selfhost_windows_product_deploy',
             'selfhost_windows_staging_recovery','selfhost_windows_expired_origin','selfhost_windows_recovery_activation',
             'selfhost_windows_recovery_journal','selfhost_windows_recovery_operator',
             'selfhost_windows_recovery_finish','selfhost_windows_recovery_leaf_caps']:
 module=importlib.import_module(name)
 assert pathlib.Path(module.__file__).resolve().parent==scripts
for module in list(sys.modules.values()):
 path=getattr(module,'__file__',None)
 if path and pathlib.Path(path).name.startswith(('selfhost_','package_web_','website_','installer_')):
  assert pathlib.Path(path).resolve().parent==scripts
if len(sys.argv)>2:
 from selfhost_windows_selection import status
 print(json.dumps(status(pathlib.Path(sys.argv[2]))))
else:print(json.dumps({'isolated_imports':True}))
'''


def isolated_reader(export, config=None):
    command = [sys.executable, '-I', '-B', '-c', ISOLATED_READER, str(export/'scripts')]
    if config is not None:command.append(str(config))
    result = subprocess.run(command, cwd=export, capture_output=True, encoding='utf-8', timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_product_imports_from_manifest_export_without_checkout_fallback(tmp_path):
    exported = export_manifest_assets(tmp_path/'exported')
    assert isolated_reader(exported) == {'isolated_imports': True}


WEBSITE_READER = r'''
import importlib,json,pathlib,sys
scripts=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(scripts))
for name in ['website_release','website_provenance','web_auth',
             'package_web_composition','website_producer_policy']:
 module=importlib.import_module(name)
 assert pathlib.Path(module.__file__).resolve().parent==scripts
import website_release as release
import website_producer_policy as policy
selected=json.load(sys.stdin)
assert release.validate_release(selected)==selected
assert policy.validate_producer(selected['producer'],role='website')==selected['producer']
for role in ['application','composition']:
 try:policy.validate_producer(selected['producer'],role=role)
 except ValueError:pass
 else:raise AssertionError('Standalone website was allowed to produce '+role)
print(json.dumps({'standalone_contract_from_bundle':True}))
'''


@pytest.mark.parametrize('omit_policy', [False, True])
def test_standalone_website_contract_from_bundle_requires_its_bundled_policy(tmp_path, omit_policy):
    exported = export_manifest_assets(tmp_path/'exported')
    policy = exported/'scripts/website_producer_policy.py'
    assert policy.is_file()
    if omit_policy:
        policy.unlink()
    fixture = json.loads((ROOT/'tests/fixtures/standalone-website-release-v2.json').read_bytes())
    assert fixture['purpose']=='synthetic-contract-fixture-not-release-evidence'
    result = subprocess.run(
        [sys.executable, '-I', '-B', '-c', WEBSITE_READER, str(exported/'scripts')],
        cwd=exported, input=json.dumps(fixture['release']), capture_output=True, encoding='utf-8', timeout=60,
    )
    if omit_policy:
        assert result.returncode != 0
        assert "No module named 'website_producer_policy'" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)=={'standalone_contract_from_bundle': True}


@pytest.mark.skipif(sys.platform != 'win32', reason='Actual private NTFS journal status')
def test_ordinary_and_product_status_from_isolated_export(monkeypatch):
    # Both data roots stay private, while the child interpreter sees only the
    # exported code and ordinary installed Python packages, never this checkout.
    sys.path.insert(0, str(ROOT/'tests'))
    from test_selfhost_windows_selection import fixture
    from test_windows_product_journal import installed
    import selfhost_windows_selection as selection
    with fixture(monkeypatch) as (root, _phase, _tx, _outcome, path, _config):
        selection.adopt(path)
        exported = export_manifest_assets(root/'exported')
        state = isolated_reader(exported, path)
        assert state['decision'] == 'adopted' and state['sequence'] == 1
    with installed(monkeypatch) as data:
        exported = export_manifest_assets(data['root']/'exported')
        state = isolated_reader(exported, data['path'])
        assert state['decision'] == 'product-selected-new' and state['generation_sequence'] == 1
