"""Execute the shipped UI startup hook against disposable static directories."""
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = "https://marty.example.com:8443"
ALIAS = "https://203.0.113.10:8443"


def prepare(tmp_path, **values):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "index.html").write_text("<html><!-- SELFHOST_GOOGLE_SITE_VERIFICATION --><main>Marty</main></html>")
    (source / "console").mkdir()
    (source / "console/index.html").write_text("<html><main>Console</main></html>")
    (source / "assets").mkdir()
    (source / "assets/shared.js").write_text("console.log('shared application asset')")
    (target / "retained.txt").write_text("retained until inputs pass")
    script = (ROOT / "scripts/ui-selfhost-start.sh").read_text()
    script = script.replace(". /scripts/load-secrets-env.sh", ": # no secrets in this fixture")
    script = script.replace('SOURCE_DIR="/opt/marty-ui-static"', "SOURCE_DIR=" + shlex.quote(str(source)))
    script = script.replace('TARGET_DIR="/usr/share/nginx/html"', "TARGET_DIR=" + shlex.quote(str(target)))
    env = {k: v for k, v in os.environ.items() if k not in {
        "UI_CANONICAL_ORIGIN", "UI_PUBLIC_ENTRY_ORIGINS", "GOOGLE_ANALYTICS_MEASUREMENT_ID", "GOOGLE_SITE_VERIFICATION", "UI_ENABLED_SECTIONS",
    }}
    result = subprocess.run(["sh"], input=script, text=True, capture_output=True, env={**env, **values})
    return result, target


def runtime_config(target):
    result = subprocess.run([
        "node", "--input-type=module", "-e",
        "import fs from 'node:fs'; import vm from 'node:vm'; const context={window:{}}; "
        "vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context); "
        "process.stdout.write(JSON.stringify(context.window.__MARTY_RUNTIME_CONFIG__));",
        str(target / "runtime-config.js"),
    ], check=True, text=True, capture_output=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize("alias", [ALIAS, "https://[2001:db8::1]:8443"])
def test_startup_emits_the_bound_public_origin_and_alias(tmp_path, alias):
    result, target = prepare(tmp_path, UI_CANONICAL_ORIGIN=CANONICAL,
                             UI_PUBLIC_ENTRY_ORIGINS=json.dumps([alias], separators=(",", ":")))
    assert result.returncode == 0, result.stderr
    assert runtime_config(target)["hosting"] == {"canonicalOrigin": CANONICAL, "publicEntryOrigins": [alias]}
    assert "<main>Marty</main>" in (target / "index.html").read_text()


def test_existing_runtime_without_hosting_inputs_keeps_normal_mode(tmp_path):
    result, target = prepare(tmp_path)
    assert result.returncode == 0, result.stderr
    assert runtime_config(target)["hosting"] == {"canonicalOrigin": "", "publicEntryOrigins": []}
    assert runtime_config(target)["web"] == {"enabled_sections": ["public", "console"]}


@pytest.mark.parametrize("choice,expected", [
    ("public,console", ["public", "console"]),
    ("public", ["public"]), ("console", ["console"]), ("none", []),
])
def test_startup_removes_disabled_documents_and_emits_the_same_client_selection(tmp_path, choice, expected):
    result, target = prepare(tmp_path, UI_ENABLED_SECTIONS=choice)
    assert result.returncode == 0, result.stderr
    assert (target / "index.html").exists() == ("public" in expected)
    assert (target / "console/index.html").exists() == ("console" in expected)
    assert (target / ".marty-ui-public-disabled").exists() == ("public" not in expected)
    assert (target / ".marty-ui-console-disabled").exists() == ("console" not in expected)
    assert (target / ".marty-ui-disabled").exists() == (not expected)
    if expected:
        assert runtime_config(target)["web"] == {"enabled_sections": expected}
        assert (target / "assets/shared.js").is_file()
    else:
        assert not (target / "runtime-config.js").exists()
        assert not (target / "assets").exists()


@pytest.mark.parametrize("choice", ["", "all", "marketing", "public,public", "console,public", "public,", "none,console", "console\n", "public;echo injected"])
def test_invalid_section_selection_preserves_the_existing_files(tmp_path, choice):
    result, target = prepare(tmp_path, UI_ENABLED_SECTIONS=choice)
    assert result.returncode != 0
    assert (target / "retained.txt").read_text() == "retained until inputs pass"


@pytest.mark.parametrize("values", [
    {"UI_CANONICAL_ORIGIN": "https://marty.example.com';throw Error('injected');//"},
    {"UI_CANONICAL_ORIGIN": CANONICAL + "\n';throw Error('injected');//"},
    {"UI_CANONICAL_ORIGIN": CANONICAL, "UI_PUBLIC_ENTRY_ORIGINS": '["https://203.0.113.10:8443"];throw Error("injected")'},
    {"UI_CANONICAL_ORIGIN": CANONICAL, "UI_PUBLIC_ENTRY_ORIGINS": '["https://203.0.113.10:8443"]\nthrow Error("injected")'},
    {"UI_CANONICAL_ORIGIN": CANONICAL, "UI_PUBLIC_ENTRY_ORIGINS": json.dumps([ALIAS, ALIAS])},
    {"UI_CANONICAL_ORIGIN": CANONICAL, "UI_PUBLIC_ENTRY_ORIGINS": '["https://another.example.com"]'},
    {"UI_PUBLIC_ENTRY_ORIGINS": json.dumps([ALIAS])},
])
def test_invalid_runtime_inputs_fail_before_replacing_static_assets(tmp_path, values):
    result, target = prepare(tmp_path, **values)
    assert result.returncode != 0
    assert (target / "retained.txt").read_text() == "retained until inputs pass"
    assert not (target / "runtime-config.js").exists()
