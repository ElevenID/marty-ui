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
        "ORGANIZATION_CREATION_ENABLED",
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
    assert runtime_config(target)["organizationCreationEnabled"] is False


@pytest.mark.parametrize("choice,expected", [("true", True), ("false", False)])
def test_startup_binds_organization_creation_to_backend_setting(tmp_path, choice, expected):
    result, target = prepare(tmp_path, ORGANIZATION_CREATION_ENABLED=choice)
    assert result.returncode == 0, result.stderr
    assert runtime_config(target)["organizationCreationEnabled"] is expected


@pytest.mark.parametrize("choice", ["", "1", "yes", "TRUE", "false;throw Error('injected')"])
def test_invalid_organization_setting_preserves_existing_assets(tmp_path, choice):
    result, target = prepare(tmp_path, ORGANIZATION_CREATION_ENABLED=choice)
    assert result.returncode != 0
    assert (target / "retained.txt").read_text() == "retained until inputs pass"


@pytest.mark.parametrize("choice,expected", [("true", True), ("false", False)])
def test_production_hook_preserves_pages_and_binds_organization_setting(tmp_path, choice, expected):
    target = tmp_path / "production"
    target.mkdir()
    page = target / "index.html"
    page.write_text("<h1>Prerendered production homepage</h1>")
    script = (ROOT / "scripts/ui-production-start.sh").read_text().replace(
        'TARGET_DIR="/usr/share/nginx/html"', "TARGET_DIR=" + shlex.quote(str(target)))
    script = script.replace(". /scripts/load-secrets-env.sh", ": # no secrets in this fixture")
    result = subprocess.run(["sh"], input=script, text=True, capture_output=True,
                            env={"PATH": os.environ["PATH"], "ORGANIZATION_CREATION_ENABLED": choice})
    assert result.returncode == 0, result.stderr
    assert runtime_config(target)["organizationCreationEnabled"] is expected
    assert page.read_text() == "<h1>Prerendered production homepage</h1>"


def test_production_hook_reads_public_files_and_refreshes_every_prerendered_head(tmp_path):
    target = tmp_path / "production"
    (target / "pricing").mkdir(parents=True)
    pages = [target / "index.html", target / "pricing/index.html"]
    for page in pages:
        page.write_text('<html><head><title>Production</title></head><body><h1>Page</h1></body></html>')
    ga, verification = tmp_path / "ga", tmp_path / "verification"
    ga.write_text("G-TEST123\n")
    verification.write_text('public-verify<&"token\n')
    script = (ROOT / "scripts/ui-production-start.sh").read_text()
    script = script.replace('TARGET_DIR="/usr/share/nginx/html"', "TARGET_DIR=" + shlex.quote(str(target)))
    script = script.replace(". /scripts/load-secrets-env.sh", ". " + shlex.quote(str(ROOT / "scripts/load-secrets-env.sh")))
    env = {"PATH": os.environ["PATH"], "GOOGLE_ANALYTICS_MEASUREMENT_ID_FILE": str(ga),
           "GOOGLE_SITE_VERIFICATION_FILE": str(verification)}
    for value in ['public-verify<&"token', "replacement", ""]:
        verification.write_text(value + "\n")
        result = subprocess.run(["sh"], input=script, text=True, capture_output=True, env=env)
        assert result.returncode == 0, result.stderr
        assert runtime_config(target)["googleAnalyticsMeasurementId"] == "G-TEST123"
        for page in pages:
            text = page.read_text()
            assert '<h1>Page</h1>' in text
            assert text.count('name="google-site-verification"') == bool(value)
            if value.startswith("public"):
                assert 'content="public-verify&lt;&amp;&quot;token"' in text
            elif value:
                assert 'content="replacement"' in text
                assert "public-verify" not in text


@pytest.mark.parametrize("audience", ["customer", "production"])
@pytest.mark.parametrize("value", ["G-test", "UA-12345-1", "G-ABC'", "G-ABC\\", "G-ABC\nthrow Error('injected')"])
def test_invalid_ga_identifier_is_rejected_before_any_runtime_or_page_change(tmp_path, audience, value):
    if audience == "customer":
        result, target = prepare(tmp_path, GOOGLE_ANALYTICS_MEASUREMENT_ID=value)
        retained = "retained.txt"
        expected = "retained until inputs pass"
    else:
        target = tmp_path / "production"
        target.mkdir()
        retained, expected = "index.html", "<head></head><h1>Retained page</h1>"
        (target / retained).write_text(expected)
        script = (ROOT / "scripts/ui-production-start.sh").read_text()
        script = script.replace('TARGET_DIR="/usr/share/nginx/html"', "TARGET_DIR=" + shlex.quote(str(target)))
        script = script.replace(". /scripts/load-secrets-env.sh", ": # no secrets in this fixture")
        result = subprocess.run(["sh"], input=script, text=True, capture_output=True,
                                env={"PATH": os.environ["PATH"], "GOOGLE_ANALYTICS_MEASUREMENT_ID": value})
    assert result.returncode != 0
    assert "must be a GA4 measurement identifier" in result.stderr
    assert (target / retained).read_text() == expected
    assert not (target / "runtime-config.js").exists()


def test_customer_valid_ga_identifier_is_safe_javascript(tmp_path):
    result, target = prepare(tmp_path, GOOGLE_ANALYTICS_MEASUREMENT_ID="G-TEST123")
    assert result.returncode == 0, result.stderr
    assert runtime_config(target)["googleAnalyticsMeasurementId"] == "G-TEST123"


def test_production_runtime_config_is_not_immutable_and_basic_google_endpoints_are_allowed():
    config = (ROOT / "ui/nginx.prod.conf").read_text()
    runtime = config.split("location = /runtime-config.js {", 1)[1].split("}", 1)[0]
    assert 'Cache-Control "no-store"' in runtime
    csp = config.split('add_header Content-Security-Policy "', 1)[1].split('"', 1)[0]
    directives = {line.split()[0]: set(line.split()[1:]) for line in csp.split(';') if line.strip()}
    assert "https://www.googletagmanager.com" in directives["script-src"]
    assert {"https://www.google-analytics.com", "https://region1.google-analytics.com",
            "https://analytics.google.com", "https://region1.analytics.google.com"} <= directives["connect-src"]
    assert "*" not in csp and "doubleclick" not in csp and "unsafe-eval" not in directives["script-src"]


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
