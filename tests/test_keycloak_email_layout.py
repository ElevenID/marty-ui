"""Render the shipped wrapper through Keycloak's actual FreeMarker contract."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.keycloak_freemarker import NoRedirect, load_freemarker_jar

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def renderer(tmp_path_factory):
    java, javac = shutil.which("java"), shutil.which("javac")
    assert java and javac, "A JDK is required for the real Keycloak email rendering contract"
    working = tmp_path_factory.mktemp("keycloak-email-layout")
    data = load_freemarker_jar("KEYCLOAK_EMAIL_FREEMARKER_JAR")
    jar = working / "freemarker-2.3.35.jar"
    jar.write_bytes(data)
    source = ROOT / "tests/java/KeycloakEmailLayoutContract.java"
    subprocess.run([javac, "-J-Xmx128m", "-cp", str(jar), "-d", str(working), str(source)],
                   check=True, capture_output=True, text=True, timeout=30)
    return [java, "-Xmx96m", "-cp", str(working) + os.pathsep + str(jar),
            "KeycloakEmailLayoutContract",
            str(ROOT / "config/keycloak/themes/11id/email/html/template.ftl")]


@pytest.mark.parametrize("action", ["VERIFY", "RESET"])
def test_inherited_action_email_uses_nested_body_without_realm_url(renderer, action):
    result = subprocess.run([*renderer, action], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    html = result.stdout
    assert html.count(action + "_BODY_SENTINEL") == 1
    assert html.count("https://example.invalid/" + action.lower()) == 1
    assert html.count("<!DOCTYPE html>") == 1
    assert "Synthetic &lt;Realm&gt;" in html
    assert "UNEXPECTED_FALLBACK" not in html
