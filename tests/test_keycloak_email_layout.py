"""Render the shipped wrapper through Keycloak's actual FreeMarker contract."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Same FreeMarker artifact used by Keycloak 26.8.0; no production data involved.
JAR_URL = "https://repo.maven.apache.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar"
JAR_SHA256 = "0fac87dddd78f1223139e8ef88e819c7f483c0a3835cdf5982ad5e4576d1d896"
MAX_JAR_BYTES = 4 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("FreeMarker test dependency must not redirect")


@pytest.fixture(scope="module")
def renderer(tmp_path_factory):
    java, javac = shutil.which("java"), shutil.which("javac")
    assert java and javac, "A JDK is required for the real Keycloak email rendering contract"
    working = tmp_path_factory.mktemp("keycloak-email-layout")
    supplied = os.environ.get("KEYCLOAK_EMAIL_FREEMARKER_JAR")
    if supplied:
        with Path(supplied).open("rb") as source:
            data = source.read(MAX_JAR_BYTES + 1)
    else:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(JAR_URL, timeout=30) as response:
            assert response.status == 200 and response.url == JAR_URL
            data = response.read(MAX_JAR_BYTES + 1)
    assert len(data) <= MAX_JAR_BYTES and hashlib.sha256(data).hexdigest() == JAR_SHA256
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
