"""Acquire the immutable FreeMarker dependency for real Keycloak theme tests."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

# Same FreeMarker artifact used by Keycloak 26.8.0. Both hosts are official
# Maven Central TLS endpoints; an alternate host does not change the artifact.
JAR_URL = "https://repo.maven.apache.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar"
JAR_FALLBACK_URL = "https://repo1.maven.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar"
JAR_ATTEMPTS = (JAR_URL, JAR_FALLBACK_URL, JAR_URL)
JAR_SHA256 = "0fac87dddd78f1223139e8ef88e819c7f483c0a3835cdf5982ad5e4576d1d896"
MAX_JAR_BYTES = 4 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 30


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("FreeMarker test dependency must not redirect")


def _verify(data: bytes) -> bytes:
    if len(data) > MAX_JAR_BYTES:
        raise ValueError("FreeMarker test dependency exceeds maximum size")
    if hashlib.sha256(data).hexdigest() != JAR_SHA256:
        raise ValueError("FreeMarker test dependency SHA256 mismatch")
    return data


def _retryable(error: urllib.error.URLError | TimeoutError | ConnectionError) -> bool:
    if isinstance(error, urllib.error.HTTPError):
        return error.code in (404, 408, 429) or 500 <= error.code < 600
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    # Certificate failures and unclassified URL errors must remain fatal.
    return isinstance(reason, (TimeoutError, ConnectionError))


def load_freemarker_jar(*override_names: str) -> bytes:
    """Honor the first nonempty local override, otherwise fetch pinned bytes."""
    supplied = next((os.environ[name] for name in override_names if os.environ.get(name)), None)
    if supplied:
        with Path(supplied).open("rb") as source:
            return _verify(source.read(MAX_JAR_BYTES + 1))

    opener = urllib.request.build_opener(NoRedirect())
    for attempt, url in enumerate(JAR_ATTEMPTS):
        try:
            with opener.open(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                if response.status != 200 or response.url != url:
                    raise ValueError("FreeMarker test dependency response URL or status mismatch")
                data = response.read(MAX_JAR_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            if not _retryable(error) or attempt == len(JAR_ATTEMPTS) - 1:
                raise
            time.sleep(attempt + 1)
        else:
            # Integrity failures must not be hidden by another download.
            return _verify(data)
    raise RuntimeError("FreeMarker test dependency acquisition exhausted")
