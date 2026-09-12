"""Test-child-only public CA locator; never mounted in a deployment image.

HTTPX deliberately ignores environment proxies and CA overrides when trust_env
is false. Keep that transport policy and certificate verification unchanged; only
select the exact synthetic public CA file for this isolated worker process.
"""

import os
from pathlib import Path

import certifi

certificate = Path(os.environ["MARTY_CANVAS_TEST_CA_FILE"])
assert certificate.name == "ca.pem"
assert certificate.parent.parent == Path("/tmp")
assert certificate.parent.name.startswith("canvas-worker-rest-")
assert certificate.is_file()
certifi.where = lambda: str(certificate)
