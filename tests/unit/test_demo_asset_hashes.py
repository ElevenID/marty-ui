from __future__ import annotations

import hashlib

from scripts.demo_asset_hashes import public_asset_sha256


def test_text_demo_asset_hash_is_independent_of_checkout_line_endings(tmp_path) -> None:
    lf = tmp_path / "poster.svg"
    crlf = tmp_path / "poster-crlf.svg"
    lf.write_bytes(b"<svg>\n<title>Demo</title>\n</svg>\n")
    crlf.write_bytes(b"<svg>\r\n<title>Demo</title>\r\n</svg>\r\n")

    expected = hashlib.sha256(lf.read_bytes()).hexdigest()
    assert public_asset_sha256(lf) == expected
    assert public_asset_sha256(crlf) == expected
