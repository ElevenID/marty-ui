"""Pure receipt contracts; persistence and cryptographic verification are separate."""
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as r

@pytest.fixture
def records():
    f = json.loads((Path(__file__).resolve().parents[1] / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json").read_text())
    a, i = f["authorization"].encode(), f["inventory"].encode()
    context = {k: r.decode(a)[k] for k in r.CONTEXT_FIELDS}
    receipt = r.controller_consumption(a, i, expected=context,
        guest_id="12345678-1234-4234-8234-123456789abc", disk_id="d"*64,
        engine_id="test-engine-12345678", installation_id="22345678-1234-4234-8234-123456789abc",
        consumed_at=100000, now=100000)
    return a, i, context, receipt

def test_exact_receipt_and_canonical_context(records):
    a, i, c, receipt = records
    assert r.bind_controller_consumption(r.encode(receipt), a, i, expected=c, expected_engine=receipt["engine_id"], now=100000) == receipt
    assert r.candidate_context_sha256(c) == "fea75ea294741f68adcde307b631428cc7884016123abd4324462426fabbba6e"
    assert r.candidate_context_sha256(dict(reversed(list(c.items())))) == r.candidate_context_sha256(c)
    for validator in (r.validate_admission, lambda x: r.validate_channel(x, now=100000)):
        with pytest.raises(ValueError): validator(receipt)

@pytest.mark.parametrize("field,value", [
    ("schema", "bad"), ("scope", "acceptance-only"), ("repository", "Other/repo"),
    ("source_ref", "refs/heads/other"), ("workflow", r.PROMOTION_WORKFLOW),
    ("authorization_sha256", "b"*64), ("context_sha256", "b"*64), ("inventory_sha256", "b"*64),
    ("nonce", "b"*64), ("source_sha", "b"*40), ("release_tag", "v1.2.4"),
    ("operator_sha256", "b"*64), ("build_run_id", 43), ("build_run_attempt", 3),
    ("harness_source_sha", "b"*40), ("run_id", 100), ("run_attempt", 4), ("phase", "published"),
    ("engine_id", "different-engine"), ("guest_id", "12345678-1234-1234-8234-123456789abc"),
    ("installation_id", "22345678-1234-4234-0234-123456789abc"), ("disk_id", "bad"),
    ("consumed_at", 99999), ("consumed_at", 100001), ("consumed_at", True),
    ("run_id", 2**53), ("extra", 1),
])
def test_mismatches_fail(records, field, value):
    a, i, c, receipt = records
    receipt[field] = value
    with pytest.raises(ValueError):
        r.bind_controller_consumption(r.encode(receipt), a, i, expected=c, expected_engine="test-engine-12345678", now=100000)

def test_closed_raw_bytes_and_expiration(records):
    a, i, c, receipt = records
    raw = r.encode(receipt)
    for changed in (raw.replace(b'{', b'{"scope":"wrong",', 1), b" "*65537, b"{}"):
        with pytest.raises(ValueError):
            r.bind_controller_consumption(changed, a, i, expected=c, expected_engine=receipt["engine_id"], now=100000)
    for aa, ii, now in ((a+b" ", i, 100000), (a, i+b" ", 100000), (a, i, 103600)):
        with pytest.raises(ValueError):
            r.bind_controller_consumption(raw, aa, ii, expected=c, expected_engine=receipt["engine_id"], now=now)
