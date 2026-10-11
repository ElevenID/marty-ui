import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_prepared_selfhost_consumer import check
from record_selfhost_bundle_preparation import record


def test_consumer_preflight_exact_artifact_and_fail_closed_model(tmp_path):
    image = "example.org/app@sha256:" + "a" * 64
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"schema": "marty.selfhost-image-lock/v1",
                                "release": "marty-ui@1.2.3", "services": {"app": image}}))
    transaction = tmp_path / "transaction.json"
    transaction.write_text("{}")
    files = {".marty-selfhost-images.json": lock.read_bytes(),
             "asset.txt": b"downloaded asset",
             "docker-compose.yml": f"services:\n  app:\n    image: {image}\n".encode()}
    inventory = {"schema": "marty.selfhost-bundle-files/v1", "directories": [""],
                 "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bundle/", b"")
        for name, data in files.items():
            bundle.writestr("bundle/" + name, data)
        bundle.writestr("bundle/.marty-selfhost-bundle.json", json.dumps(inventory))
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(record(archive, lock, transaction, "b" * 40, "123")))
    model = tmp_path / "model.json"
    model.write_text(json.dumps({"services": {"app": {"image": image}}}))
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    def run():
        return check(archive, lock, transaction, receipt, model, checkout)

    assert run()["qualification"] == "unqualified"
    installed = tmp_path / "bundle"
    state = tmp_path / "state"
    secrets = tmp_path / "secrets"
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(tmp_path)
    for directory in (state, secrets):
        directory.mkdir()
    asset = installed / "asset.txt"

    def confined(model_value):
        model.write_text(json.dumps(model_value))
        return check(archive, lock, transaction, receipt, model, checkout,
                     install_root=installed, state_root=state, secret_root=secrets)

    service = {"image": image, "volumes": [
        {"type": "bind", "source": str(asset), "read_only": True},
        {"type": "bind", "source": str(state / "postgres")},
    ]}
    assert confined({"services": {"app": service},
                     "secrets": {"operator": {"file": str(secrets / "token")}}})[
                         "qualification"] == "unqualified"
    asset.write_text("altered asset")
    with pytest.raises(ValueError, match="installed ZIP tree differs"):
        confined({"services": {"app": service}})
    asset.write_bytes(files["asset.txt"])
    if os.name != "nt":
        asset.unlink()
        asset.symlink_to(tmp_path / "foreign")
        with pytest.raises(ValueError, match="symlink or special file"):
            confined({"services": {"app": service}})
        asset.unlink()
        asset.write_bytes(files["asset.txt"])
    extra = installed / "extra.txt"
    extra.write_text("not shipped")
    with pytest.raises(ValueError, match="installed ZIP tree differs"):
        confined({"services": {"app": service}})
    extra.unlink()
    asset.unlink()
    with pytest.raises(ValueError, match="installed ZIP tree differs"):
        confined({"services": {"app": service}})
    asset.write_bytes(files["asset.txt"])
    for source in (tmp_path / "foreign", secrets / "token"):
        service["volumes"][0]["source"] = str(source)
        with pytest.raises(ValueError, match="outside the isolated installation"):
            confined({"services": {"app": service}})
    service["volumes"][0]["source"] = str(asset)
    service["volumes"][0]["read_only"] = False
    with pytest.raises(ValueError, match="missing or writable bundle mount"):
        confined({"services": {"app": service}})
    service["volumes"][0]["read_only"] = True
    with pytest.raises(ValueError, match="outside the isolated installation"):
        confined({"services": {"app": service},
                  "secrets": {"operator": {"file": str(tmp_path / "foreign")}}})
    with pytest.raises(ValueError, match="outside the isolated installation"):
        confined({"services": {"app": service},
                  "secrets": {"operator": {"file": str(asset)}}})
    with pytest.raises(ValueError, match="roots overlap"):
        check(archive, lock, transaction, receipt, model, checkout,
              install_root=installed, state_root=installed / "state", secret_root=secrets)
    with pytest.raises(ValueError, match="another source or run"):
        check(archive, lock, transaction, receipt, model, checkout, "c" * 40, "123")
    with pytest.raises(ValueError, match="another source or run"):
        check(archive, lock, transaction, receipt, model, checkout, "b" * 40, "456")
    model.write_text(json.dumps({"services": {"app": {"image": image}},
                                 "secrets": {"operator": {"file": str(tmp_path / "operator-secret")}},
                                 "configs": {"operator": {"file": str(tmp_path / "operator-config")}}}))
    assert run()["qualification"] == "unqualified"
    model.write_text(json.dumps({"services": {"app": {"image": image}}}))
    changed = json.loads(receipt.read_text())
    changed["archive_sha256"] = "0" * 64
    receipt.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="receipt changed"):
        run()
    receipt.write_text(json.dumps(record(archive, lock, transaction, "b" * 40, "123")))

    for invalid in ({"build": "../src"}, {"image": "example.org/app:latest"},
                    {"image": image, "volumes": [{"type": "bind", "source": str(checkout / "src")}]},
                    {"image": image, "volumes": [{"type": "bind", "source": "../src"}]}):
        model.write_text(json.dumps({"services": {"app": invalid}}))
        with pytest.raises(ValueError):
            run()
    for kind in ("secrets", "configs"):
        model.write_text(json.dumps({"services": {"app": {"image": image}},
                                     kind: {"source_file": {"file": str(checkout / "source.txt")}}}))
        with pytest.raises(ValueError, match="mounts the source checkout"):
            run()
        model.write_text(json.dumps({"services": {"app": {"image": image}},
                                     kind: {"source_file": {"file": "../source.txt"}}}))
        with pytest.raises(ValueError, match="unresolved host source"):
            run()


def test_consumer_preflight_rejects_qualified_receipt(tmp_path):
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"schema":"marty.selfhost-bundle-preparation/v1","qualification":"qualified"}')
    with pytest.raises(ValueError, match="unqualified preparation receipt"):
        check(tmp_path / "missing.zip", tmp_path / "missing-lock", tmp_path / "missing-transaction",
              receipt, tmp_path / "missing-model", tmp_path)
