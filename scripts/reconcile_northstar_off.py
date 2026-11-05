"""Contained read-only Northstar reconciliation; no create/start/stop or lock changes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def bound(ref):
    file=Path(ref["path"])
    assert file.is_absolute() and file.is_file() and not file.is_symlink()
    assert hashlib.sha256(file.read_bytes()).hexdigest()==ref["sha256"]
    return file


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--input",type=Path,required=True)
    args=parser.parse_args();supplied=json.loads(args.input.read_bytes())
    assert supplied["readOnlyVerificationAuthorized"] is True
    config=json.loads(bound(supplied["operation"]).read_bytes())
    assert supplied["dispatcher"]["sha256"]==config["sourceSha256"]
    dispatcher=bound(supplied["dispatcher"])
    spec=importlib.util.spec_from_file_location("reconciliation_dispatcher",dispatcher)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    output=Path(supplied["outputDir"])
    assert output.is_absolute() and output.is_relative_to(Path.home()/".codex/private") and not output.exists()
    output.mkdir(mode=0o700)
    core,operation=module.prepare(config,output)
    source=core.ref(Path(__file__))
    operation.verify_reconciliation_source(source)
    result=operation.observe_recovered_off(json.loads(bound(supplied["history"]).read_bytes()))
    result.update(producerInput=core.ref(args.input),producerSource=source,
                  operation=supplied["operation"],history=supplied["history"])
    print(json.dumps({"result":operation.save("result.json",result)}))


if __name__=="__main__":main()
