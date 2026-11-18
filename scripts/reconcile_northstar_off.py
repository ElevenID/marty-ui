"""Contained read-only Northstar reconciliation; no create/start/stop or lock changes."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path


def bound(ref):
    file=Path(ref["path"])
    assert file.is_absolute() and file.is_file() and not file.is_symlink()
    assert hashlib.sha256(file.read_bytes()).hexdigest()==ref["sha256"]
    return file


def failure_record(error, stage):
    """Fixed metadata only: never provider text, process output, cookies or paths."""
    message=str(error)
    code=message if re.fullmatch(r'[A-Z][A-Z0-9_]{1,79}',message) else 'READONLY_RECONCILIATION_FAILED'
    name=type(error).__name__
    result={'state':'FAILED','stage':stage if stage in ('prepare','verify-source','observe-recovered-off') else 'unknown',
            'errorClass':name if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}',name) else 'Error','code':code,
            'runtimeWrites':False,'releaseQualified':False,'recordingQualified':False}
    bridge=getattr(error,'scopeFailure',None)
    if type(bridge) is dict and set(bridge)=={'errorClass','code','exitCode','stdoutBytes'}:
        if (bridge['errorClass'] in ('Error','AssertionError','TypeError','RangeError','SyntaxError')
                and type(bridge['code']) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{1,79}',bridge['code'])
                and type(bridge['exitCode']) is int and type(bridge['stdoutBytes']) is int
                and -2147483648<=bridge['exitCode']<=4294967295
                and 0<=bridge['stdoutBytes']<=32768):
            result['scopeFailure']=bridge
    return result


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
    stage='prepare'
    try:
        core,operation=module.prepare(config,output)
        source=core.ref(Path(__file__))
        stage='verify-source'
        operation.verify_reconciliation_source(source)
        stage='observe-recovered-off'
        result=operation.observe_recovered_off(json.loads(bound(supplied["history"]).read_bytes()))
        result.update(producerInput=core.ref(args.input),producerSource=source,
                      operation=supplied["operation"],history=supplied["history"])
        print(json.dumps({"result":operation.save("result.json",result)}))
    except BaseException as error:
        record=failure_record(error,stage)
        file=output/'failure.json'
        with file.open('x',encoding='utf-8') as stream:
            json.dump(record,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        print(json.dumps({'state':'FAILED','failure':{'path':str(file),
            'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}}))
        return 1
    return 0


if __name__=="__main__":sys.exit(main())
