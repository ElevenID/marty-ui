"""Source-only current-ten migration controls; no database or daemon calls."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scoped_native_runtime import MIGRATIONS, migration_names, ref
from scoped_d12_native_execution import exact_exported_sql, D05_MIGRATION_SHA256
from scoped_native_maintenance import operational_sql_sources
import scoped_native_profiles

PROFILE = "d05-membership-current-functional"
CT = "rust/services/credential-template/migrations/0003_membership_achievement_criteria.sql"
ISSUER = "rust/services/issuance/migrations/0012_membership_achievement_criteria.sql"


@pytest.mark.parametrize("drift", [None, "missing-ct", "missing-issuer", "extra", "changed"])
def test_current_ten_exact_sql_and_shared_digest_refuse_drift(tmp_path, monkeypatch, drift):
    revision = "47e42c7f61e150e1ece953e02b4041324b6bdea4"
    monkeypatch.setattr(scoped_native_profiles, "current_rollout_build", lambda profile: SimpleNamespace(ui_revision=revision))
    names = set(D05_MIGRATION_SHA256) | {"scripts/sql/" + name for name in operational_sql_sources()} | {"scripts/sql/passport-beta-maintenance-catalog.sql"}
    refs = {}
    for name in names:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        refs[name] = ref(target)
    migrations = {name: refs[name] for name in D05_MIGRATION_SHA256}
    if drift == "missing-ct":
        del migrations[CT]
    elif drift == "missing-issuer":
        del migrations[ISSUER]
    elif drift == "extra":
        migrations["foreign.sql"] = refs[CT]
    elif drift == "changed":
        target = tmp_path / CT
        target.write_bytes(target.read_bytes() + b"\n-- changed\n")
        migrations[CT] = ref(target)
    inputs = {"sqlSources": {name: refs["scripts/sql/" + name] for name in operational_sql_sources()},
              "catalogSql": refs["scripts/sql/passport-beta-maintenance-catalog.sql"], "migrationSources": migrations}
    prepared = {"sources": {"ui": {"revision": revision, "directory": str(tmp_path)}}}
    program = "const fs=require('node:fs'),m=require(process.argv[1]);process.stdout.write(m.migrationDigest(JSON.parse(fs.readFileSync(0)),process.argv[2]))"
    result = subprocess.run(["node", "-e", program, str(ROOT / "tests/scripts/native-maintenance-metadata.js"), PROFILE], input=json.dumps(migrations), text=True, capture_output=True)
    if drift is None:
        exact_exported_sql(prepared, inputs, PROFILE)
        assert result.returncode == 0 and len(result.stdout) == 64
        assert migration_names(None) == MIGRATIONS
        assert {"rust/services/" + item.replace("/", "/migrations/", 1) + ".sql" for item in migration_names(PROFILE)} == set(migrations)
    else:
        with pytest.raises(ValueError, match="D12_EXACT_(RUST_MIGRATION_SET|GIT_EXPORTED_MIGRATION)_REQUIRED"):
            exact_exported_sql(prepared, inputs, PROFILE)
        assert result.returncode != 0
