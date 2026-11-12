"""Real native retained startup checks; fragment agreement is not deployment admission.

Opt-in images and an exact local engine are required. Every database is new
synthetic tmpfs storage on a private internal network, without host ports/binds.
The once-started stock case must fail the membership-only proof because native
legacy normalization also changes formats and display metadata. A previously
reconciled stock case agrees with the limited witnesses, including explicit
system-catalog timestamp cohorts and retained customer-row checks. Neither proves
all retained startup data or authorizes the product transition.
"""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import quote

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import selfhost_windows_product_schema as membership  # noqa: E402
import selfhost_windows_product_ledger as ledger  # noqa: E402
import selfhost_windows_product_catalog as catalog  # noqa: E402
import selfhost_windows_product_startup as startup  # noqa: E402
import selfhost_windows_product as product  # noqa: E402
import selfhost_windows_product_deploy as deploy  # noqa: E402


@pytest.mark.skipif(
    os.environ.get("MARTY_RUN_PRODUCT_NATIVE_STARTUP_TEST") != "1",
    reason="explicit isolated native startup qualification",
)
@pytest.mark.parametrize("old_reconciled", [False, True])
def test_real_native_retained_startup_limits_membership_ledger_catalog_fragments(
    old_reconciled, tmp_path
):
    OLD = os.environ["MARTY_PRODUCT_NATIVE_TEST_OLD_IMAGE"]
    NEW = os.environ["MARTY_PRODUCT_NATIVE_TEST_NEW_IMAGE"]
    OLD_SOURCE = os.environ["MARTY_PRODUCT_NATIVE_TEST_OLD_SOURCE"]
    NEW_SOURCE = os.environ["MARTY_PRODUCT_NATIVE_TEST_NEW_SOURCE"]
    OPS = tmp_path
    OWNER = "native-startup-synthetic-test"
    PROJECT = "marty-selfhost-native-schema-qa-" + uuid.uuid4().hex[:12]
    OPS = OPS / PROJECT
    OPS.mkdir()
    NET = PROJECT + "-network"
    PG = PROJECT + "-postgres"
    REDIS = PROJECT + "-redis"
    ENGINE = os.environ.get("MARTY_PRODUCT_SCHEMA_TEST_ENGINE_ID")
    require_engine = bool(ENGINE) and not os.environ.get("DOCKER_HOST")
    if not require_engine:
        raise RuntimeError("Explicit isolated engine required")
    for image in [OLD, NEW]:
        if (
            re.fullmatch(
                r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}", image
            )
            is None
        ):
            raise RuntimeError("Immutable native test image required")
    for revision in [OLD_SOURCE, NEW_SOURCE]:
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise RuntimeError("Exact native test source required")
    RETAINED_RESTART = old_reconciled
    CONTAINERS = []
    IMAGE_IDS = {}
    EXPECTED_CID_IMAGES = {}
    DOCKER = ["docker"]
    NETWORK_INTENDED = False
    NETWORK_ID = None
    ATTEMPT_ID = uuid.uuid4().hex
    # Synthetic only; reserved URI bytes exercise the image's secret loader.
    DB_PASSWORD = "native-fixture-" + ATTEMPT_ID + "%:/@"
    # Only this fixture writes the synthetic file; a production one-off must
    # inherit the admitted service's existing secrets and override its entrypoint.
    issuance_shell = (
        'set -e; printf %s "$SYNTHETIC_DB_PASSWORD" > /tmp/synthetic-db-password; '
        + deploy.ISSUANCE_MIGRATION_SHELL
    )
    INTENDED_CONTAINERS = {}
    ACK_IDS = {}
    REPORT = {
        "schema": "marty.windows-native-startup-fragment-test/v1",
        "project": PROJECT,
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "production_admission": False,
        "production_data_used": False,
        "old_restart_before_baseline": RETAINED_RESTART,
        "engine_id": ENGINE,
        "native_sources": {"old": OLD_SOURCE, "new": NEW_SOURCE},
        "native_images": {"old": OLD, "new": NEW},
        "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "checks": [],
    }

    def require(ok, message="Isolated native QA refused"):
        if not ok:
            raise RuntimeError(message)

    def cmd(args, input=None, timeout=90):
        return subprocess.check_output(
            [*DOCKER, *args], input=input, stderr=subprocess.STDOUT, timeout=timeout
        )

    def owned(cid):
        x = json.loads(cmd(["inspect", cid]))[0]
        labels = x["Config"]["Labels"]
        require(x["Image"] == EXPECTED_CID_IMAGES[cid])
        names = [name for name, expected in ACK_IDS.items() if expected == cid]
        require(len(names) == 1 and x["Name"] == "/" + names[0])
        require(
            labels.get("com.docker.compose.service")
            == INTENDED_CONTAINERS[names[0]]["role"]
        )
        require(labels.get("elevenid.test.attempt") == ATTEMPT_ID)
        require(
            x["Id"] == cid
            and labels.get("elevenid.owner") == OWNER
            and labels.get("com.docker.compose.project") == PROJECT
        )
        require(
            not x["HostConfig"].get("PortBindings") and not x["HostConfig"].get("Binds")
        )
        require(all(m["Type"] == "tmpfs" for m in x["Mounts"]))
        require(set(x["NetworkSettings"]["Networks"]) == {NET})
        return x

    def remove(cid):
        owned(cid)
        cmd(["stop", "--time", "3", cid], timeout=15)
        owned(cid)
        cmd(["rm", cid])
        CONTAINERS.remove(cid)
        EXPECTED_CID_IMAGES.pop(cid)
        require(not cmd(["ps", "-aq", "--no-trunc", "--filter", "id=" + cid]).strip())

    def run(image, role, entry, args=(), background=True):
        name = PROJECT + "-" + role
        require(not cmd(["ps", "-aq", "--filter", "name=^/" + name + "$"]).strip())
        INTENDED_CONTAINERS[name] = {"image_id": IMAGE_IDS[image], "role": role}
        options = [
            "run",
            "--pull",
            "never",
            "--detach",
            "--name",
            name,
            "--network",
            NET,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=33554432",
            "--label",
            "elevenid.owner=" + OWNER,
            "--label",
            "elevenid.test.attempt=" + ATTEMPT_ID,
            "--label",
            "com.docker.compose.project=" + PROJECT,
            "--label",
            "com.docker.compose.service=" + role,
        ]
        if role == "redis":
            options += ["--tmpfs", "/data:rw,noexec,nosuid,size=16777216"]
        env = {
            "DATABASE_URL": "postgresql://postgres:" + quote(DB_PASSWORD, safe="") + "@" + PG + "/marty_schema_test",
            "ENVIRONMENT": "test",
            "MARTY_MIGRATION_PROFILE": "selfhost-production",
            "PUBLIC_API_URL": "https://startup-qa.invalid",
            "PUBLIC_DOMAIN": "startup-qa.invalid",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
            "MARTY_ISSUER_DID": "did:web:startup-qa.invalid:orgs:marty",
            "MARTY_ISSUER_URL": "https://startup-qa.invalid/orgs/marty",
            "ORG_GRPC_TARGET": "unavailable-organization:9002",
            "RP_GRPC_TARGET": "unavailable-revocation:9013",
            "CREDENTIAL_TEMPLATE_DATABASE_MAX_CONNECTIONS": "2",
            "TRUST_PROFILE_DATABASE_MAX_CONNECTIONS": "2",
            "ORGANIZATION_DATABASE_MAX_CONNECTIONS": "2",
            "REDIS_URL": "redis://" + REDIS + ":6379",
            "ES_GRPC_TARGET": "http://unavailable-events:9010",
            "ES_GRPC_TIMEOUT_SECONDS": "1",
            "MARTY_ORG_ADMIN_EMAIL": "startup-admin@startup-qa.invalid",
            "DEPLOYMENT_PROFILE_DATABASE_MAX_CONNECTIONS": "2",
        }
        if role in {"wrong-tenant-deployment", "wrong-tenant-flow"}:
            env["MARTY_ORG_ID"] = "00000000-0000-0000-0000-000000000002"
        if role == "new-issuance-migrate":
            require(entry == "/bin/sh" and args == ["-c", issuance_shell])
            env.pop("DATABASE_URL")
            env.update({
                "SYNTHETIC_DB_PASSWORD": DB_PASSWORD,
                "MARTY_DB_PASSWORD_FILE": "/tmp/synthetic-db-password",
                "DATABASE_URL_TEMPLATE": "postgresql://postgres:${MARTY_DB_PASSWORD}@" + PG + "/marty_schema_test",
            })
        for k, v in env.items():
            options += ["--env", k + "=" + v]
        cid = cmd([*options, "--entrypoint", entry, image, *args]).decode().strip()
        require(len(cid) == 64)
        ACK_IDS[name] = cid
        EXPECTED_CID_IMAGES[cid] = IMAGE_IDS[image]
        CONTAINERS.append(cid)
        owned(cid)
        if not background:
            code = cmd(["wait", cid], timeout=90).decode().strip()
            logs = cmd(["logs", cid])
            (OPS / (role + ".log")).write_bytes(logs)
            require(code == "0", role + " failed; see owned synthetic log")
        return cid

    def ready(cid, port):
        for _ in range(60):
            row = owned(cid)
            if not row["State"]["Running"]:
                (OPS / "failed-startup.log").write_bytes(cmd(["logs", cid]))
                raise RuntimeError("Native startup exited; see synthetic log")
            r = subprocess.run(
                [
                    *DOCKER,
                    "exec",
                    cid,
                    "curl",
                    "--fail",
                    "--silent",
                    "--max-time",
                    "2",
                    "http://127.0.0.1:" + str(port) + "/health",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if r.returncode == 0:
                return
            time.sleep(0.5)
        (OPS / "failed-startup.log").write_bytes(cmd(["logs", cid]))
        raise RuntimeError("Native health timed out")

    COLUMN_HASHES = "SELECT jsonb_object_agg(e.key,encode(sha256(convert_to(e.value::text,'UTF8')),'hex')) FROM credential_template_service.credential_templates t CROSS JOIN LATERAL jsonb_each(to_jsonb(t)) e WHERE t.id='50000000-0000-0000-0000-000000000040';"

    def sql(s):
        cid = next(
            c
            for c in CONTAINERS
            if owned(c)["Config"]["Labels"].get("com.docker.compose.service")
            == "postgres"
        )
        return cmd(
            [
                "exec",
                "-i",
                cid,
                "psql",
                "-X",
                "-U",
                "postgres",
                "-d",
                "marty_schema_test",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "-",
            ],
            input=s.encode(),
        ).decode()

    def all_table_fingerprints():
        # All native fixture processes are stopped at each observation. Ordinary
        # row values remain inside this synthetic PostgreSQL instance.
        items = [owned(cid) for cid in CONTAINERS]
        return membership.probe.retained_rows_snapshot(
            Docker(), items, PROJECT, profile=profile
        )["tables"]

    class Docker:
        prefix = ["docker"]

    profile = membership.probe.LedgerProfile(application="marty_schema_test")
    try:
        context = cmd(["context", "show"]).decode().strip()
        require(context == os.environ.get("MARTY_PRODUCT_NATIVE_TEST_CONTEXT"))
        DOCKER = ["docker", "--context", context]
        Docker.prefix = DOCKER
        info = json.loads(cmd(["info", "--format", "{{json .}}"]))
        require(info["ID"] == ENGINE and info["OSType"] == "linux")
        for image, revision in [(OLD, OLD_SOURCE), (NEW, NEW_SOURCE)]:
            row = json.loads(cmd(["image", "inspect", image]))[0]
            IMAGE_IDS[image] = row["Id"]
            require(
                row["Config"]["Labels"]["org.opencontainers.image.revision"] == revision
                and image in row["RepoDigests"]
            )
            require(
                row.get("Os") == "linux"
                and row.get("Architecture") == "amd64"
                and not row["Config"].get("Volumes")
            )
        pg_image = json.loads(
            (ROOT / "release/external-images.json").read_text(encoding="utf-8")
        )["postgres"]
        redis_image = json.loads(
            (ROOT / "release/external-images.json").read_text(encoding="utf-8")
        )["redis"]
        require(
            re.fullmatch(r"docker.io/library/redis@sha256:[0-9a-f]{64}", redis_image)
        )
        redis_info = json.loads(cmd(["image", "inspect", redis_image]))[0]
        require(
            any(
                product.image_identity(reference) == product.image_identity(redis_image)
                for reference in redis_info["RepoDigests"]
            )
            and redis_info.get("Os") == "linux"
            and redis_info.get("Architecture") == "amd64"
            and set(redis_info["Config"].get("Volumes") or {}) <= {"/data"}
        )
        IMAGE_IDS[redis_image] = redis_info["Id"]
        require("@sha256:" in pg_image)
        pg_info = json.loads(cmd(["image", "inspect", pg_image]))[0]
        IMAGE_IDS[pg_image] = pg_info["Id"]
        REPORT["image_ids"] = dict(IMAGE_IDS)
        require(
            set(pg_info["Config"].get("Volumes") or {})
            <= {"/var/lib/postgresql/data", "/var/run/postgresql", "/tmp"}
        )
        require(
            not cmd(["network", "ls", "-q", "--filter", "name=^" + NET + "$"]).strip()
        )
        NETWORK_INTENDED = True
        NETWORK_ID = cmd(
            [
                "network",
                "create",
                "--internal",
                "--label",
                "elevenid.owner=" + OWNER,
                "--label",
                "elevenid.test.attempt=" + ATTEMPT_ID,
                "--label",
                "com.docker.compose.project=" + PROJECT,
                NET,
            ]
        )
        NETWORK_ID = NETWORK_ID.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", NETWORK_ID))
        network = json.loads(cmd(["network", "inspect", NETWORK_ID]))[0]
        require(
            network["Id"] == NETWORK_ID
            and network["Name"] == NET
            and network["Internal"] is True
            and network["Labels"].get("elevenid.owner") == OWNER
            and network["Labels"].get("com.docker.compose.project") == PROJECT
            and network["Labels"].get("elevenid.test.attempt") == ATTEMPT_ID
        )
        INTENDED_CONTAINERS[PG] = {"image_id": IMAGE_IDS[pg_image], "role": "postgres"}
        cid = (
            cmd(
                [
                    "run",
                    "--pull",
                    "never",
                    "--detach",
                    "--name",
                    PG,
                    "--network",
                    NET,
                    "--read-only",
                    "--user",
                    "postgres",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "128",
                    "--memory",
                    "384m",
                    "--cpus",
                    "1",
                    "--label",
                    "elevenid.owner=" + OWNER,
                    "--label",
                    "elevenid.test.attempt=" + ATTEMPT_ID,
                    "--label",
                    "com.docker.compose.project=" + PROJECT,
                    "--label",
                    "com.docker.compose.service=postgres",
                    "--env",
                    "POSTGRES_DB=marty_schema_test",
                    "--env",
                    "POSTGRES_USER=postgres",
                    "--env",
                    "POSTGRES_PASSWORD=" + DB_PASSWORD,
                    "--env",
                    "PGDATA=/var/lib/postgresql/data/owned",
                    "--tmpfs",
                    "/var/lib/postgresql/data:rw,noexec,nosuid,size=268435456,mode=1777",
                    "--tmpfs",
                    "/var/run/postgresql:rw,noexec,nosuid,size=16777216,mode=1777",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=16777216,mode=1777",
                    pg_image,
                ]
            )
            .decode()
            .strip()
        )
        require(len(cid) == 64)
        ACK_IDS[PG] = cid
        EXPECTED_CID_IMAGES[cid] = IMAGE_IDS[pg_image]
        CONTAINERS.append(cid)
        owned(cid)
        for _ in range(60):
            if (
                subprocess.run(
                    [
                        *DOCKER,
                        "exec",
                        cid,
                        "pg_isready",
                        "-U",
                        "postgres",
                        "-d",
                        "marty_schema_test",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).returncode
                == 0
            ):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Owned PostgreSQL did not become ready")
        redis = run(
            redis_image,
            "redis",
            "redis-server",
            ["--save", "", "--appendonly", "no", "--dir", "/tmp"],
        )
        for _ in range(30):
            ping = subprocess.run(
                [*DOCKER, "exec", redis, "redis-cli", "ping"],
                capture_output=True,
                timeout=5,
            )
            if ping.returncode == 0 and ping.stdout.strip() == b"PONG":
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Owned Redis did not become ready")
        migration = run(
            OLD,
            "old-organization-migrate",
            "/usr/local/bin/marty-organization",
            ["migrate"],
            False,
        )
        remove(migration)
        REPORT["checks"].append("old organization native schema prerequisite")
        organization = run(OLD, "old-organization", "/usr/local/bin/marty-organization")
        ready(organization, 8002)
        remove(organization)
        REPORT["checks"].append(
            "old organization full startup with reserved administrator"
        )
        assert (
            sql(
                "SELECT count(*) FROM organization_service.members WHERE "
                "email='startup-admin@startup-qa.invalid' AND user_id='' AND status='active';"
            ).strip()
            == "1"
        )
        inserted_member = sql(
            "WITH inserted AS (INSERT INTO organization_service.members SELECT (jsonb_populate_record("
            "NULL::organization_service.members,to_jsonb(candidate)||"
            '\'{"id":"81000000-0000-0000-0000-000000000001",'
            '"user_id":"synthetic-retained-user",'
            '"email":"retained-member@startup-qa.invalid"}\'::jsonb)).* '
            "FROM organization_service.members candidate "
            "WHERE email='startup-admin@startup-qa.invalid' RETURNING id) "
            "SELECT count(*) FROM inserted;"
        )
        assert inserted_member.strip() == "1"
        retained_member_sql = (
            "SELECT count(*) FROM organization_service.members WHERE "
            "id='81000000-0000-0000-0000-000000000001' "
            "AND organization_id='00000000-0000-0000-0000-000000000001' "
            "AND user_id='synthetic-retained-user' "
            "AND email='retained-member@startup-qa.invalid' AND status='active';"
        )
        assert sql(retained_member_sql).strip() == "1"
        for role, entry, port in [
            ("old-credential-template", "marty-credential-template", 8003),
            ("old-trust-profile", "marty-trust-profile", 8004),
        ]:
            service = run(OLD, role, "/usr/local/bin/" + entry)
            ready(service, port)
            REPORT["checks"].append(role + " full startup")
            remove(service)
        if RETAINED_RESTART:
            for role, entry, port in [
                ("retained-old-credential-template", "marty-credential-template", 8003),
                ("retained-old-trust-profile", "marty-trust-profile", 8004),
            ]:
                service = run(OLD, role, "/usr/local/bin/" + entry)
                ready(service, port)
                REPORT["checks"].append(role + " full startup")
                remove(service)
        migration = run(
            OLD,
            "old-issuance-migrate",
            "/usr/local/bin/marty-issuance-service",
            ["migrate"],
            False,
        )
        remove(migration)
        REPORT["checks"].append("old issuance native migrate with seed and password authentication")
        deployment = run(
            OLD, "old-deployment", "/usr/local/bin/marty-deployment-profile"
        )
        ready(deployment, 8010)
        remove(deployment)
        REPORT["checks"].append("old deployment full startup")
        flow = run(
            OLD, "old-flow-migrate", "/usr/local/bin/marty-flow", ["migrate"], False
        )
        remove(flow)
        REPORT["checks"].append("old Flow native migrate with retained bootstrap state")
        # Customer rows must not inherit a built-in row's timestamp allowance.
        for table, patch in [
            (
                "credential_template_service.wallet_registry",
                {
                    "id": "wr-fixture-customer",
                    "name": "Customer fixture wallet",
                    "organization_id": "00000000-0000-0000-0000-000000000002",
                },
            ),
            (
                "credential_template_service.delivery_destinations",
                {
                    "id": "dd-fixture-customer",
                    "name": "Customer fixture destination",
                    "organization_id": "00000000-0000-0000-0000-000000000002",
                    "is_system": False,
                },
            ),
            (
                "trust_profile_service.issuer_entities",
                {
                    "id": "80000000-0000-0000-0000-000000000001",
                    "issuer_id": "did:web:customer.startup-qa.invalid",
                    "display_name": "Customer fixture issuer",
                    "organization_id": "00000000-0000-0000-0000-000000000002",
                    "metadata": {},
                },
            ),
        ]:
            literal = json.dumps(patch).replace("'", "''")
            sql(
                "INSERT INTO "
                + table
                + " SELECT (jsonb_populate_record(NULL::"
                + table
                + ",to_jsonb(candidate)||'"
                + literal
                + "'::jsonb)).* FROM "
                + table
                + " candidate ORDER BY id LIMIT 1;"
            )
        sql(
            "CREATE SCHEMA synthetic_retained; CREATE TABLE synthetic_retained.accounts(id text PRIMARY KEY,email text NOT NULL,payload jsonb NOT NULL); INSERT INTO synthetic_retained.accounts VALUES('synthetic-account','qa-account@startup-qa.invalid','{\"keep\":true}');"
        )
        sql("""CREATE TABLE synthetic_retained.value_shapes(id text PRIMARY KEY,bounded int[] NOT NULL,raw json NOT NULL);
INSERT INTO synthetic_retained.value_shapes VALUES('shape','[0:1]={1,2}'::int[],'{"key":1,"key":2}'::json);
CREATE SEQUENCE synthetic_retained.positions;
CREATE MATERIALIZED VIEW synthetic_retained.account_summary AS SELECT count(*) AS total FROM synthetic_retained.accounts;""")
        before_all = all_table_fingerprints()
        json_shape = sql("SELECT to_jsonb(t)::text FROM synthetic_retained.value_shapes t;")
        for mutation, restore in [
            ("bounded=ARRAY[1,2]", "bounded='[0:1]={1,2}'::int[]"),
            ("raw='{\"key\":2}'::json", "raw='{\"key\":1,\"key\":2}'::json"),
        ]:
            sql("UPDATE synthetic_retained.value_shapes SET " + mutation + ";")
            assert sql("SELECT to_jsonb(t)::text FROM synthetic_retained.value_shapes t;") == json_shape
            assert all_table_fingerprints()["synthetic_retained.value_shapes"] != before_all["synthetic_retained.value_shapes"]
            sql("UPDATE synthetic_retained.value_shapes SET " + restore + ";")
        sql("SELECT nextval('synthetic_retained.positions');")
        assert all_table_fingerprints()["synthetic_retained.positions"] != before_all["synthetic_retained.positions"]
        sql("SELECT setval('synthetic_retained.positions',1,false);")
        lo = int(sql("SELECT lo_create(0);").strip())
        with pytest.raises(ValueError):
            all_table_fingerprints()
        sql("SELECT lo_unlink(" + str(lo) + ");")
        sql("CREATE TYPE synthetic_retained.custom_value AS ENUM('one'); CREATE TABLE synthetic_retained.custom_values(value synthetic_retained.custom_value);")
        with pytest.raises(ValueError):
            all_table_fingerprints()
        sql("DROP TABLE synthetic_retained.custom_values; DROP TYPE synthetic_retained.custom_value;")
        assert all_table_fingerprints() == before_all
        REPORT["checks"].append("array bounds, raw JSON and sequence changes detected; large objects and custom output types refused")
        role_ids = [
            str(uuid.uuid5(uuid.UUID("00000000-0000-0000-0000-000000000001"), name))
            for name in (
                "owner",
                "admin",
                "access_admin",
                "catalog_admin",
                "reviewer",
                "operator",
                "viewer",
                "applicant",
            )
        ]
        role_cohort = (
            "id IN (" + ",".join("'" + key + "'" for key in role_ids) + ") "
            "AND organization_id='00000000-0000-0000-0000-000000000001' AND is_system"
        )
        role_payload_sql = (
            "SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(convert_to("
            "coalesce(jsonb_agg(CASE WHEN "
            + role_cohort
            + " THEN to_jsonb(t)-'updated_at' "
            "ELSE to_jsonb(t) END ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex')) "
            "FROM organization_service.roles t;"
        )
        roles_before = json.loads(sql(role_payload_sql))
        deployment_cohort = (
            "id='70000000-0000-0000-0000-000000000001' "
            "AND organization_id='00000000-0000-0000-0000-000000000001'"
        )
        deployment_payload_sql = (
            "SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(convert_to("
            "coalesce(jsonb_agg(CASE WHEN "
            + deployment_cohort
            + " THEN to_jsonb(t)-'updated_at' ELSE to_jsonb(t) END ORDER BY id),"
            "'[]'::jsonb)::text,'UTF8')),'hex')) FROM deployment_profile_service.deployment_profiles t;"
        )
        deployment_before = json.loads(sql(deployment_payload_sql))
        assert deployment_before["rows"] == 1
        assert roles_before["rows"] == len(role_ids)
        assert sql(
            "SELECT count(*) FROM organization_service.roles WHERE " + role_cohort
        ).strip() == str(len(role_ids))
        before_columns = json.loads(sql(COLUMN_HASHES))
        items = [owned(cid)]
        prior = {
            "membership": membership.capture(Docker(), items, PROJECT, profile=profile),
            "startup": startup.capture(
                Docker(),
                items,
                PROJECT,
                organization_id="00000000-0000-0000-0000-000000000001",
                issuer_did="did:web:startup-qa.invalid:orgs:marty",
                profile=profile,
            ),
            "ledger": ledger.capture(Docker(), items, PROJECT, profile=profile),
            "catalog": catalog.capture(Docker(), items, PROJECT, profile=profile),
        }
        # This fixture deliberately starts only a subset of application roles.
        # Bind its real ledger inventory, without claiming the full production
        # profile or inventing absent service ledgers.
        fixture_ledgers = frozenset((row['schema'], row['name']) for row in
                                   json.loads(sql(membership.probe.LEDGERS_SQL)))
        def detailed_fixture_ledgers():
            return membership.probe._database_snapshot(Docker(),
                membership.probe._postgres_base(items, PROJECT), profile.application,
                fixture_ledgers, detailed=True)
        profile_before = detailed_fixture_ledgers()
        for name, witness in prior['ledger']['ledgers'].items():
            assert profile_before['migration_ledgers'][name] == witness['rows_sha256']
        (OPS / "synthetic-before-witnesses.json").write_text(
            json.dumps(prior, indent=2), encoding="utf-8"
        )
        role_clock = json.loads(sql("SELECT to_json(clock_timestamp());"))
        organization = run(NEW, "new-organization", "/usr/local/bin/marty-organization")
        ready(organization, 8002)
        remove(organization)
        REPORT["checks"].append("new organization full startup with retained members")
        assert sql(retained_member_sql).strip() == "1"
        assert (
            json.loads(
                sql(
                    "SELECT to_json(count(*)=8 AND bool_and(updated_at >= '"
                    + role_clock.replace("'", "''")
                    + "'::timestamptz AND updated_at <= clock_timestamp())) FROM "
                    "organization_service.roles WHERE " + role_cohort
                )
            )
            is True
        )
        for role, entry, port in [
            ("new-credential-template", "marty-credential-template", 8003),
            ("new-trust-profile", "marty-trust-profile", 8004),
        ]:
            service = run(NEW, role, "/usr/local/bin/" + entry)
            ready(service, port)
            REPORT["checks"].append(role + " full startup")
            remove(service)
        migration = run(
            NEW,
            "new-issuance-migrate",
            "/bin/sh",
            ["-c", issuance_shell],
            False,
        )
        remove(migration)
        REPORT["checks"].append("new issuance native migrate with file-secret authentication")
        deployment_clock = json.loads(sql("SELECT to_json(clock_timestamp());"))
        deployment = run(
            NEW, "new-deployment", "/usr/local/bin/marty-deployment-profile"
        )
        ready(deployment, 8010)
        remove(deployment)
        assert json.loads(sql(deployment_payload_sql)) == deployment_before
        assert (
            json.loads(
                sql(
                    "SELECT to_json(count(*)=1 AND bool_and(updated_at >= '"
                    + deployment_clock.replace("'", "''")
                    + "'::timestamptz AND updated_at <= clock_timestamp())) FROM "
                    "deployment_profile_service.deployment_profiles WHERE "
                    + deployment_cohort
                )
            )
            is True
        )
        REPORT["checks"].append(
            "new deployment full startup retains payload with scoped timestamp"
        )
        flow = run(
            NEW,
            "new-flow-verify",
            "/usr/local/bin/marty-flow",
            ["verify-owned-schema"],
            False,
        )
        remove(flow)
        REPORT["checks"].append(
            "new Flow verifies retained schema and tenant without provider startup"
        )
        retained_before_rejections = all_table_fingerprints()
        for role, entry, arguments in [
            ("wrong-tenant-deployment", "marty-deployment-profile", []),
            ("wrong-tenant-flow", "marty-flow", ["verify-owned-schema"]),
        ]:
            rejected = run(NEW, role, "/usr/local/bin/" + entry, arguments)
            assert cmd(["wait", rejected], timeout=90).decode().strip() == "1"
            rejection_log = cmd(["logs", rejected])
            (OPS / (role + ".log")).write_bytes(rejection_log)
            assert b"belongs to a different organization" in rejection_log
            assert owned(rejected)["State"]["OOMKilled"] is False
            remove(rejected)
            assert all_table_fingerprints() == retained_before_rejections
            REPORT["checks"].append(role + " rejected without retained row changes")
        after = {
            name: json.loads(
                sql(
                    module.after_sql(prior[name])
                    if name in {"membership", "startup"}
                    else module.statement(prior[name])
                )
            )
            for name, module in [
                ("membership", membership),
                ("startup", startup),
                ("ledger", ledger),
                ("catalog", catalog),
            ]
        }
        profile_after = detailed_fixture_ledgers()
        for name, witness in after['ledger']['ledgers'].items():
            assert profile_after['migration_ledgers'][name] == witness['rows_sha256']
        for name in fixture_ledgers:
            key = '.'.join(name)
            if key not in ledger.BASELINES:
                assert profile_before['migration_ledgers'][key] == profile_after['migration_ledgers'][key]
        REPORT['checks'].append('complete fixture ledger map binds native narrow additions; other ledgers retained')
        (OPS / "synthetic-after-witnesses.json").write_text(
            json.dumps(after, indent=2), encoding="utf-8"
        )
        after_all = all_table_fingerprints()
        assert set(after_all) == set(before_all) | {
            "trust_profile_service.credential_authority_revisions"
        }
        mutable = {
            "deployment_profile_service.deployment_profiles",
            "organization_service.roles",
            "credential_template_service.credential_templates",
            "credential_template_service.wallet_registry",
            "credential_template_service.delivery_destinations",
            "credential_template_service.rust_schema_versions",
            "issuance_service.application_templates",
            "issuance_service.rust_schema_migrations",
            "trust_profile_service.issuer_entities",
            "trust_profile_service.native_migrations",
            "trust_profile_service.credential_authority_revisions",
        }
        changed = {
            table for table in after_all if before_all.get(table) != after_all[table]
        }
        assert changed == mutable
        assert json.loads(sql(role_payload_sql)) == roles_before
        REPORT["checks"].append(
            "organization role payloads retained except system-role updated_at"
        )
        assert (
            after_all["trust_profile_service.credential_authority_revisions"]["rows"]
            == 0
        )
        for table in set(before_all) - mutable:
            assert before_all[table] == after_all[table], table
        REPORT["observed_tables"] = len(after_all)
        REPORT["changed_tables"] = sorted(changed)
        # The new witness must still refuse any non-timestamp/customer change.
        for table, column, key in [
            (
                "credential_template_service.wallet_registry",
                "name",
                "wr-fixture-customer",
            ),
            (
                "credential_template_service.delivery_destinations",
                "name",
                "dd-fixture-customer",
            ),
            (
                "trust_profile_service.issuer_entities",
                "display_name",
                "80000000-0000-0000-0000-000000000001",
            ),
            ("organization_service.roles", "name", role_ids[0]),
            ("deployment_profile_service.deployment_profiles", "name", startup.DEPLOYMENT_ID),
        ]:
            sql(
                "UPDATE "
                + table
                + " SET "
                + column
                + "="
                + column
                + "||' unexpected' WHERE id::text='"
                + key
                + "';"
            )
            with pytest.raises(ValueError):
                startup.capture(
                    Docker(),
                    items,
                    PROJECT,
                    organization_id="00000000-0000-0000-0000-000000000001",
                    issuer_did="did:web:startup-qa.invalid:orgs:marty",
                    before=prior["startup"],
                    profile=profile,
                )
            sql(
                "UPDATE "
                + table
                + " SET "
                + column
                + "=left("
                + column
                + ",length("
                + column
                + ")-length(' unexpected')) WHERE id::text='"
                + key
                + "';"
            )
        startup.capture(
            Docker(),
            items,
            PROJECT,
            organization_id="00000000-0000-0000-0000-000000000001",
            issuer_did="did:web:startup-qa.invalid:orgs:marty",
            before=prior["startup"],
            profile=profile,
        )
        REPORT["checks"].append("five customer and system payload mutations refused and restored")
        after_columns = json.loads(sql(COLUMN_HASHES))
        REPORT["membership_changed_columns"] = sorted(
            k for k in before_columns if before_columns[k] != after_columns.get(k)
        )
        REPORT["witness_failures"] = []
        for name, module in [
            ("membership", membership),
            ("startup", startup),
            ("ledger", ledger),
            ("catalog", catalog),
        ]:
            try:
                delta = module.validate_delta(prior[name], after[name])
                assert (
                    delta["native_admission"] is False
                    and delta["product_transition_admission"] is False
                )
                REPORT["checks"].append(name + " retained-state witness agrees")
            except ValueError as error:
                REPORT["witness_failures"].append(
                    {"witness": name, "error": str(error)}
                )
        expected = [] if old_reconciled else ["membership"]
        assert [row["witness"] for row in REPORT["witness_failures"]] == expected
        expected_columns = (
            ["claims", "updated_at", "version"]
            if old_reconciled
            else [
                "claims",
                "display_style",
                "supported_formats",
                "updated_at",
                "version",
            ]
        )
        assert REPORT["membership_changed_columns"] == expected_columns
        REPORT["fragment_validation_passed"] = not REPORT["witness_failures"]
        assert REPORT["production_admission"] is False
        REPORT["passed"] = True
    except Exception as error:
        REPORT.update(
            passed=False, error_type=type(error).__name__, error=str(error)[:300]
        )
        raise
    finally:
        REPORT["cleanup_errors"] = []
        REPORT["reconciled_unacknowledged_resources"] = []
        if NETWORK_INTENDED:
            try:
                ids = (
                    cmd(
                        [
                            "network",
                            "ls",
                            "-q",
                            "--no-trunc",
                            "--filter",
                            "name=^" + NET + "$",
                        ]
                    )
                    .decode()
                    .split()
                )
                require(len(ids) == 1, "Uncertain or missing intended network: " + NET)
                require(
                    NETWORK_ID is None or ids[0] == NETWORK_ID,
                    "Network name was replaced",
                )
                row = json.loads(cmd(["network", "inspect", ids[0]]))[0]
                require(
                    row["Id"] == ids[0]
                    and row["Name"] == NET
                    and row["Internal"] is True
                    and row["Labels"].get("elevenid.owner") == OWNER
                    and row["Labels"].get("com.docker.compose.project") == PROJECT
                    and row["Labels"].get("elevenid.test.attempt") == ATTEMPT_ID
                )
                if NETWORK_ID is None:
                    REPORT["reconciled_unacknowledged_resources"].append(
                        {"kind": "network", "id": ids[0]}
                    )
                NETWORK_ID = ids[0]
            except Exception as error:
                REPORT["cleanup_errors"].append(
                    type(error).__name__ + ":" + str(error)[:180]
                )
        # Intent is retained before each create. Lost stdout/timeout is not
        # permission to replay creation or to claim that cleanup succeeded.
        for name, intent in INTENDED_CONTAINERS.items():
            try:
                ids = (
                    cmd(["ps", "-aq", "--no-trunc", "--filter", "name=^/" + name + "$"])
                    .decode()
                    .split()
                )
                require(len(ids) <= 1)
                if not ids:
                    require(
                        name in ACK_IDS, "Uncertain intended container outcome: " + name
                    )
                    continue
                cid = ids[0]
                require(re.fullmatch(r"[0-9a-f]{64}", cid))
                require(
                    name not in ACK_IDS or ACK_IDS[name] == cid,
                    "Container name was replaced",
                )
                unacknowledged = name not in ACK_IDS
                ACK_IDS[name] = cid
                EXPECTED_CID_IMAGES[cid] = intent["image_id"]
                owned(cid)
                if unacknowledged:
                    REPORT["reconciled_unacknowledged_resources"].append(
                        {"kind": "container", "id": cid}
                    )
                if cid not in CONTAINERS:
                    CONTAINERS.append(cid)
            except Exception as error:
                REPORT["cleanup_errors"].append(
                    type(error).__name__ + ":" + str(error)[:180]
                )
        for cid in list(reversed(CONTAINERS)):
            try:
                remove(cid)
            except Exception as error:
                REPORT["cleanup_errors"].append(
                    type(error).__name__ + ":" + str(error)[:180]
                )
        if NETWORK_ID:
            try:
                row = json.loads(cmd(["network", "inspect", NETWORK_ID]))[0]
                require(
                    row["Id"] == NETWORK_ID
                    and row["Name"] == NET
                    and row["Internal"] is True
                    and row["Labels"].get("elevenid.owner") == OWNER
                    and row["Labels"].get("com.docker.compose.project") == PROJECT
                    and row["Labels"].get("elevenid.test.attempt") == ATTEMPT_ID
                    and not row.get("Containers")
                )
                cmd(["network", "rm", NETWORK_ID])
                require(
                    not cmd(
                        [
                            "network",
                            "ls",
                            "-q",
                            "--no-trunc",
                            "--filter",
                            "id=" + NETWORK_ID,
                        ]
                    ).strip()
                )
            except Exception as error:
                REPORT["cleanup_errors"].append(
                    type(error).__name__ + ":" + str(error)[:180]
                )
        REPORT["finished_utc"] = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        (OPS / "exploration-result.json").write_text(
            json.dumps(REPORT, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(REPORT))
        require(
            not REPORT["cleanup_errors"],
            "Owned synthetic cleanup incomplete; inspect startup test receipt",
        )
