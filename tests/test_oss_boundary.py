from pathlib import Path

import pytest

from scripts.check_oss_boundary import scan_repository


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_current_repository_has_no_private_commerce_implementation() -> None:
    assert scan_repository(REPO_ROOT) == []


def test_boundary_scan_reports_private_package_reference(tmp_path: Path) -> None:
    package = tmp_path / "ui" / "package.json"
    package.parent.mkdir(parents=True)
    package.write_text('{"dependencies":{"@marty/subscriptions":"0.1.0"}}', encoding="utf-8")

    findings = scan_repository(tmp_path)

    assert findings == ["forbidden marker '@marty/subscriptions': ui/package.json"]


def test_boundary_scan_reports_commercial_price_catalog(tmp_path: Path) -> None:
    catalog = tmp_path / "packages" / "marty_common" / "plan_catalog.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text('{"plans":[{"billing":{"annual_price":12000}}]}', encoding="utf-8")

    findings = scan_repository(tmp_path)

    assert findings == [
        "commercial catalog key 'annual_price': packages/marty_common/plan_catalog.json",
        "commercial catalog key 'billing': packages/marty_common/plan_catalog.json",
        "forbidden path: packages/marty_common/plan_catalog.json",
    ]


@pytest.mark.parametrize("relative", ["docker/ui.Dockerfile", "scripts/ui_release.py"])
def test_exact_production_identity_metadata_is_allowed(tmp_path: Path, relative: str) -> None:
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text((REPO_ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")

    assert scan_repository(tmp_path) == []


@pytest.mark.parametrize("relative", ["docker/ui.Dockerfile", "scripts/ui_release.py"])
@pytest.mark.parametrize("payload,marker", [
    ('git clone https://github.com/ElevenID/marty-subscriptions',
     "ElevenID/marty-subscriptions"),
    ('import("@marty/subscriptions")', "@marty/subscriptions"),
    ('{"dependencies":{"@marty/subscriptions":"0.1.0"}}', "@marty/subscriptions"),
    ('endpoint = "/v1/billing"', "/v1/billing"),
    ('endpoint = "/v1/plans"', "/v1/plans"),
    ('endpoint = "/v1/usage"', "/v1/usage"),
    ('endpoint = "https://connect.squareup.com/v2/payments"', "connect.squareup.com"),
    ('SQUARE_ACCESS_TOKEN = "private-input"', "SQUARE_ACCESS_TOKEN"),
    ('SQUARE_WEBHOOK_SIGNATURE_KEY = "private-input"', "SQUARE_WEBHOOK_SIGNATURE_KEY"),
])
def test_metadata_file_still_rejects_private_source_and_billing_inputs(
    tmp_path: Path, relative: str, payload: str, marker: str,
) -> None:
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text(
        (REPO_ROOT / relative).read_text(encoding="utf-8") + "\n" + payload + "\n",
        encoding="utf-8",
    )

    assert f"forbidden marker {marker!r}: {relative}" in scan_repository(tmp_path)


@pytest.mark.parametrize("relative", ["docker/ui.Dockerfile", "scripts/ui_release.py"])
@pytest.mark.parametrize("mutation", ["extend", "repeat", "relocate"])
def test_identity_exception_requires_exact_statement_once_at_exact_path(
    tmp_path: Path, relative: str, mutation: str,
) -> None:
    content = (REPO_ROOT / relative).read_text(encoding="utf-8")
    statement = next(line for line in content.splitlines()
                     if "ElevenID/marty-subscriptions" in line)
    if mutation == "extend":
        content = content.replace(statement, statement + "; fetch_private_source()", 1)
    elif mutation == "repeat":
        content += "\n" + statement + "\n"
    else:
        relative = "scripts/unreviewed-release.py"
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text(content, encoding="utf-8")

    assert ("forbidden marker 'ElevenID/marty-subscriptions': "
            + relative) in scan_repository(tmp_path)


def test_production_identity_constant_cannot_be_reused_to_fetch_private_source(
    tmp_path: Path,
) -> None:
    relative = "scripts/ui_release.py"
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text(
        (REPO_ROOT / relative).read_text(encoding="utf-8")
        + '\nsubprocess.run(["git", "clone", COMMERCE_REPOSITORY], check=True)\n',
        encoding="utf-8",
    )

    assert scan_repository(tmp_path) == [
        f"forbidden marker 'COMMERCE_REPOSITORY': {relative}",
    ]
