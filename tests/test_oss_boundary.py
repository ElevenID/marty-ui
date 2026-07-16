from pathlib import Path

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
    ]
