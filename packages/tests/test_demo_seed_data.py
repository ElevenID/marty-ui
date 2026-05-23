from marty_common.demo_seed_data import (
    DEMO_VENDOR_ORG_ID,
    DEMO_VENDOR_SPRUCEKIT_MDL_WALLET_CONFIG,
    DEMO_VENDOR_WALLET_CONFIG,
    DEMO_VENDOR_CREDENTIAL_TEMPLATES,
    get_demo_vendor_seed_bundle,
)


def test_demo_vendor_seed_bundle_contains_expected_fixture_shape() -> None:
    bundle = get_demo_vendor_seed_bundle()

    assert bundle["organization"]["id"] == DEMO_VENDOR_ORG_ID
    assert {row["name"] for row in bundle["credential_types"]} == {
        "passport",
        "drivers_license",
        "national_id",
        "travel_visa",
        "access_badge",
        "dtc",
        "open_badge",
    }
    assert {row["credential_type"] for row in bundle["credential_templates"]} == {
        "passport",
        "drivers_license",
        "national_id",
        "travel_visa",
        "access_badge",
        "dtc",
        "open_badge",
        "org.iso.18013.5.1.mDL",
    }


def test_open_badge_demo_template_matches_curated_fixture() -> None:
    open_badge = next(
        row for row in DEMO_VENDOR_CREDENTIAL_TEMPLATES if row["credential_type"] == "open_badge"
    )

    assert open_badge["name"] == "Professional Development Certificate"
    assert any(
        claim["name"] == "completion_date" and claim["claim_type"] == "date"
        for claim in open_badge["claims"]
    )
    assert open_badge["wallet_configs"] == [DEMO_VENDOR_WALLET_CONFIG]


def test_iso_mdl_demo_template_matches_sprucekit_fixture() -> None:
    iso_mdl = next(
        row for row in DEMO_VENDOR_CREDENTIAL_TEMPLATES if row["credential_type"] == "org.iso.18013.5.1.mDL"
    )

    assert iso_mdl["credential_payload_format"] == "mso_mdoc"
    assert iso_mdl["supported_formats"] == ["mso_mdoc"]
    assert iso_mdl["wallet_configs"] == [DEMO_VENDOR_SPRUCEKIT_MDL_WALLET_CONFIG]
    assert any(
        claim["name"] == "driving_privileges" and claim["selectively_disclosable"] is False
        for claim in iso_mdl["claims"]
    )