from marty_common.system_ids import (
    MARTY_DEFAULT_ORG_ID,
    MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID,
    MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID,
    MARTY_MEMBER_MDOC_TEMPLATE_ID,
    MARTY_MEMBER_SD_JWT_TEMPLATE_ID,
    MARTY_OPEN_BADGE_LOGIN_POLICY_ID,
    MARTY_TRUST_BUNDLE_SOURCE_ID,
    MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID,
    MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID,
    SYSTEM_ID_GROUPS,
    flatten_system_ids,
)


def test_known_system_ids_expose_expected_anchor_values() -> None:
    assert MARTY_DEFAULT_ORG_ID == "00000000-0000-0000-0000-000000000001"
    assert MARTY_MEMBER_SD_JWT_TEMPLATE_ID == "50000000-0000-0000-0000-000000000010"
    assert MARTY_MEMBER_MDOC_TEMPLATE_ID == "50000000-0000-0000-0000-000000000030"
    assert MARTY_OPEN_BADGE_LOGIN_POLICY_ID == "50000000-0000-0000-0000-000000000004"
    assert MARTY_TRUST_BUNDLE_SOURCE_ID == "60000000-0000-0000-0000-000000000021"
    assert MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID == "50000000-0000-0000-0000-000000000040"
    assert MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID == "0ab66d45-0d84-5fbd-837f-25788d32279e"
    assert MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID == "50000000-0000-0000-0000-000000000041"
    assert MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID == "0ab66d45-0d84-5fbd-837f-25788d3227a1"


def test_flatten_system_ids_returns_grouped_keys() -> None:
    flattened = flatten_system_ids()

    assert flattened["organizations.marty_default"] == MARTY_DEFAULT_ORG_ID
    assert flattened["presentation_policies.open_badge_login"] == MARTY_OPEN_BADGE_LOGIN_POLICY_ID
    assert flattened["application_templates.verified_member_badge"] == MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID
    assert flattened["credential_templates.verified_member_badge"] == MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID
    assert flattened["application_templates.canvas_mip_quiz_open_badge"] == MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID
    assert flattened["credential_templates.canvas_mip_quiz_open_badge"] == MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID

    expected_count = sum(len(group) for group in SYSTEM_ID_GROUPS.values())
    assert len(flattened) == expected_count
