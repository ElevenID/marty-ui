from marty_common.plans import PlanTier, get_plan_limits, resolve_plan_info, resolve_plan_tier


def test_resolve_plan_tier_maps_current_commercial_aliases_to_internal_tiers():
    assert resolve_plan_tier("free") == PlanTier.SANDBOX
    assert resolve_plan_tier("starter") == PlanTier.PROGRAM
    assert resolve_plan_tier("hosted_pilot") == PlanTier.PROGRAM
    assert resolve_plan_tier("professional") == PlanTier.PROGRAM
    assert resolve_plan_tier("enterprise") == PlanTier.SYSTEM


def test_get_plan_limits_accepts_commercial_billing_tiers():
    assert get_plan_limits("free") == get_plan_limits(PlanTier.SANDBOX)
    assert get_plan_limits("starter") == get_plan_limits(PlanTier.PROGRAM)
    assert get_plan_limits("professional") == get_plan_limits(PlanTier.PROGRAM)
    assert get_plan_limits("enterprise") == get_plan_limits(PlanTier.SYSTEM)


def test_resolve_plan_info_prefers_current_commercial_labels():
    free_info = resolve_plan_info("free")
    assert free_info.display_name == "Developer Sandbox"
    assert free_info.monthly_price == 0

    starter_info = resolve_plan_info("starter")
    assert starter_info.display_name == "Hosted Pilot"
    assert starter_info.monthly_price == 299

    professional_info = resolve_plan_info("professional")
    assert professional_info.display_name == "Self-Hosted Production"
    assert professional_info.annual_price == 12000