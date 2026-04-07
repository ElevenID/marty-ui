// ============================================================================
// Billing Plan-Tier Feature Gates — Cedar Forbid Policies
// ============================================================================
//
// INTERNAL to the Marty platform — NOT part of the MIP protocol.
//
// These forbid policies restrict access to plan-gated features based on the
// organization's plan tier. They are evaluated by BillingCedarEngine as a
// separate authorization decision after MIP RBAC.
//
// Because Cedar is deny-by-default, a blanket permit is required for paid
// tiers, then forbid policies carve out restrictions for lower tiers.
//
// Plan matrix (from plans.py):
//   free:         no webhooks, no audit_logs, no custom_cedar_policies, no device_registration
//   starter:      + webhooks, + audit_logs
//   professional: + custom_cedar_policies, + device_registration, + multi_environment
//   enterprise:   everything
// ============================================================================

// ── Default permit: allow all billing actions (forbids carve out restrictions) ─

@id("billing-default-permit")
permit (
    principal,
    action,
    resource
);

// ── Webhooks: blocked on Free tier ──────────────────────────────────────

@id("billing-deny-webhooks-free")
forbid (
    principal,
    action in [Billing::Action::"webhooks:read", Billing::Action::"webhooks:write"],
    resource
)
when {
    context.plan_tier == "free"
};

// ── Audit logs: blocked on Free tier ────────────────────────────────────

@id("billing-deny-audit-free")
forbid (
    principal,
    action == Billing::Action::"audit:read",
    resource
)
when {
    context.plan_tier == "free"
};

// ── Deployment writes (multi-environment): blocked on Free + Starter ────

@id("billing-deny-deployment-write-low-tier")
forbid (
    principal,
    action == Billing::Action::"deployment:write",
    resource
)
when {
    context.plan_tier == "free" || context.plan_tier == "starter"
};

// ── Custom Cedar policies: blocked on Free + Starter ────────────────────

@id("billing-deny-custom-cedar-low-tier")
forbid (
    principal,
    action == Billing::Action::"custom_cedar_policies:access",
    resource
)
when {
    context.plan_tier == "free" || context.plan_tier == "starter"
};

// ── Device registration (kiosk): blocked on Free + Starter ──────────────

@id("billing-deny-device-reg-low-tier")
forbid (
    principal,
    action == Billing::Action::"device_registration:access",
    resource
)
when {
    context.plan_tier == "free" || context.plan_tier == "starter"
};
