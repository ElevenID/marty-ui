// ============================================================================
// MIP Cedar Policies - Application Approval Rules
// ============================================================================
//
// Runtime approval policies used by provider-backed evidence flows.
// Provider adapters pass normalized EvidenceFact summaries through
// ApprovalContext; policies never parse provider payloads directly.
// ============================================================================

@id("auto-approve-verified-external-evidence")
permit (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context has evidence_provider &&
    context has evidence_verification_status &&
    context has evidence_scope_matched &&
    context has all_required_evidence_satisfied &&
    context has satisfied_requirement_count &&
    context has required_evidence_count &&
    context.evidence_verification_status == "VERIFIED" &&
    context.evidence_scope_matched &&
    context.all_required_evidence_satisfied &&
    context.satisfied_requirement_count >= context.required_evidence_count
};

@id("deny-unverified-external-evidence")
forbid (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context has evidence_provider &&
    context has evidence_verification_status &&
    context.evidence_verification_status != "VERIFIED"
};

@id("deny-wrong-scope-external-evidence")
forbid (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context has evidence_provider &&
    context has evidence_scope_matched &&
    !context.evidence_scope_matched
};
