"""
Policy-Based Selective Disclosure Engine

Implements context-aware selective disclosure using Marty's authorization engine
for policy-based attribute sharing decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class PolicyBasedDisclosureEngine:
    """Engine for policy-driven selective disclosure decisions."""

    def __init__(self):
        self.disclosure_policies = self._initialize_disclosure_policies()
        self.context_rules = self._initialize_context_rules()
        self.attribute_sensitivity = self._initialize_attribute_sensitivity()
        self.purpose_mappings = self._initialize_purpose_mappings()

    def _initialize_disclosure_policies(self) -> dict[str, Any]:
        """Initialize disclosure policies for different contexts."""

        return {
            "retail_age_verification": {
                "policy_id": "retail_age_001",
                "name": "Retail Age Verification",
                "description": "Minimal disclosure for retail age verification",
                "context_type": "commercial",
                "purpose": "age_verification",
                "trust_level": "medium",
                "allowed_attributes": {
                    "required": ["age_over_18", "age_over_21"],
                    "optional": ["given_name"],
                    "prohibited": ["birth_date", "address", "portrait", "document_number"],
                },
                "data_retention": {"allowed": False, "max_duration": "immediate_use_only"},
                "privacy_level": "high",
            },
            "government_identity_verification": {
                "policy_id": "gov_id_001",
                "name": "Government Identity Verification",
                "description": "Enhanced disclosure for government services",
                "context_type": "government",
                "purpose": "identity_verification",
                "trust_level": "high",
                "allowed_attributes": {
                    "required": ["family_name", "given_name", "birth_date", "document_number"],
                    "optional": ["address", "portrait"],
                    "prohibited": ["driving_privileges"],
                },
                "data_retention": {
                    "allowed": True,
                    "max_duration": "30_days",
                    "purpose_limitation": True,
                },
                "privacy_level": "medium",
            },
            "employment_verification": {
                "policy_id": "emp_ver_001",
                "name": "Employment Verification",
                "description": "Employment eligibility verification",
                "context_type": "employment",
                "purpose": "work_authorization",
                "trust_level": "medium",
                "allowed_attributes": {
                    "required": ["family_name", "given_name", "age_over_18"],
                    "optional": ["age_over_21", "document_number"],
                    "prohibited": ["birth_date", "address", "portrait", "driving_privileges"],
                },
                "data_retention": {
                    "allowed": True,
                    "max_duration": "6_months",
                    "purpose_limitation": True,
                },
                "privacy_level": "medium",
            },
            "financial_kyc": {
                "policy_id": "fin_kyc_001",
                "name": "Financial KYC Verification",
                "description": "Know Your Customer verification for financial services",
                "context_type": "financial",
                "purpose": "kyc_compliance",
                "trust_level": "high",
                "allowed_attributes": {
                    "required": [
                        "family_name",
                        "given_name",
                        "birth_date",
                        "address",
                        "document_number",
                    ],
                    "optional": ["portrait"],
                    "prohibited": ["driving_privileges"],
                },
                "data_retention": {
                    "allowed": True,
                    "max_duration": "7_years",
                    "purpose_limitation": True,
                },
                "privacy_level": "low",
            },
            "healthcare_age_verification": {
                "policy_id": "health_age_001",
                "name": "Healthcare Age Verification",
                "description": "Age verification for healthcare services",
                "context_type": "healthcare",
                "purpose": "healthcare_eligibility",
                "trust_level": "high",
                "allowed_attributes": {
                    "required": ["age_over_18", "age_over_65"],
                    "optional": ["given_name", "family_name"],
                    "prohibited": [
                        "birth_date",
                        "address",
                        "portrait",
                        "document_number",
                        "driving_privileges",
                    ],
                },
                "data_retention": {"allowed": False, "max_duration": "session_only"},
                "privacy_level": "high",
            },
            "law_enforcement": {
                "policy_id": "law_enf_001",
                "name": "Law Enforcement Verification",
                "description": "Full disclosure for law enforcement with warrant",
                "context_type": "law_enforcement",
                "purpose": "legal_investigation",
                "trust_level": "highest",
                "allowed_attributes": {
                    "required": ["*"],  # All attributes when legally authorized
                    "optional": [],
                    "prohibited": [],
                },
                "data_retention": {
                    "allowed": True,
                    "max_duration": "as_legally_required",
                    "purpose_limitation": False,
                },
                "privacy_level": "minimal",
                "special_authorization_required": True,
            },
        }

    def _initialize_context_rules(self) -> dict[str, Any]:
        """Initialize context-based disclosure rules."""

        return {
            "location_sensitivity": {
                "public_space": {
                    "default_privacy_level": "high",
                    "recommended_disclosure": "minimal",
                    "additional_protections": ["no_biometric_data"],
                },
                "private_establishment": {
                    "default_privacy_level": "medium",
                    "recommended_disclosure": "purpose_limited",
                    "additional_protections": ["data_retention_limits"],
                },
                "government_facility": {
                    "default_privacy_level": "medium",
                    "recommended_disclosure": "enhanced",
                    "additional_protections": ["audit_trail_required"],
                },
                "secure_facility": {
                    "default_privacy_level": "low",
                    "recommended_disclosure": "comprehensive",
                    "additional_protections": ["full_audit_trail"],
                },
            },
            "time_sensitivity": {
                "emergency": {
                    "disclosure_level": "enhanced",
                    "approval_required": False,
                    "retention_limits": "emergency_duration_only",
                },
                "routine": {
                    "disclosure_level": "standard",
                    "approval_required": True,
                    "retention_limits": "policy_defined",
                },
                "batch_processing": {
                    "disclosure_level": "minimal",
                    "approval_required": True,
                    "retention_limits": "immediate_processing_only",
                },
            },
            "verifier_trust": {
                "unverified": {
                    "max_disclosure": "public_attributes_only",
                    "requires_consent": True,
                    "audit_level": "full",
                },
                "verified_commercial": {
                    "max_disclosure": "business_purpose_limited",
                    "requires_consent": True,
                    "audit_level": "standard",
                },
                "government_verified": {
                    "max_disclosure": "government_purpose_limited",
                    "requires_consent": False,
                    "audit_level": "enhanced",
                },
                "certified_high_trust": {
                    "max_disclosure": "comprehensive_with_oversight",
                    "requires_consent": False,
                    "audit_level": "comprehensive",
                },
            },
        }

    def _initialize_attribute_sensitivity(self) -> dict[str, Any]:
        """Initialize attribute sensitivity classifications."""

        return {
            "public": {
                "attributes": ["age_over_18", "age_over_21", "age_over_65"],
                "sensitivity_level": "low",
                "default_disclosure": "allowed",
                "restrictions": "none",
            },
            "personal_identifiable": {
                "attributes": ["family_name", "given_name", "document_number"],
                "sensitivity_level": "medium",
                "default_disclosure": "purpose_limited",
                "restrictions": "consent_required",
            },
            "highly_sensitive": {
                "attributes": ["birth_date", "address", "portrait"],
                "sensitivity_level": "high",
                "default_disclosure": "restricted",
                "restrictions": "explicit_consent_and_purpose",
            },
            "biometric": {
                "attributes": ["portrait", "fingerprint", "iris_scan"],
                "sensitivity_level": "highest",
                "default_disclosure": "prohibited_unless_essential",
                "restrictions": "special_authorization_required",
            },
            "operational": {
                "attributes": ["driving_privileges", "restrictions", "endorsements"],
                "sensitivity_level": "medium",
                "default_disclosure": "context_dependent",
                "restrictions": "purpose_verification_required",
            },
        }

    def _initialize_purpose_mappings(self) -> dict[str, Any]:
        """Initialize purpose-to-attribute mappings."""

        return {
            "age_verification": {
                "essential_attributes": ["age_over_18", "age_over_21"],
                "supporting_attributes": ["given_name"],
                "prohibited_attributes": ["birth_date", "address", "portrait"],
            },
            "identity_verification": {
                "essential_attributes": ["family_name", "given_name"],
                "supporting_attributes": ["document_number", "portrait"],
                "prohibited_attributes": ["driving_privileges"],
            },
            "driving_verification": {
                "essential_attributes": ["family_name", "given_name", "driving_privileges"],
                "supporting_attributes": ["document_number", "portrait", "restrictions"],
                "prohibited_attributes": ["address"],
            },
            "address_verification": {
                "essential_attributes": ["family_name", "given_name", "address"],
                "supporting_attributes": ["document_number"],
                "prohibited_attributes": ["birth_date", "portrait", "driving_privileges"],
            },
        }

    def evaluate_disclosure_policy(
        self,
        presentation_request: dict[str, Any],
        available_attributes: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate what attributes should be disclosed based on policy."""

        # Determine applicable policy
        policy = self._select_applicable_policy(presentation_request, context)

        # Evaluate context factors
        context_evaluation = self._evaluate_context_factors(context)

        # Determine attribute disclosure permissions
        disclosure_decisions = self._make_disclosure_decisions(
            presentation_request, available_attributes, policy, context_evaluation
        )

        # Apply privacy protections
        privacy_protections = self._apply_privacy_protections(
            disclosure_decisions, policy, context_evaluation
        )

        # Generate user consent requirements
        consent_requirements = self._generate_consent_requirements(
            disclosure_decisions, policy, context
        )

        return {
            "evaluation_id": f"eval_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "applicable_policy": policy,
            "context_evaluation": context_evaluation,
            "disclosure_decisions": disclosure_decisions,
            "privacy_protections": privacy_protections,
            "consent_requirements": consent_requirements,
            "recommended_action": self._determine_recommended_action(disclosure_decisions),
            "risk_assessment": self._assess_disclosure_risk(disclosure_decisions, context),
            "audit_record": self._create_audit_record(
                presentation_request, context, disclosure_decisions
            ),
        }

    def _select_applicable_policy(
        self, request: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Select the most applicable disclosure policy."""

        context_type = context.get("context_type", "unknown")
        purpose = request.get("purpose", "general")
        trust_level = context.get("verifier_trust_level", "unverified")

        # Find matching policies
        matching_policies = []
        for policy_id, policy in self.disclosure_policies.items():
            if policy.get("context_type") == context_type and policy.get("purpose") == purpose:
                matching_policies.append(policy)

        # If no exact match, use fallback logic
        if not matching_policies:
            if context_type == "government":
                return self.disclosure_policies["government_identity_verification"]
            elif context_type == "commercial":
                return self.disclosure_policies["retail_age_verification"]
            else:
                # Default to most restrictive policy
                return self.disclosure_policies["retail_age_verification"]

        # Select policy with appropriate trust level
        for policy in matching_policies:
            if policy.get("trust_level") == trust_level:
                return policy

        # Fallback to first matching policy
        return matching_policies[0]

    def _evaluate_context_factors(self, context: dict[str, Any]) -> dict[str, Any]:
        """Evaluate contextual factors affecting disclosure."""

        location = context.get("location", "unknown")
        urgency = context.get("urgency", "routine")
        verifier_trust = context.get("verifier_trust_level", "unverified")

        location_rules = self.context_rules["location_sensitivity"].get(
            location, self.context_rules["location_sensitivity"]["public_space"]
        )

        time_rules = self.context_rules["time_sensitivity"].get(
            urgency, self.context_rules["time_sensitivity"]["routine"]
        )

        trust_rules = self.context_rules["verifier_trust"].get(
            verifier_trust, self.context_rules["verifier_trust"]["unverified"]
        )

        return {
            "location_assessment": location_rules,
            "time_assessment": time_rules,
            "trust_assessment": trust_rules,
            "overall_risk_level": self._calculate_overall_risk(
                location_rules, time_rules, trust_rules
            ),
            "privacy_recommendations": self._generate_privacy_recommendations(
                location_rules, time_rules, trust_rules
            ),
        }

    def _make_disclosure_decisions(
        self,
        request: dict[str, Any],
        available_attributes: dict[str, Any],
        policy: dict[str, Any],
        context_eval: dict[str, Any],
    ) -> dict[str, Any]:
        """Make specific disclosure decisions for each attribute."""

        requested_attributes = request.get("requested_attributes", [])
        required_attrs = policy["allowed_attributes"]["required"]
        optional_attrs = policy["allowed_attributes"]["optional"]
        prohibited_attrs = policy["allowed_attributes"]["prohibited"]

        decisions = {"approved": {}, "denied": {}, "conditional": {}, "requires_consent": {}}

        for attr_name, attr_value in available_attributes.items():
            if attr_name not in requested_attributes:
                continue

            # Check if attribute is prohibited
            if attr_name in prohibited_attrs:
                decisions["denied"][attr_name] = {
                    "reason": "prohibited_by_policy",
                    "policy_rule": "explicit_prohibition",
                }
                continue

            # Check sensitivity level
            sensitivity = self._get_attribute_sensitivity(attr_name)

            # Make disclosure decision based on policy and sensitivity
            if attr_name in required_attrs:
                if sensitivity["sensitivity_level"] in ["low", "medium"]:
                    decisions["approved"][attr_name] = {
                        "value": attr_value,
                        "reason": "required_by_policy",
                        "sensitivity": sensitivity["sensitivity_level"],
                    }
                else:
                    decisions["conditional"][attr_name] = {
                        "value": attr_value,
                        "reason": "high_sensitivity_requires_review",
                        "conditions": ["explicit_consent", "purpose_verification"],
                    }
            elif attr_name in optional_attrs:
                if context_eval["overall_risk_level"] == "low":
                    decisions["requires_consent"][attr_name] = {
                        "value": attr_value,
                        "reason": "optional_requires_consent",
                        "consent_type": "explicit",
                    }
                else:
                    decisions["denied"][attr_name] = {
                        "reason": "high_risk_context",
                        "risk_level": context_eval["overall_risk_level"],
                    }
            else:
                decisions["denied"][attr_name] = {
                    "reason": "not_in_policy",
                    "policy_rule": "default_deny",
                }

        return decisions

    def _get_attribute_sensitivity(self, attr_name: str) -> dict[str, Any]:
        """Get sensitivity classification for an attribute."""

        for category, info in self.attribute_sensitivity.items():
            if attr_name in info["attributes"]:
                return info

        # Default to medium sensitivity for unknown attributes
        return {
            "sensitivity_level": "medium",
            "default_disclosure": "purpose_limited",
            "restrictions": "consent_required",
        }

    def _calculate_overall_risk(
        self,
        location_rules: dict[str, Any],
        time_rules: dict[str, Any],
        trust_rules: dict[str, Any],
    ) -> str:
        """Calculate overall risk level from context factors."""

        privacy_level = location_rules.get("default_privacy_level", "high")
        disclosure_level = time_rules.get("disclosure_level", "standard")
        max_disclosure = trust_rules.get("max_disclosure", "minimal")

        # Simple risk calculation (in production, this would be more sophisticated)
        risk_score = 0

        if privacy_level == "low":
            risk_score += 3
        elif privacy_level == "medium":
            risk_score += 2
        else:
            risk_score += 1

        if "minimal" in max_disclosure:
            risk_score += 1
        elif "comprehensive" in max_disclosure:
            risk_score += 3
        else:
            risk_score += 2

        if risk_score <= 3:
            return "low"
        elif risk_score <= 5:
            return "medium"
        else:
            return "high"

    def _generate_privacy_recommendations(
        self,
        location_rules: dict[str, Any],
        time_rules: dict[str, Any],
        trust_rules: dict[str, Any],
    ) -> list[str]:
        """Generate privacy recommendations based on context."""

        recommendations = []

        if location_rules.get("default_privacy_level") == "high":
            recommendations.append("Use minimal disclosure appropriate for public setting")

        if trust_rules.get("requires_consent"):
            recommendations.append("Explicit user consent required before disclosure")

        if time_rules.get("retention_limits") == "immediate_processing_only":
            recommendations.append("Ensure immediate deletion after processing")

        return recommendations

    def _apply_privacy_protections(
        self, decisions: dict[str, Any], policy: dict[str, Any], context_eval: dict[str, Any]
    ) -> dict[str, Any]:
        """Apply privacy protections to disclosure decisions."""

        return {
            "data_minimization": {
                "applied": True,
                "description": "Only attributes necessary for stated purpose are disclosed",
            },
            "purpose_limitation": {
                "applied": policy["data_retention"]["purpose_limitation"],
                "description": "Data use limited to stated purpose only",
            },
            "retention_limits": {
                "max_duration": policy["data_retention"]["max_duration"],
                "deletion_required": policy["data_retention"]["max_duration"]
                != "as_legally_required",
            },
            "access_controls": {
                "audit_required": True,
                "access_logging": "full",
                "authorized_personnel_only": True,
            },
            "technical_protections": [
                "encryption_in_transit",
                "encryption_at_rest",
                "digital_signatures",
                "non_repudiation",
            ],
        }

    def _generate_consent_requirements(
        self, decisions: dict[str, Any], policy: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate user consent requirements."""

        requires_consent_attrs = list(decisions.get("requires_consent", {}).keys())
        conditional_attrs = list(decisions.get("conditional", {}).keys())

        if not requires_consent_attrs and not conditional_attrs:
            return {"consent_required": False, "consent_type": "none"}

        return {
            "consent_required": True,
            "consent_type": "explicit",
            "attributes_requiring_consent": requires_consent_attrs + conditional_attrs,
            "consent_text": self._generate_consent_text(
                requires_consent_attrs + conditional_attrs, policy, context
            ),
            "withdrawal_allowed": True,
            "retention_notice": f"Data will be retained for: {policy['data_retention']['max_duration']}",
        }

    def _generate_consent_text(
        self, attributes: list[str], policy: dict[str, Any], context: dict[str, Any]
    ) -> str:
        """Generate user-friendly consent text."""

        purpose = policy.get("purpose", "verification")
        context_type = policy.get("context_type", "general")
        retention = policy["data_retention"]["max_duration"]

        attr_descriptions = {
            "given_name": "first name",
            "family_name": "last name",
            "birth_date": "date of birth",
            "address": "address",
            "portrait": "photo",
            "document_number": "ID number",
        }

        attr_list = ", ".join([attr_descriptions.get(attr, attr) for attr in attributes])

        return (
            f"Do you consent to sharing your {attr_list} "
            f"for {purpose} with this {context_type} organization? "
            f"Your information will be retained for {retention}."
        )

    def _determine_recommended_action(self, decisions: dict[str, Any]) -> str:
        """Determine recommended action based on disclosure decisions."""

        if decisions["denied"]:
            return "review_required"
        elif decisions["conditional"]:
            return "conditional_approval"
        elif decisions["requires_consent"]:
            return "user_consent_required"
        else:
            return "approve"

    def _assess_disclosure_risk(
        self, decisions: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Assess privacy and security risks of disclosure."""

        disclosed_sensitive = any(
            self._get_attribute_sensitivity(attr)["sensitivity_level"] in ["high", "highest"]
            for attr in decisions.get("approved", {}).keys()
        )

        return {
            "overall_risk": "high" if disclosed_sensitive else "medium",
            "privacy_risk": "medium" if len(decisions.get("approved", {})) > 3 else "low",
            "security_risk": "low",  # Assuming secure channel
            "compliance_risk": (
                "low" if context.get("verifier_trust_level") == "verified_commercial" else "medium"
            ),
            "recommendations": [
                "Ensure secure transmission",
                "Verify verifier identity",
                "Audit disclosure decision",
            ],
        }

    def _create_audit_record(
        self, request: dict[str, Any], context: dict[str, Any], decisions: dict[str, Any]
    ) -> dict[str, Any]:
        """Create audit record for disclosure decision."""

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.get("request_id", "unknown"),
            "verifier_id": context.get("verifier_id", "unknown"),
            "purpose": request.get("purpose", "unknown"),
            "context_type": context.get("context_type", "unknown"),
            "approved_attributes": list(decisions.get("approved", {}).keys()),
            "denied_attributes": list(decisions.get("denied", {}).keys()),
            "user_consent_given": context.get("user_consent", False),
            "policy_applied": context.get("policy_id", "unknown"),
            "risk_level": context.get("risk_level", "unknown"),
        }

    def get_policy_summary(self) -> dict[str, Any]:
        """Get summary of all disclosure policies."""

        return {
            "total_policies": len(self.disclosure_policies),
            "policy_types": list({p["context_type"] for p in self.disclosure_policies.values()}),
            "privacy_levels": list({p["privacy_level"] for p in self.disclosure_policies.values()}),
            "purposes_supported": list({p["purpose"] for p in self.disclosure_policies.values()}),
            "policies": {
                policy_id: {
                    "name": policy["name"],
                    "context_type": policy["context_type"],
                    "purpose": policy["purpose"],
                    "privacy_level": policy["privacy_level"],
                    "trust_level": policy["trust_level"],
                }
                for policy_id, policy in self.disclosure_policies.items()
            },
        }
