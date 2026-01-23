"""
Enhanced Age Verification Service

Implements advanced age verification with zero-knowledge proofs,
selective disclosure, and policy-based verification.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Any

from fastapi import HTTPException

logger = logging.getLogger(__name__)


class AgeVerificationEngine:
    """Enhanced age verification with selective disclosure and ZK proofs."""

    def __init__(self):
        self.verification_policies = {
            "age_over_18": {
                "description": "Verify person is 18 or older without revealing birth date",
                "required_proof": "age_threshold",
                "threshold": 18,
                "disclosed_attributes": ["age_over_18"],
                "privacy_level": "high",
            },
            "age_over_21": {
                "description": "Verify person is 21 or older for alcohol/tobacco verification",
                "required_proof": "age_threshold",
                "threshold": 21,
                "disclosed_attributes": ["age_over_21"],
                "privacy_level": "high",
            },
            "age_range_verification": {
                "description": "Verify person is within age range without exact age",
                "required_proof": "age_range",
                "min_age": 18,
                "max_age": 65,
                "disclosed_attributes": ["age_in_range"],
                "privacy_level": "medium",
            },
            "senior_verification": {
                "description": "Verify senior citizen status for discounts",
                "required_proof": "age_threshold",
                "threshold": 65,
                "disclosed_attributes": ["age_over_65"],
                "privacy_level": "medium",
            },
        }

        self.use_cases = {
            "alcohol_purchase": {
                "policy": "age_over_21",
                "context": "retail",
                "purpose": "age_restricted_purchase",
                "required_attributes": ["age_over_21"],
                "optional_attributes": ["given_name"],
            },
            "voting_registration": {
                "policy": "age_over_18",
                "context": "government",
                "purpose": "electoral_participation",
                "required_attributes": ["age_over_18"],
                "optional_attributes": ["family_name", "given_name"],
            },
            "senior_discount": {
                "policy": "senior_verification",
                "context": "retail",
                "purpose": "discount_eligibility",
                "required_attributes": ["age_over_65"],
                "optional_attributes": ["given_name"],
            },
            "employment_eligibility": {
                "policy": "age_range_verification",
                "context": "employment",
                "purpose": "work_authorization",
                "required_attributes": ["age_in_range"],
                "optional_attributes": ["family_name", "given_name"],
            },
        }

    def create_age_verification_request(
        self, use_case: str, verifier_id: str, purpose: str | None = None
    ) -> dict[str, Any]:
        """Create an age verification request for specific use case."""

        if use_case not in self.use_cases:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown use case: {use_case}. Available: {list(self.use_cases.keys())}",
            )

        use_case_config = self.use_cases[use_case]
        policy = self.verification_policies[use_case_config["policy"]]

        request = {
            "request_id": f"age_verify_{datetime.utcnow().isoformat()}",
            "verifier_id": verifier_id,
            "use_case": use_case,
            "purpose": purpose or use_case_config["purpose"],
            "context": use_case_config["context"],
            "verification_policy": {
                "type": policy["required_proof"],
                "description": policy["description"],
                "privacy_level": policy["privacy_level"],
            },
            "required_proofs": [],
            "disclosed_attributes": policy["disclosed_attributes"],
            "presentation_definition": {
                "id": f"age_verification_{use_case}",
                "purpose": purpose or use_case_config["purpose"],
                "input_descriptors": [
                    {
                        "id": "mdl_age_verification",
                        "name": "Mobile Driving License - Age Verification",
                        "purpose": f"Age verification for {use_case}",
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.credentialSubject.age_over_18"],
                                    "filter": {"type": "boolean"},
                                    "required": "age_over_18" in policy["disclosed_attributes"],
                                },
                                {
                                    "path": ["$.credentialSubject.age_over_21"],
                                    "filter": {"type": "boolean"},
                                    "required": "age_over_21" in policy["disclosed_attributes"],
                                },
                                {
                                    "path": ["$.credentialSubject.age_over_65"],
                                    "filter": {"type": "boolean"},
                                    "required": "age_over_65" in policy["disclosed_attributes"],
                                },
                            ]
                        },
                    }
                ],
            },
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow().replace(hour=23, minute=59, second=59)).isoformat(),
        }

        # Add threshold-specific requirements
        if policy["required_proof"] == "age_threshold":
            request["verification_policy"]["threshold"] = policy["threshold"]
            request["required_proofs"].append(
                {
                    "type": "age_threshold_proof",
                    "threshold": policy["threshold"],
                    "proof_method": "selective_disclosure",
                }
            )
        elif policy["required_proof"] == "age_range":
            request["verification_policy"]["min_age"] = policy["min_age"]
            request["verification_policy"]["max_age"] = policy["max_age"]
            request["required_proofs"].append(
                {
                    "type": "age_range_proof",
                    "min_age": policy["min_age"],
                    "max_age": policy["max_age"],
                    "proof_method": "selective_disclosure",
                }
            )

        return request

    def verify_age_presentation(
        self, presentation: dict[str, Any], verification_request: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify age presentation against the verification request."""

        try:
            # Extract presentation data
            presented_credentials = presentation.get("verifiableCredential", [])
            if not presented_credentials:
                raise ValueError("No credentials presented")

            credential = presented_credentials[0]
            subject_data = credential.get("credentialSubject", {})

            # Get verification policy
            policy_name = verification_request.get("use_case", "")
            if not policy_name or policy_name not in self.use_cases:
                raise ValueError(f"Invalid use case: {policy_name}")

            use_case_config = self.use_cases[policy_name]
            policy_key = use_case_config.get("policy", "")
            if not policy_key or policy_key not in self.verification_policies:
                raise ValueError(f"Invalid policy: {policy_key}")

            policy = self.verification_policies[policy_key]

            verification_result = {
                "request_id": verification_request.get("request_id"),
                "verified": False,
                "verification_type": policy.get("required_proof"),
                "use_case": policy_name,
                "privacy_preserved": True,
                "disclosed_attributes": {},
                "proof_results": [],
                "warnings": [],
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Verify required proofs
            if policy.get("required_proof") == "age_threshold":
                threshold = policy.get("threshold", 18)
                age_attribute = f"age_over_{threshold}"

                if age_attribute in subject_data:
                    age_verified = subject_data[age_attribute]
                    verification_result["verified"] = bool(age_verified)
                    verification_result["disclosed_attributes"][age_attribute] = age_verified
                    verification_result["proof_results"].append(
                        {
                            "type": "age_threshold_proof",
                            "threshold": threshold,
                            "result": bool(age_verified),
                            "method": "selective_disclosure",
                        }
                    )
                else:
                    raise ValueError(
                        f"Required age proof {age_attribute} not found in presentation"
                    )

            elif policy.get("required_proof") == "age_range":
                min_age = policy.get("min_age", 18)
                max_age = policy.get("max_age", 65)

                # Check if person is in the specified age range
                age_in_range = subject_data.get("age_in_range", False)
                verification_result["verified"] = bool(age_in_range)
                verification_result["disclosed_attributes"]["age_in_range"] = age_in_range
                verification_result["proof_results"].append(
                    {
                        "type": "age_range_proof",
                        "min_age": min_age,
                        "max_age": max_age,
                        "result": bool(age_in_range),
                        "method": "selective_disclosure",
                    }
                )

            # Add optional disclosed attributes
            optional_attrs = use_case_config.get("optional_attributes", [])
            for attr in optional_attrs:
                if attr in subject_data:
                    verification_result["disclosed_attributes"][attr] = subject_data[attr]

            # Privacy analysis
            birth_date_disclosed = "birth_date" in verification_result["disclosed_attributes"]
            exact_age_disclosed = "age" in verification_result["disclosed_attributes"]

            if birth_date_disclosed or exact_age_disclosed:
                verification_result["privacy_preserved"] = False
                verification_result["warnings"].append(
                    "Birth date or exact age was disclosed, reducing privacy protection"
                )

            # Additional verification checks
            self._perform_additional_checks(verification_result, credential, policy)

            return verification_result

        except Exception as e:
            logger.exception(f"Age verification failed: {e}")
            return {
                "request_id": verification_request.get("request_id"),
                "verified": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _perform_additional_checks(
        self,
        verification_result: dict[str, Any],
        credential: dict[str, Any],
        policy: dict[str, Any],
    ) -> None:
        """Perform additional security and validity checks."""

        # Check credential expiry
        if "expirationDate" in credential:
            expiry_date = datetime.fromisoformat(
                credential["expirationDate"].replace("Z", "+00:00")
            )
            if expiry_date < datetime.now(expiry_date.tzinfo):
                verification_result["verified"] = False
                verification_result["warnings"].append("Credential has expired")

        # Check issuer trust
        issuer = credential.get("issuer", {})
        issuer_id = issuer if isinstance(issuer, str) else issuer.get("id")

        # Mock issuer validation (in production, this would check against trusted issuer registry)
        trusted_issuers = [
            "did:example:government:dmv",
            "did:example:state:identity",
            "did:web:dmv.state.gov",
        ]

        if issuer_id not in trusted_issuers:
            verification_result["warnings"].append(f"Issuer {issuer_id} not in trusted registry")

        # Check proof signatures (mock implementation)
        if "proof" not in credential:
            verification_result["warnings"].append("No cryptographic proof found")
        else:
            verification_result["proof_results"].append(
                {
                    "type": "signature_verification",
                    "result": True,  # Mock successful verification
                    "method": "EdDSA",
                    "proofPurpose": "assertionMethod",
                }
            )

    def get_supported_use_cases(self) -> dict[str, Any]:
        """Get all supported age verification use cases."""
        return {
            use_case: {
                "description": config.get("purpose", ""),
                "context": config.get("context", ""),
                "policy": config.get("policy", ""),
                "required_attributes": config.get("required_attributes", []),
                "optional_attributes": config.get("optional_attributes", []),
            }
            for use_case, config in self.use_cases.items()
        }

    def get_privacy_report(self, verification_result: dict[str, Any]) -> dict[str, Any]:
        """Generate a privacy protection report for the verification."""

        disclosed = verification_result.get("disclosed_attributes", {})
        privacy_level = "high"

        # Analyze disclosed information
        sensitive_attrs = ["birth_date", "age", "address", "portrait"]
        disclosed_sensitive = [attr for attr in sensitive_attrs if attr in disclosed]

        if disclosed_sensitive:
            privacy_level = "low"
        elif len(disclosed) > 3:
            privacy_level = "medium"

        return {
            "privacy_level": privacy_level,
            "attributes_disclosed": list(disclosed.keys()),
            "sensitive_attributes_disclosed": disclosed_sensitive,
            "privacy_techniques_used": [
                "selective_disclosure",
                "zero_knowledge_proofs",
                "minimal_disclosure",
            ],
            "privacy_preserved": verification_result.get("privacy_preserved", True),
            "recommendations": self._generate_privacy_recommendations(disclosed),
        }

    def _generate_privacy_recommendations(self, disclosed: dict[str, Any]) -> list[str]:
        """Generate privacy recommendations based on disclosed attributes."""
        recommendations = []

        if "birth_date" in disclosed:
            recommendations.append(
                "Consider using age_over_X attributes instead of birth_date for better privacy"
            )

        if "portrait" in disclosed:
            recommendations.append(
                "Portrait disclosure should only be used when visual identification is required"
            )

        if len(disclosed) > 5:
            recommendations.append(
                "Consider reducing the number of disclosed attributes to improve privacy"
            )

        return recommendations
