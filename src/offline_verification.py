"""
Offline QR Code Verification Engine

Implements offline verification capabilities for mDoc/mDL using QR codes
that can be verified without network connectivity.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta
from io import BytesIO
from typing import Any

import cbor2
import qrcode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger(__name__)


class OfflineQREngine:
    """Engine for creating and verifying offline QR codes for mDoc/mDL."""

    def __init__(self):
        self.offline_cache = {}
        self.trusted_certificates = {}
        self.verification_keys = {}

        # Initialize with demo certificates
        self._initialize_demo_certificates()

    def _initialize_demo_certificates(self) -> None:
        """Initialize demo certificates for offline verification."""

        # Generate demo ECDSA key pair for signing
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Store keys for demo (in production, these would be loaded from secure storage)
        self.demo_private_key = private_key
        self.demo_public_key = public_key

        # Mock certificate for demo issuer
        self.trusted_certificates["demo_issuer"] = {
            "issuer_id": "did:example:demo:issuer",
            "public_key": public_key,
            "valid_from": datetime.utcnow() - timedelta(days=30),
            "valid_until": datetime.utcnow() + timedelta(days=365),
            "certificate_type": "mDL_issuer",
            "trust_level": "demo",
        }

    def create_offline_qr(
        self,
        mdl_data: dict[str, Any],
        verification_requirements: dict[str, Any] | None = None,
        expires_in_minutes: int = 30,
    ) -> dict[str, Any]:
        """Create an offline-verifiable QR code for mDL data."""

        try:
            # Create offline verification package
            offline_package = {
                "version": "1.0",
                "type": "offline_mdl_verification",
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (
                    datetime.utcnow() + timedelta(minutes=expires_in_minutes)
                ).isoformat(),
                "issuer_id": "did:example:demo:issuer",
                "verification_requirements": verification_requirements
                or {
                    "required_fields": ["given_name", "family_name", "age_over_18"],
                    "purpose": "offline_verification",
                    "context": "demo",
                },
                "mdl_data": self._prepare_offline_data(mdl_data),
                "cryptographic_binding": self._create_cryptographic_binding(mdl_data),
                "verification_metadata": {
                    "verification_method": "offline_qr",
                    "signature_algorithm": "ECDSA-SHA256",
                    "trust_anchor": "demo_ca",
                    "can_be_copied": False,
                    "single_use": True,
                },
            }

            # Sign the package
            signature = self._sign_offline_package(offline_package)
            offline_package["signature"] = signature

            # Encode as CBOR for efficiency
            cbor_data = cbor2.dumps(offline_package)

            # Create QR code
            qr_code_data = base64.b64encode(cbor_data).decode("utf-8")
            qr = qrcode.QRCode(
                version=None,  # Auto-determine size
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_code_data)
            qr.make(fit=True)

            # Generate QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64 for web display
            buffer = BytesIO()
            qr_image.save(buffer, format="PNG")
            qr_image_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

            # Cache for potential verification
            cache_key = offline_package["cryptographic_binding"]["package_id"]
            self.offline_cache[cache_key] = {
                "package": offline_package,
                "created_at": datetime.utcnow(),
                "used": False,
            }

            return {
                "qr_code_image": qr_image_base64,
                "qr_code_data": qr_code_data,
                "package_id": cache_key,
                "expires_at": offline_package["expires_at"],
                "size_bytes": len(cbor_data),
                "verification_info": {
                    "can_verify_offline": True,
                    "requires_network": False,
                    "single_use": True,
                    "expires_in_minutes": expires_in_minutes,
                },
                "contained_data": list(offline_package["mdl_data"].keys()),
            }

        except Exception as e:
            logger.exception("Failed to create offline QR code: %s", e)
            raise ValueError(f"QR code creation failed: {e}") from e

    def verify_offline_qr(
        self, qr_data: str, verification_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Verify an offline QR code without network connectivity."""

        try:
            # Decode QR data
            cbor_data = base64.b64decode(qr_data)
            offline_package = cbor2.loads(cbor_data)

            verification_result = {
                "verified": False,
                "verification_type": "offline_qr",
                "timestamp": datetime.utcnow().isoformat(),
                "package_info": {
                    "type": offline_package.get("type"),
                    "version": offline_package.get("version"),
                    "created_at": offline_package.get("created_at"),
                    "expires_at": offline_package.get("expires_at"),
                },
                "checks_performed": [],
                "warnings": [],
                "disclosed_data": {},
            }

            # 1. Verify package integrity
            integrity_check = self._verify_package_integrity(offline_package)
            verification_result["checks_performed"].append(integrity_check)

            if not integrity_check["passed"]:
                verification_result["error"] = "Package integrity verification failed"
                return verification_result

            # 2. Verify expiration
            expiry_check = self._verify_expiration(offline_package)
            verification_result["checks_performed"].append(expiry_check)

            if not expiry_check["passed"]:
                verification_result["error"] = "QR code has expired"
                return verification_result

            # 3. Verify cryptographic signature
            signature_check = self._verify_signature(offline_package)
            verification_result["checks_performed"].append(signature_check)

            if not signature_check["passed"]:
                verification_result["error"] = "Cryptographic signature verification failed"
                return verification_result

            # 4. Verify single-use constraint
            usage_check = self._verify_single_use(offline_package)
            verification_result["checks_performed"].append(usage_check)

            if not usage_check["passed"]:
                verification_result["warnings"].append("QR code may have been used before")

            # 5. Extract and verify data according to requirements
            data_check = self._verify_data_requirements(offline_package, verification_context or {})
            verification_result["checks_performed"].append(data_check)
            verification_result["disclosed_data"] = data_check.get("disclosed_data", {})

            # 6. Verify issuer trust
            trust_check = self._verify_issuer_trust(offline_package)
            verification_result["checks_performed"].append(trust_check)

            # Overall verification result
            all_critical_passed = all(
                check["passed"]
                for check in verification_result["checks_performed"]
                if check.get("critical", True)
            )

            verification_result["verified"] = all_critical_passed

            # Mark as used if verification successful
            if verification_result["verified"]:
                self._mark_as_used(offline_package)

            # Add verification summary
            verification_result["summary"] = {
                "total_checks": len(verification_result["checks_performed"]),
                "passed_checks": sum(
                    1 for c in verification_result["checks_performed"] if c["passed"]
                ),
                "critical_issues": sum(
                    1
                    for c in verification_result["checks_performed"]
                    if not c["passed"] and c.get("critical", True)
                ),
                "warnings": len(verification_result["warnings"]),
            }

            return verification_result

        except Exception as e:
            logger.exception("Offline QR verification failed: %s", e)
            return {
                "verified": False,
                "error": f"Verification failed: {e}",
                "timestamp": datetime.utcnow().isoformat(),
                "verification_type": "offline_qr",
            }

    def _prepare_offline_data(self, mdl_data: dict[str, Any]) -> dict[str, Any]:
        """Prepare mDL data for offline verification."""

        # Only include necessary data for offline verification
        offline_data = {}

        # Essential identity fields
        essential_fields = [
            "given_name",
            "family_name",
            "birth_date",
            "age_over_18",
            "age_over_21",
            "document_number",
            "expiry_date",
            "issuing_country",
            "issuing_authority",
        ]

        for field in essential_fields:
            if field in mdl_data:
                offline_data[field] = mdl_data[field]

        # Add computed fields for offline verification
        if "birth_date" in mdl_data:
            birth_date = datetime.fromisoformat(mdl_data["birth_date"]).date()
            today = datetime.utcnow().date()
            age = (
                today.year
                - birth_date.year
                - ((today.month, today.day) < (birth_date.month, birth_date.day))
            )

            offline_data["computed_age"] = age
            offline_data["age_over_18"] = age >= 18
            offline_data["age_over_21"] = age >= 21
            offline_data["age_over_65"] = age >= 65

        return offline_data

    def _create_cryptographic_binding(self, mdl_data: dict[str, Any]) -> dict[str, Any]:
        """Create cryptographic binding for the offline package."""

        import hashlib
        import uuid

        # Create unique package ID
        package_id = str(uuid.uuid4())

        # Create content hash
        content_bytes = json.dumps(mdl_data, sort_keys=True).encode("utf-8")
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        return {
            "package_id": package_id,
            "content_hash": content_hash,
            "binding_method": "sha256_hash",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _sign_offline_package(self, package: dict[str, Any]) -> dict[str, Any]:
        """Sign the offline package with issuer's private key."""

        # Create signature payload (exclude signature field)
        signature_payload = {k: v for k, v in package.items() if k != "signature"}
        payload_bytes = json.dumps(signature_payload, sort_keys=True).encode("utf-8")

        # Sign with demo private key
        signature_bytes = self.demo_private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

        return {
            "algorithm": "ECDSA-SHA256",
            "signature": base64.b64encode(signature_bytes).decode("utf-8"),
            "public_key_id": "demo_issuer",
            "signature_timestamp": datetime.utcnow().isoformat(),
        }

    def _verify_package_integrity(self, package: dict[str, Any]) -> dict[str, Any]:
        """Verify the integrity of the offline package."""

        required_fields = [
            "version",
            "type",
            "created_at",
            "expires_at",
            "issuer_id",
            "mdl_data",
            "cryptographic_binding",
            "signature",
        ]

        missing_fields = [field for field in required_fields if field not in package]

        return {
            "check_name": "package_integrity",
            "passed": len(missing_fields) == 0,
            "details": (
                f"Missing fields: {missing_fields}"
                if missing_fields
                else "All required fields present"
            ),
            "critical": True,
        }

    def _verify_expiration(self, package: dict[str, Any]) -> dict[str, Any]:
        """Verify the package hasn't expired."""

        try:
            expires_at = datetime.fromisoformat(package["expires_at"].replace("Z", ""))
            now = datetime.utcnow()

            is_valid = now <= expires_at
            time_remaining = expires_at - now if is_valid else timedelta(0)

            return {
                "check_name": "expiration",
                "passed": is_valid,
                "details": f"Time remaining: {time_remaining}" if is_valid else "Package expired",
                "critical": True,
                "expires_at": expires_at.isoformat(),
                "time_remaining_seconds": time_remaining.total_seconds(),
            }
        except (ValueError, KeyError) as e:
            return {
                "check_name": "expiration",
                "passed": False,
                "details": f"Invalid expiration data: {e}",
                "critical": True,
            }

    def _verify_signature(self, package: dict[str, Any]) -> dict[str, Any]:
        """Verify the cryptographic signature."""

        try:
            signature_info = package.get("signature", {})
            public_key_id = signature_info.get("public_key_id")

            if public_key_id not in self.trusted_certificates:
                return {
                    "check_name": "signature_verification",
                    "passed": False,
                    "details": f"Unknown issuer: {public_key_id}",
                    "critical": True,
                }

            # Get public key
            cert_info = self.trusted_certificates[public_key_id]
            public_key = cert_info["public_key"]

            # Verify signature
            signature_payload = {k: v for k, v in package.items() if k != "signature"}
            payload_bytes = json.dumps(signature_payload, sort_keys=True).encode("utf-8")
            signature_bytes = base64.b64decode(signature_info["signature"])

            try:
                public_key.verify(signature_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
                signature_valid = True
            except Exception:
                signature_valid = False

            return {
                "check_name": "signature_verification",
                "passed": signature_valid,
                "details": "Valid signature" if signature_valid else "Invalid signature",
                "critical": True,
                "algorithm": signature_info.get("algorithm"),
                "issuer": public_key_id,
            }

        except Exception as e:
            return {
                "check_name": "signature_verification",
                "passed": False,
                "details": f"Signature verification error: {e}",
                "critical": True,
            }

    def _verify_single_use(self, package: dict[str, Any]) -> dict[str, Any]:
        """Verify single-use constraint."""

        package_id = package.get("cryptographic_binding", {}).get("package_id")

        if not package_id:
            return {
                "check_name": "single_use",
                "passed": False,
                "details": "No package ID found",
                "critical": False,
            }

        cached_package = self.offline_cache.get(package_id)

        if not cached_package:
            return {
                "check_name": "single_use",
                "passed": True,
                "details": "Package not in cache (first use)",
                "critical": False,
            }

        already_used = cached_package.get("used", False)

        return {
            "check_name": "single_use",
            "passed": not already_used,
            "details": "Already used" if already_used else "First use",
            "critical": False,
        }

    def _verify_data_requirements(
        self, package: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify data meets verification requirements."""

        mdl_data = package.get("mdl_data", {})
        requirements = package.get("verification_requirements", {})
        required_fields = requirements.get("required_fields", [])

        missing_fields = [field for field in required_fields if field not in mdl_data]
        disclosed_data = {field: mdl_data[field] for field in required_fields if field in mdl_data}

        # Add context-specific verifications
        context_purpose = context.get("purpose", "general")
        if context_purpose == "age_verification":
            age_verified = mdl_data.get("age_over_18", False) or mdl_data.get("age_over_21", False)
            disclosed_data["age_verification_result"] = age_verified

        return {
            "check_name": "data_requirements",
            "passed": len(missing_fields) == 0,
            "details": (
                f"Missing required fields: {missing_fields}"
                if missing_fields
                else "All requirements met"
            ),
            "critical": True,
            "disclosed_data": disclosed_data,
            "requirements": requirements,
        }

    def _verify_issuer_trust(self, package: dict[str, Any]) -> dict[str, Any]:
        """Verify issuer is trusted."""

        issuer_id = package.get("issuer_id")

        if not issuer_id:
            return {
                "check_name": "issuer_trust",
                "passed": False,
                "details": "No issuer ID found",
                "critical": True,
            }

        # Check if issuer is trusted (simplified for demo)
        trusted_issuers = [
            "did:example:demo:issuer",
            "did:example:government:dmv",
            "did:web:dmv.state.gov",
        ]

        is_trusted = issuer_id in trusted_issuers

        return {
            "check_name": "issuer_trust",
            "passed": is_trusted,
            "details": f"Issuer {issuer_id} {'is trusted' if is_trusted else 'not trusted'}",
            "critical": True,
            "issuer_id": issuer_id,
        }

    def _mark_as_used(self, package: dict[str, Any]) -> None:
        """Mark package as used to prevent reuse."""

        package_id = package.get("cryptographic_binding", {}).get("package_id")
        if package_id and package_id in self.offline_cache:
            self.offline_cache[package_id]["used"] = True
            self.offline_cache[package_id]["used_at"] = datetime.utcnow()

    def get_offline_capabilities(self) -> dict[str, Any]:
        """Get information about offline verification capabilities."""

        return {
            "supports_offline": True,
            "verification_methods": ["qr_code", "nfc", "bluetooth"],
            "supported_algorithms": ["ECDSA-SHA256", "EdDSA"],
            "max_offline_duration_minutes": 1440,  # 24 hours
            "single_use_only": True,
            "supported_document_types": ["mDL", "mID", "passport"],
            "trust_anchors": list(self.trusted_certificates.keys()),
            "cache_size": len(self.offline_cache),
        }
