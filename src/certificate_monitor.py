"""
Certificate Lifecycle Integration for mDL Demo

Integrates Marty's certificate lifecycle monitor to show mDL DSC
(Document Signer Certificate) expiry tracking and management.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


class MDLCertificateMonitor:
    """Monitor mDL Document Signer Certificates and their lifecycle."""

    def __init__(self):
        self.dsc_certificates = {}
        self.expiry_alerts = {}
        self.certificate_chains = {}

        # Initialize with demo DSC certificates
        self._initialize_demo_certificates()

    def _initialize_demo_certificates(self) -> None:
        """Initialize demo DSC certificates for monitoring."""

        now = datetime.utcnow()

        # Demo DSC certificates with different expiry scenarios
        self.dsc_certificates = {
            "DSC-001-ACTIVE": {
                "certificate_id": "DSC-001-ACTIVE",
                "common_name": "Demo mDL Document Signer",
                "issuer": "Demo Country CSCA",
                "subject": "CN=Demo mDL DSC,O=Demo DMV,C=Demo",
                "serial_number": "12345678901234567890",
                "not_before": now - timedelta(days=90),
                "not_after": now + timedelta(days=275),  # ~9 months remaining
                "signature_algorithm": "ecdsa-with-SHA256",
                "key_usage": ["digital_signature", "key_cert_sign"],
                "extended_key_usage": ["mDL_document_signing"],
                "status": "active",
                "certificate_type": "document_signer",
                "document_types": ["org.iso.18013.5.1.mDL"],
                "issuing_authority": "Demo DMV",
                "country_code": "XX",
                "trust_level": "high",
            },
            "DSC-002-EXPIRING": {
                "certificate_id": "DSC-002-EXPIRING",
                "common_name": "Demo mDL Document Signer - Legacy",
                "issuer": "Demo Country CSCA",
                "subject": "CN=Demo mDL DSC Legacy,O=Demo DMV,C=Demo",
                "serial_number": "12345678901234567891",
                "not_before": now - timedelta(days=365),
                "not_after": now + timedelta(days=15),  # Expiring soon
                "signature_algorithm": "ecdsa-with-SHA256",
                "key_usage": ["digital_signature", "key_cert_sign"],
                "extended_key_usage": ["mDL_document_signing"],
                "status": "expiring_soon",
                "certificate_type": "document_signer",
                "document_types": ["org.iso.18013.5.1.mDL"],
                "issuing_authority": "Demo DMV",
                "country_code": "XX",
                "trust_level": "high",
            },
            "DSC-003-CRITICAL": {
                "certificate_id": "DSC-003-CRITICAL",
                "common_name": "Demo mDL Document Signer - Critical",
                "issuer": "Demo Country CSCA",
                "subject": "CN=Demo mDL DSC Critical,O=Demo DMV,C=Demo",
                "serial_number": "12345678901234567892",
                "not_before": now - timedelta(days=730),
                "not_after": now + timedelta(days=3),  # Critical - expires in 3 days
                "signature_algorithm": "ecdsa-with-SHA256",
                "key_usage": ["digital_signature", "key_cert_sign"],
                "extended_key_usage": ["mDL_document_signing"],
                "status": "critical",
                "certificate_type": "document_signer",
                "document_types": ["org.iso.18013.5.1.mDL"],
                "issuing_authority": "Demo DMV",
                "country_code": "XX",
                "trust_level": "high",
            },
            "DSC-004-EXPIRED": {
                "certificate_id": "DSC-004-EXPIRED",
                "common_name": "Demo mDL Document Signer - Expired",
                "issuer": "Demo Country CSCA",
                "subject": "CN=Demo mDL DSC Expired,O=Demo DMV,C=Demo",
                "serial_number": "12345678901234567893",
                "not_before": now - timedelta(days=1095),
                "not_after": now - timedelta(days=5),  # Already expired
                "signature_algorithm": "ecdsa-with-SHA256",
                "key_usage": ["digital_signature", "key_cert_sign"],
                "extended_key_usage": ["mDL_document_signing"],
                "status": "expired",
                "certificate_type": "document_signer",
                "document_types": ["org.iso.18013.5.1.mDL"],
                "issuing_authority": "Demo DMV",
                "country_code": "XX",
                "trust_level": "revoked",
            },
        }

        # Initialize certificate chains
        self._initialize_certificate_chains()

        # Generate initial alerts
        self._generate_expiry_alerts()

    def _initialize_certificate_chains(self) -> None:
        """Initialize certificate chains for validation."""

        now = datetime.utcnow()

        # Root CA (Country Signing CA)
        root_ca = {
            "certificate_id": "CSCA-ROOT-001",
            "common_name": "Demo Country CSCA Root",
            "issuer": "Demo Country CSCA Root",  # Self-signed
            "subject": "CN=Demo Country CSCA Root,O=Demo Government,C=XX",
            "not_before": now - timedelta(days=1825),  # 5 years ago
            "not_after": now + timedelta(days=1825),  # 5 years from now
            "certificate_type": "root_ca",
            "key_usage": ["key_cert_sign", "crl_sign"],
            "basic_constraints": {"ca": True, "path_len": 2},
            "status": "active",
        }

        # Intermediate CA (Document Signer CA)
        intermediate_ca = {
            "certificate_id": "DSCA-INT-001",
            "common_name": "Demo mDL Document Signer CA",
            "issuer": "Demo Country CSCA Root",
            "subject": "CN=Demo mDL Document Signer CA,O=Demo DMV,C=XX",
            "not_before": now - timedelta(days=730),
            "not_after": now + timedelta(days=365),
            "certificate_type": "intermediate_ca",
            "key_usage": ["key_cert_sign", "crl_sign"],
            "basic_constraints": {"ca": True, "path_len": 0},
            "status": "active",
        }

        # Store certificate chains
        for cert_id in self.dsc_certificates:
            self.certificate_chains[cert_id] = {
                "end_entity": self.dsc_certificates[cert_id],
                "intermediate_ca": intermediate_ca,
                "root_ca": root_ca,
                "chain_valid": True,
                "validation_path": ["CSCA-ROOT-001", "DSCA-INT-001", cert_id],
            }

    def _generate_expiry_alerts(self) -> None:
        """Generate expiry alerts based on certificate status."""

        for cert_id, cert in self.dsc_certificates.items():
            days_until_expiry = (cert["not_after"] - datetime.utcnow()).days

            alert_level = "info"
            if days_until_expiry < 0:
                alert_level = "expired"
            elif days_until_expiry <= 7:
                alert_level = "critical"
            elif days_until_expiry <= 30:
                alert_level = "warning"
            elif days_until_expiry <= 90:
                alert_level = "notice"

            self.expiry_alerts[cert_id] = {
                "alert_id": f"ALERT-{cert_id}-{datetime.utcnow().strftime('%Y%m%d')}",
                "certificate_id": cert_id,
                "alert_level": alert_level,
                "days_until_expiry": days_until_expiry,
                "expiry_date": cert["not_after"].isoformat(),
                "message": self._generate_alert_message(cert, days_until_expiry, alert_level),
                "created_at": datetime.utcnow().isoformat(),
                "acknowledged": False,
                "renewal_recommended": days_until_expiry <= 90,
                "impact_assessment": self._assess_expiry_impact(cert),
            }

    def _generate_alert_message(
        self, cert: dict[str, Any], days_until_expiry: int, alert_level: str
    ) -> str:
        """Generate human-readable alert message."""

        cert_name = cert["common_name"]

        if alert_level == "expired":
            return f"Certificate '{cert_name}' has EXPIRED {abs(days_until_expiry)} days ago. Immediate action required."
        elif alert_level == "critical":
            return f"Certificate '{cert_name}' expires in {days_until_expiry} days. Critical renewal required."
        elif alert_level == "warning":
            return f"Certificate '{cert_name}' expires in {days_until_expiry} days. Renewal recommended."
        elif alert_level == "notice":
            return f"Certificate '{cert_name}' expires in {days_until_expiry} days. Plan renewal."
        else:
            return f"Certificate '{cert_name}' expires in {days_until_expiry} days."

    def _assess_expiry_impact(self, cert: dict[str, Any]) -> dict[str, Any]:
        """Assess the impact of certificate expiry."""

        return {
            "severity": "high" if cert["status"] in ["critical", "expired"] else "medium",
            "affected_services": ["mDL issuance", "document verification"],
            "business_impact": (
                "Service disruption"
                if cert["status"] == "expired"
                else "Potential service disruption"
            ),
            "recommended_actions": [
                "Generate new certificate request",
                "Coordinate with CSCA for signing",
                "Test new certificate in staging",
                "Schedule certificate rotation",
                "Update certificate in all systems",
            ],
            "estimated_downtime": (
                "0-2 hours" if cert["status"] != "expired" else "Until certificate renewal"
            ),
        }

    def get_certificate_status_overview(self) -> dict[str, Any]:
        """Get overview of all DSC certificate statuses."""

        status_counts = {}
        for cert in self.dsc_certificates.values():
            status = cert["status"]
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "total_certificates": len(self.dsc_certificates),
            "status_distribution": status_counts,
            "critical_alerts": len(
                [a for a in self.expiry_alerts.values() if a["alert_level"] == "critical"]
            ),
            "expired_certificates": len(
                [c for c in self.dsc_certificates.values() if c["status"] == "expired"]
            ),
            "certificates_needing_renewal": len(
                [
                    c
                    for c in self.dsc_certificates.values()
                    if c["status"] in ["critical", "expiring_soon"]
                ]
            ),
            "last_updated": datetime.utcnow().isoformat(),
        }

    def get_expiry_dashboard(self) -> dict[str, Any]:
        """Get certificate expiry dashboard data."""

        # Sort certificates by expiry date
        sorted_certs = sorted(self.dsc_certificates.values(), key=lambda x: x["not_after"])

        dashboard = {
            "overview": self.get_certificate_status_overview(),
            "certificates": [],
            "alerts": list(self.expiry_alerts.values()),
            "recommendations": self._generate_renewal_recommendations(),
            "upcoming_expirations": [],
        }

        # Add certificate details for dashboard
        for cert in sorted_certs:
            days_until_expiry = (cert["not_after"] - datetime.utcnow()).days
            cert_info = {
                "certificate_id": cert["certificate_id"],
                "common_name": cert["common_name"],
                "status": cert["status"],
                "days_until_expiry": days_until_expiry,
                "expiry_date": cert["not_after"].isoformat(),
                "issuing_authority": cert["issuing_authority"],
                "document_types": cert["document_types"],
                "renewal_priority": self._calculate_renewal_priority(cert),
            }
            dashboard["certificates"].append(cert_info)

            # Add to upcoming expirations if within 180 days
            if 0 <= days_until_expiry <= 180:
                dashboard["upcoming_expirations"].append(cert_info)

        return dashboard

    def _generate_renewal_recommendations(self) -> list[dict[str, Any]]:
        """Generate certificate renewal recommendations."""

        recommendations = []

        for cert_id, cert in self.dsc_certificates.items():
            days_until_expiry = (cert["not_after"] - datetime.utcnow()).days

            if cert["status"] in ["expired", "critical", "expiring_soon"]:
                priority = "high" if days_until_expiry <= 30 else "medium"

                recommendation = {
                    "certificate_id": cert_id,
                    "priority": priority,
                    "action": (
                        "immediate_renewal" if cert["status"] == "expired" else "schedule_renewal"
                    ),
                    "recommended_timeline": self._calculate_renewal_timeline(cert),
                    "steps": [
                        "Generate certificate signing request (CSR)",
                        "Submit CSR to CSCA for signing",
                        "Receive and validate new certificate",
                        "Deploy certificate to production systems",
                        "Verify mDL signing functionality",
                        "Revoke old certificate after transition",
                    ],
                    "estimated_effort": "4-8 hours",
                    "risk_if_delayed": self._assess_delay_risk(cert),
                }
                recommendations.append(recommendation)

        return sorted(recommendations, key=lambda x: x["priority"] == "high", reverse=True)

    def _calculate_renewal_priority(self, cert: dict[str, Any]) -> str:
        """Calculate renewal priority for certificate."""

        days_until_expiry = (cert["not_after"] - datetime.utcnow()).days

        if cert["status"] == "expired":
            return "emergency"
        elif days_until_expiry <= 7:
            return "critical"
        elif days_until_expiry <= 30:
            return "high"
        elif days_until_expiry <= 90:
            return "medium"
        else:
            return "low"

    def _calculate_renewal_timeline(self, cert: dict[str, Any]) -> str:
        """Calculate recommended renewal timeline."""

        if cert["status"] == "expired":
            return "immediate"
        elif cert["status"] == "critical":
            return "within 48 hours"
        elif cert["status"] == "expiring_soon":
            return "within 2 weeks"
        else:
            return "within 30 days"

    def _assess_delay_risk(self, cert: dict[str, Any]) -> str:
        """Assess risk of delaying certificate renewal."""

        if cert["status"] == "expired":
            return "Service outage - mDL issuance and verification will fail"
        elif cert["status"] == "critical":
            return "High risk of service disruption within days"
        elif cert["status"] == "expiring_soon":
            return "Moderate risk - may impact production systems"
        else:
            return "Low risk - sufficient time for planned renewal"

    def simulate_certificate_renewal(self, cert_id: str) -> dict[str, Any]:
        """Simulate certificate renewal process."""

        if cert_id not in self.dsc_certificates:
            raise ValueError(f"Certificate {cert_id} not found")

        old_cert = self.dsc_certificates[cert_id]

        # Simulate new certificate generation
        now = datetime.utcnow()
        new_cert_id = f"{cert_id}-RENEWED"

        new_cert = {
            "certificate_id": new_cert_id,
            "common_name": old_cert["common_name"] + " (Renewed)",
            "issuer": old_cert["issuer"],
            "subject": old_cert["subject"].replace(cert_id.split("-")[1], "RENEWED"),
            "serial_number": old_cert["serial_number"] + "1",  # Increment serial
            "not_before": now,
            "not_after": now + timedelta(days=1095),  # 3 years validity
            "signature_algorithm": old_cert["signature_algorithm"],
            "key_usage": old_cert["key_usage"],
            "extended_key_usage": old_cert["extended_key_usage"],
            "status": "active",
            "certificate_type": old_cert["certificate_type"],
            "document_types": old_cert["document_types"],
            "issuing_authority": old_cert["issuing_authority"],
            "country_code": old_cert["country_code"],
            "trust_level": "high",
        }

        # Update old certificate status
        self.dsc_certificates[cert_id]["status"] = "superseded"

        # Add new certificate
        self.dsc_certificates[new_cert_id] = new_cert

        # Update certificate chain
        old_chain = self.certificate_chains[cert_id].copy()
        old_chain["end_entity"] = new_cert
        old_chain["validation_path"][-1] = new_cert_id
        self.certificate_chains[new_cert_id] = old_chain

        # Clear old alerts and generate new ones
        if cert_id in self.expiry_alerts:
            del self.expiry_alerts[cert_id]

        self._generate_expiry_alerts()

        return {
            "renewal_successful": True,
            "old_certificate": cert_id,
            "new_certificate": new_cert_id,
            "transition_period": "30 days",
            "actions_completed": [
                "Generated new certificate",
                "Updated certificate chains",
                "Cleared expiry alerts",
                "Marked old certificate as superseded",
            ],
            "next_steps": [
                "Deploy new certificate to production",
                "Update mDL issuing services",
                "Verify functionality with test issuance",
                "Schedule old certificate revocation",
            ],
            "new_expiry_date": new_cert["not_after"].isoformat(),
        }

    def get_certificate_details(self, cert_id: str) -> dict[str, Any]:
        """Get detailed information about a specific certificate."""

        if cert_id not in self.dsc_certificates:
            raise ValueError(f"Certificate {cert_id} not found")

        cert = self.dsc_certificates[cert_id]
        chain = self.certificate_chains.get(cert_id, {})
        alert = self.expiry_alerts.get(cert_id, {})

        return {
            "certificate": cert,
            "certificate_chain": chain,
            "expiry_alert": alert,
            "usage_statistics": {
                "mdl_documents_signed": 1250,  # Mock data
                "last_used": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                "average_daily_usage": 45,
                "peak_usage_time": "14:00-16:00 UTC",
            },
            "security_status": {
                "key_strength": "256-bit ECDSA",
                "algorithm_status": "current",
                "revocation_status": "not_revoked",
                "trust_chain_valid": chain.get("chain_valid", False),
            },
        }
