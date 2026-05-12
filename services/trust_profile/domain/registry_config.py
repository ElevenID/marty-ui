"""
Trust Registry Configuration

Defines known trust registries (ICAO PKD, EU Trust Lists, AAMVA) and their metadata.
This configuration drives the registry import feature.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


class RegistryType(str, Enum):
    ICAO_PKD = "ICAO_PKD"
    EU_TRUST_LIST = "EU_TRUST_LIST"
    AAMVA = "AAMVA"


class TrustFramework(str, Enum):
    ICAO = "ICAO"
    EUDI = "EUDI"
    AAMVA = "AAMVA"
    CUSTOM = "CUSTOM"


class CredentialFormat(str, Enum):
    MDOC = "MDOC"
    SD_JWT_VC = "SD_JWT_VC"
    VC_JWT = "VC_JWT"
    JSON_LD = "JSON_LD"


@dataclass
class RegistryConfig:
    """Configuration for a single trust registry source."""
    registry_type: RegistryType
    registry_name: str
    registry_url: str
    supported_frameworks: List[TrustFramework]
    supported_formats: List[CredentialFormat]
    sync_interval_hours: int = 24
    description: str = ""
    issuer_type_filter: Optional[str] = None  # e.g., "DOCUMENT_SIGNER", "ROOT_CA"


# Known trust registries
KNOWN_REGISTRIES: Dict[RegistryType, RegistryConfig] = {
    RegistryType.ICAO_PKD: RegistryConfig(
        registry_type=RegistryType.ICAO_PKD,
        registry_name="ICAO Public Key Directory",
        registry_url="https://pkd.icao.int",
        supported_frameworks=[TrustFramework.ICAO],
        supported_formats=[CredentialFormat.MDOC],
        sync_interval_hours=24,
        description="International Civil Aviation Organization Public Key Directory for ePassports and travel documents",
        issuer_type_filter="DOCUMENT_SIGNER"
    ),
    RegistryType.EU_TRUST_LIST: RegistryConfig(
        registry_type=RegistryType.EU_TRUST_LIST,
        registry_name="EU List of Trusted Lists (LoTL)",
        registry_url="https://ec.europa.eu/digital-building-blocks/web-redirect/en/eu-trusted-lists-xml",
        supported_frameworks=[TrustFramework.EUDI],
        supported_formats=[CredentialFormat.SD_JWT_VC, CredentialFormat.VC_JWT],
        sync_interval_hours=24,
        description="European Union's centralized Trust List containing trusted certificate and credential issuers",
        issuer_type_filter="CREDENTIAL_ISSUER"
    ),
    RegistryType.AAMVA: RegistryConfig(
        registry_type=RegistryType.AAMVA,
        registry_name="American Association of Motor Vehicle Administrators",
        registry_url="https://www.aamva.org/standards",
        supported_frameworks=[TrustFramework.AAMVA],
        supported_formats=[CredentialFormat.MDOC, CredentialFormat.SD_JWT_VC],
        sync_interval_hours=24,
        description="AAMVA database of trusted issuers for mobile driver licenses and travel documents",
        issuer_type_filter="MDOC_ISSUER"
    ),
}


def get_registries_for_framework(framework: TrustFramework) -> List[RegistryConfig]:
    """Get all registries supported by a trust framework."""
    return [
        config for config in KNOWN_REGISTRIES.values()
        if framework in config.supported_frameworks
    ]


def get_supported_formats_for_registry(registry_type: RegistryType) -> List[CredentialFormat]:
    """Get supported credential formats for a registry."""
    config = KNOWN_REGISTRIES.get(registry_type)
    return config.supported_formats if config else []


def get_registry_config(registry_type: RegistryType) -> Optional[RegistryConfig]:
    """Get configuration for a specific registry."""
    return KNOWN_REGISTRIES.get(registry_type)
