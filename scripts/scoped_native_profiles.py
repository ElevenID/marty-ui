"""Closed, reviewed build scopes; callers cannot supply arbitrary Cargo targets."""
from dataclasses import dataclass


@dataclass(frozen=True)
class BuildProfile:
    name: str
    ui_revision: str
    roles: tuple[tuple[str, str], ...]
    packages: tuple[str, ...]
    container_prefix: str
    owner: str
    core_revision: str = "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"
    volumes: tuple[str, str] = ("ui-canvas-cargo", "d05-rust-target-20261026")
    cargo_profile: str = "dev"


SIGNING_CAS = BuildProfile(
    "d02-signing-cas",
    "3b862bebdd2cc0707d9a38f6df55db198b6be417",
    (("signing-keys", "marty-signing-keys"), ("gateway", "marty-gateway")),
    ("marty-signing-keys", "marty-gateway"),
    "marty-d02-signing-cas-",
    "d02-signing-cas-native",
)

SIGNING_CAS_NO_TRANSFORM = BuildProfile(
    "d02-signing-cas-no-transform",
    "9b1efd21163dadeff7cf1ced5fe47c5e046d2121",
    (("signing-keys", "marty-signing-keys"),),
    ("marty-signing-keys",),
    "marty-d02-signing-cas-header-",
    "d02-signing-cas-header-native",
)

CURRENT_ISSUER_READY = BuildProfile(
    "current-issuer-ready-two-role",
    "5d22484685fc6c8723e419e656252385c0db3654",
    (("signing-keys", "marty-signing-keys"), ("gateway", "marty-gateway")),
    ("marty-signing-keys", "marty-gateway"),
    "marty-current-issuer-ready-",
    "current-issuer-ready-native",
)

CURRENT_ISSUER_POLICY_SIGNING = BuildProfile(
    "current-issuer-policy-signing-only",
    "4c99781ca5807494826e0ee0f8d63ee0fc5ad91d",
    (("signing-keys", "marty-signing-keys"),),
    ("marty-signing-keys",),
    "marty-current-issuer-policy-signing-",
    "current-issuer-ready-native",
)

CURRENT_ISSUER_POLICY_SIGNING_COMPACT = BuildProfile(
    "current-issuer-policy-signing-compact",
    "4c99781ca5807494826e0ee0f8d63ee0fc5ad91d",
    (("signing-keys", "marty-signing-keys"),),
    ("marty-signing-keys",),
    "marty-current-issuer-policy-signing-compact-",
    "current-issuer-ready-native",
)

D12_PASSPORT_CURRENT = BuildProfile(
    "d12-passport-current-three-role",
    "449ab93ca80d147622ae61283f7d8084f7c62884",
    (("flow", "marty-flow"), ("gateway", "marty-gateway"),
     ("issuance-native", "marty-issuance-service")),
    ("marty-flow", "marty-gateway", "marty-issuance-service"),
    "marty-d12-current-main-",
    "d12-passport-current-native",
    "11655e38c2dbf69bfa5bc3c873f80c5fad628723",
    volumes=("ui-canvas-cargo", "marty-d12-current-main-native-target"),
)


ISSUANCE_OFFER_FORMAT = BuildProfile(
    "d05-issuance-offer-format-only",
    "e836a700579a1dc0be4894c6bf416c26529d2564",
    (("issuance-native", "marty-issuance-service"),),
    ("marty-issuance-service",),
    "marty-d05-issuance-offer-format-",
    "current-issuer-ready-native",
)

D05_MEMBERSHIP_CURRENT = BuildProfile(
    "d05-membership-verified-native-six-role",
    "d15139805564c7211d574d45659d972e08af0378",
    (("presentation-policy", "marty-presentation-policy"),
     ("credential-template", "marty-credential-template"),
     ("trust-profile", "marty-trust-profile"),
     ("compliance-profile", "marty-compliance-profile"),
     ("signing-keys", "marty-signing-keys"), ("gateway", "marty-gateway")),
    ("marty-presentation-policy", "marty-credential-template", "marty-trust-profile",
     "marty-compliance-profile", "marty-signing-keys", "marty-gateway"),
    "marty-d05-membership-",
    "d05-membership-native",
    "ab91a6fd97b2483965e8cb966c3b2e3ddeedf1ca",
    volumes=("ui-canvas-cargo", "marty-d12-current-main-native-target"),
)


# Current D05 includes the owner-policy read endpoint and durable login callback
# chain. Keep the historical six-role product/recipe available unchanged.
D05_MEMBERSHIP_LATEST = BuildProfile(
    "d05-membership-current-native-ten-role",
    "47e42c7f61e150e1ece953e02b4041324b6bdea4",
    D05_MEMBERSHIP_CURRENT.roles + (("auth", "marty-auth"), ("flow", "marty-flow"),
                                  ("issuance-native", "marty-issuance-service"),
                                  ("organization", "marty-organization")),
    D05_MEMBERSHIP_CURRENT.packages + ("marty-auth", "marty-flow", "marty-issuance-service",
                                     "marty-organization"),
    "marty-d05-current-membership-",
    "d05-current-membership-native",
    D05_MEMBERSHIP_CURRENT.core_revision,
    volumes=D05_MEMBERSHIP_CURRENT.volumes,
)


# TODO (platform build owner): a new all-service profile must use current
# provider-neutral source and a fresh closed manifest. Do not revive old IDs.
RETIRED_BUILD_PROFILES = frozenset({"oid4vc-all-services", "oid4vc-latest-maintenance-all-services"})


def legacy_profile_reference(name):
    """Read historical receipt metadata; this never registers a build profile."""
    import hashlib
    import json
    from pathlib import Path
    if name not in RETIRED_BUILD_PROFILES:
        raise ValueError("UNKNOWN_LEGACY_BUILD_REFERENCE")
    path = Path(__file__).resolve().parents[1] / "contracts/scoped-full-build-legacy-reference.json"
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != "c181b530debdf5714c3bf909f6f2227cf1d85bf68235412886d70cb8433d5063":
        raise ValueError("LEGACY_BUILD_REFERENCE_CHANGED")
    values = json.loads(raw)["profiles"][name]
    values["roles"] = tuple(tuple(row) for row in values["roles"])
    values["packages"] = tuple(values["packages"])
    values["volumes"] = tuple(values["volumes"])
    return BuildProfile(**values)


def reviewed_profile(name):
    if name in RETIRED_BUILD_PROFILES:
        raise ValueError("RETIRED_BUILD_PROFILE_USE_CURRENT_PLATFORM_BUILD")
    for profile in (SIGNING_CAS, SIGNING_CAS_NO_TRANSFORM, CURRENT_ISSUER_READY, CURRENT_ISSUER_POLICY_SIGNING, CURRENT_ISSUER_POLICY_SIGNING_COMPACT, D12_PASSPORT_CURRENT, ISSUANCE_OFFER_FORMAT, D05_MEMBERSHIP_CURRENT, D05_MEMBERSHIP_LATEST):
        if name == profile.name:
            return profile
    raise ValueError("UNKNOWN_REVIEWED_BUILD_PROFILE")


D12_CURRENT_ROLLOUT = "d12-passport-current-functional"
D05_CURRENT_ROLLOUT = "d05-membership-current-functional"

def current_rollout_build(profile):
    """Only these complete source-bound cohorts may use the current observer/overlay."""
    if profile == D12_CURRENT_ROLLOUT:
        return D12_PASSPORT_CURRENT
    if profile == D05_CURRENT_ROLLOUT:
        return D05_MEMBERSHIP_LATEST
    raise ValueError("UNREVIEWED_CURRENT_ROLLOUT_PROFILE")
