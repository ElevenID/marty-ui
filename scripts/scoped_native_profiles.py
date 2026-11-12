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

CANVAS_SCOPED_JOBS = BuildProfile(
    "canvas-issuer-scoped-jobs",
    "fce109daf47a7712c1ff5779b0e33def57bbce20",
    (("issuance-native", "marty-issuance-service"),),
    ("marty-issuance-service",),
    "marty-canvas-scoped-jobs-",
    "canvas-scoped-jobs-native",
    "44040270000f93b7e7499cbec31b3bb3dd7e3df1",
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


OFFICIAL_ALL_SERVICES = BuildProfile(
    "oid4vc-all-services",
    "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f",
    tuple((name, name) for name in (
        "marty-applicant", "marty-auth", "marty-canvas-sandbox",
        "marty-canvas-sync-worker", "marty-compliance-profile",
        "marty-credential-template", "marty-deployment-profile",
        "marty-device-registration", "marty-event-stream", "marty-flow",
        "marty-gateway", "marty-issuance-service", "marty-keyless-grpc-bridge",
        "marty-notification", "marty-oidf-keyless-edge", "marty-organization",
        "marty-passport-acceptance-api-key", "marty-passport-beta-bureau",
        "marty-passport-callback-signer", "marty-passport-callback-signer-supported",
        "marty-passport-keyless-edge", "marty-passport-provider-ingress",
        "marty-passport-tls-bootstrap", "marty-presentation-policy",
        "marty-revocation-profile", "marty-signing-keys", "marty-trust-profile",
        "marty-verification-service", "marty-verifier-positive-gate",
    )),
    (),
    "marty-oid4vc-all-services-",
    "oid4vc-local-native",
    volumes=("ui-canvas-cargo", "marty-oid4vc-native-d2de-target-20261028"),
    cargo_profile="release",
)


LATEST_ALL_SERVICES = BuildProfile(
    "oid4vc-latest-maintenance-all-services",
    "852dbb5cc0cca79cfe0bbbed5cb8fb94cda0ad34",
    OFFICIAL_ALL_SERVICES.roles,
    (),
    "marty-native-latest-maintenance-",
    "native-latest-maintenance",
    volumes=OFFICIAL_ALL_SERVICES.volumes,
    cargo_profile="release",
)


def reviewed_profile(name):
    for profile in (SIGNING_CAS, SIGNING_CAS_NO_TRANSFORM, CURRENT_ISSUER_READY, CURRENT_ISSUER_POLICY_SIGNING, CURRENT_ISSUER_POLICY_SIGNING_COMPACT, CANVAS_SCOPED_JOBS, D12_PASSPORT_CURRENT, ISSUANCE_OFFER_FORMAT, D05_MEMBERSHIP_CURRENT, D05_MEMBERSHIP_LATEST, OFFICIAL_ALL_SERVICES, LATEST_ALL_SERVICES):
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
