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

CANVAS_SCOPED_JOBS = BuildProfile(
    "canvas-issuer-scoped-jobs",
    "fce109daf47a7712c1ff5779b0e33def57bbce20",
    (("issuance-native", "marty-issuance-service"),),
    ("marty-issuance-service",),
    "marty-canvas-scoped-jobs-",
    "canvas-scoped-jobs-native",
    "44040270000f93b7e7499cbec31b3bb3dd7e3df1",
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


def reviewed_profile(name):
    for profile in (SIGNING_CAS, SIGNING_CAS_NO_TRANSFORM, CANVAS_SCOPED_JOBS, OFFICIAL_ALL_SERVICES):
        if name == profile.name:
            return profile
    raise ValueError("UNKNOWN_REVIEWED_BUILD_PROFILE")
