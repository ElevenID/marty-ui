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


def reviewed_profile(name):
    for profile in (SIGNING_CAS, SIGNING_CAS_NO_TRANSFORM, CANVAS_SCOPED_JOBS):
        if name == profile.name:
            return profile
    raise ValueError("UNKNOWN_REVIEWED_BUILD_PROFILE")
