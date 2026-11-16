"""One beta release metadata derivation; never inherit prior Gateway claims."""

import copy
import json
import re
import tomllib

TARGET = "/opt/marty-ui-static/demos/manifests/2026.08.0.json"
KEYS = ("ELEVENID_COMPONENT_REVISIONS_JSON", "ELEVENID_IMAGE_DIGESTS_JSON")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def marker_maps(source, cargo_lock_bytes, signed_images, runtime_roles):
    require(re.fullmatch("[a-f0-9]{40}", source) is not None, "PRODUCT_COMMIT_REQUIRED")
    lock = tomllib.loads(cargo_lock_bytes.decode("utf-8"))
    components = {"marty-ui": source}
    for name in ("marty-core", "marty-microservices-framework"):
        sources = {
            v["source"]
            for v in lock["package"]
            if "/" + name + "?" in v.get("source", "")
        }
        require(len(sources) == 1, "ONE_LOCKED_SOURCE_REQUIRED")
        text = next(iter(sources))
        revision = text.rsplit("#", 1)[-1]
        require(
            re.fullmatch("[a-f0-9]{40}", revision) is not None
            and "rev=" + revision in text,
            "EXACT_LOCKED_REVISION_REQUIRED",
        )
        components[name] = revision
    roles = [row["role"] for row in runtime_roles]
    require(
        len(roles) == 22 and len(set(roles)) == 22, "EXACT_PRODUCT_ROLE_SET_REQUIRED"
    )
    images = {}
    for role in roles:
        reference = signed_images["services"].get("ui" if role == "ui-prod" else role)
        if role in ("passport-beta-bureau", "passport-callback-signer"):
            reference = signed_images["services"]["gateway"]
        require(
            isinstance(reference, str)
            and re.fullmatch(r".+@sha256:[a-f0-9]{64}", reference) is not None,
            "SIGNED_ROLE_IMAGE_REQUIRED",
        )
        images[role] = reference.split("@")[1]
    return components, images


def gateway_metadata_model(base, marker):
    result = copy.deepcopy(base)
    environment = result["services"]["gateway"]["environment"]
    require(
        all(key in environment for key in KEYS), "EXISTING_GATEWAY_METADATA_REQUIRED"
    )
    environment[KEYS[0]] = json.dumps(
        marker["component_revisions"], separators=(",", ":"), sort_keys=True
    )
    environment[KEYS[1]] = json.dumps(
        marker["image_digests"], separators=(",", ":"), sort_keys=True
    )
    return result


def ui_metadata_model(base, public_file):
    result = copy.deepcopy(base)
    volumes = result["services"]["ui-prod"].setdefault("volumes", [])
    require(
        not any(v.get("target") == TARGET for v in volumes),
        "PUBLIC_MANIFEST_ALREADY_OVERRIDDEN",
    )
    volumes.append(
        dict(
            type="bind",
            source=str(public_file).replace("\\", "/"),
            target=TARGET,
            read_only=True,
            bind={},
        )
    )
    return result
