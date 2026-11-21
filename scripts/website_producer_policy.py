"""Role-scoped web producer identities; this policy does not verify signatures.

The standalone public website can produce only website receipts and its own
website image. Legacy application/composition authorities remain unchanged.
"""
from __future__ import annotations

import ui_release as ui

REF = "refs/heads/main"
STANDALONE_REPOSITORY = "ElevenID/website"
STANDALONE_REPOSITORY_ID = "1459542519"
STANDALONE_WORKFLOW = ".github/workflows/production-website-release.yml"
STANDALONE_IMAGE = "ghcr.io/elevenid/website"
LEGACY_REPOSITORIES = {ui.REPOSITORY: "1140864197", ui.COMMERCE_REPOSITORY: "1207411806"}
LEGACY_WEBSITE_IMAGE = "ghcr.io/elevenid/marty-ui-oss/website"
LEGACY_COMMERCE_WEBSITE_IMAGE = "ghcr.io/elevenid/marty-subscriptions/website"
PACKAGE_APPLICATION_IMAGE = "ghcr.io/elevenid/marty-ui-oss/application"
ROLES = ("website", "application", "composition")


def repositories_for(role: str) -> dict[str, str]:
    """Return a fresh allowlist for one semantic authority, never a union."""
    ui.require(isinstance(role, str) and role in ROLES, "unknown web producer role")
    result = dict(LEGACY_REPOSITORIES)
    if role == "website":
        result[STANDALONE_REPOSITORY] = STANDALONE_REPOSITORY_ID
    return result


def producer_policy(repository: str, *, role: str) -> dict[str, str]:
    repositories = repositories_for(role)
    ui.require(isinstance(repository, str) and repository in repositories,
               "repository is not authorized for the web producer role")
    workflows = {ui.REPOSITORY: ui.WORKFLOW, ui.COMMERCE_REPOSITORY: ui.COMMERCE_WORKFLOW,
                 STANDALONE_REPOSITORY: STANDALONE_WORKFLOW}
    return {"repository": repository, "repository_id": repositories[repository],
            "workflow": workflows[repository], "ref": REF}


def validate_producer(producer: dict, *, role: str) -> dict:
    ui.require(isinstance(producer, dict) and set(producer) == {
        "repository", "workflow", "source_sha", "ref", "run_id", "run_attempt"},
        "web producer fields differ")
    expected = producer_policy(producer["repository"], role=role)
    ui.require(producer["workflow"] == expected["workflow"] and producer["ref"] == expected["ref"],
               "web producer workflow or ref differs")
    ui.require(isinstance(producer["source_sha"], str) and ui.SHA.fullmatch(producer["source_sha"]) is not None,
               "invalid web producer source SHA")
    for name in ("run_id", "run_attempt"):
        ui.require(isinstance(producer[name], str) and ui.RUN.fullmatch(producer[name]) is not None,
                   "invalid web producer invocation")
    return producer


def image_policy(uri: str, *, role: str) -> dict[str, str]:
    """Keep image coordinates bound to their original producer and role."""
    repositories_for(role)
    images = {
        "website": {LEGACY_WEBSITE_IMAGE: ui.REPOSITORY,
                    LEGACY_COMMERCE_WEBSITE_IMAGE: ui.COMMERCE_REPOSITORY,
                    STANDALONE_IMAGE: STANDALONE_REPOSITORY},
        "application": {ui.PUBLIC_IMAGE: ui.REPOSITORY, ui.COMMERCE_IMAGE: ui.COMMERCE_REPOSITORY},
        "composition": {},
    }[role]
    if role == "application":
        images[PACKAGE_APPLICATION_IMAGE] = ui.REPOSITORY
    ui.require(isinstance(uri, str) and uri in images, "image is not authorized for the web producer role")
    return producer_policy(images[uri], role=role)
