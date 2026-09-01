#!/usr/bin/env python3
"""Fail closed when a stack release tag already has a draft or published release."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

API_VERSION = "2026-03-10"
REGISTRY = "ghcr.io"
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)


class ReleaseLookupError(RuntimeError):
    """The release state could not be established safely."""


class ReleaseAlreadyExists(RuntimeError):
    """A draft or published release already owns the requested tag."""


class RegistryTagAlreadyExists(RuntimeError):
    """A registry manifest already owns the requested version tag."""


def _release_url(repository: str, tag: str) -> str:
    try:
        owner, name = repository.split("/", 1)
    except ValueError as error:
        raise ReleaseLookupError("repository must use OWNER/REPO format") from error
    if not owner or not name or "/" in name or not tag:
        raise ReleaseLookupError(
            "repository must use OWNER/REPO format and tag must be non-empty"
        )
    return (
        "https://api.github.com/repos/"
        f"{quote(owner, safe='')}/{quote(name, safe='')}/releases/tags/{quote(tag, safe='')}"
    )


def _load_release(
    repository: str,
    tag: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any] | None:
    if not token:
        raise ReleaseLookupError("GH_TOKEN is required")
    request = Request(
        _release_url(repository, tag),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    try:
        with opener(request, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise ReleaseLookupError(
            f"GitHub release lookup failed with HTTP {error.code}"
        ) from error
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseLookupError(
            "GitHub release lookup returned an invalid response"
        ) from error
    if not isinstance(payload, dict):
        raise ReleaseLookupError("GitHub release lookup returned an invalid response")
    return payload


def ensure_release_absent(
    repository: str,
    tag: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> None:
    release = _load_release(repository, tag, token, opener=opener)
    if release is None:
        return
    if release.get("tag_name") != tag or not isinstance(release.get("draft"), bool):
        raise ReleaseLookupError(
            "GitHub release response did not match the requested tag"
        )
    state = "draft" if release["draft"] else "published"
    raise ReleaseAlreadyExists(
        f"Release {tag} already exists as a {state}; refusing to rebuild or overwrite it. "
        "Inspect and explicitly remove an incomplete draft before retrying."
    )


def _registry_repository(image: str) -> str:
    prefix = f"{REGISTRY}/"
    if (
        not image.startswith(prefix)
        or "@" in image
        or ":" in image[len(prefix) :]
        or image.endswith("/")
    ):
        raise ReleaseLookupError("registry image must be an unqualified ghcr.io path")
    repository = image[len(prefix) :]
    if repository.count("/") < 1 or any(not item for item in repository.split("/")):
        raise ReleaseLookupError("registry image path is invalid")
    return repository


def _registry_token(
    repository: str,
    username: str,
    token: str,
    *,
    opener: Callable[..., Any],
) -> str:
    query = urlencode({"service": REGISTRY, "scope": f"repository:{repository}:pull"})
    headers = {"Accept": "application/json"}
    if username and token:
        credential = base64.b64encode(f"{username}:{token}".encode()).decode()
        headers["Authorization"] = f"Basic {credential}"
    request = Request(f"https://{REGISTRY}/token?{query}", headers=headers)
    try:
        with opener(request, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        raise ReleaseLookupError(
            f"registry token lookup failed with HTTP {error.code}"
        ) from error
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseLookupError(
            "registry token lookup returned an invalid response"
        ) from error
    if not isinstance(payload, dict):
        raise ReleaseLookupError("registry token lookup returned an invalid response")
    registry_token = payload.get("token") or payload.get("access_token")
    if not isinstance(registry_token, str) or not registry_token:
        raise ReleaseLookupError("registry token lookup returned no token")
    return registry_token


def ensure_registry_tag_absent(
    image: str,
    version_tag: str,
    username: str = "",
    token: str = "",
    *,
    opener: Callable[..., Any] = urlopen,
) -> None:
    repository = _registry_repository(image)
    if not version_tag or version_tag.startswith("v") or "/" in version_tag:
        raise ReleaseLookupError("registry version tag must be an exact no-v tag")
    registry_token = _registry_token(repository, username, token, opener=opener)
    request = Request(
        f"https://{REGISTRY}/v2/{quote(repository, safe='/')}/manifests/"
        f"{quote(version_tag, safe='')}",
        headers={
            "Accept": MANIFEST_ACCEPT,
            "Authorization": f"Bearer {registry_token}",
        },
        method="HEAD",
    )
    try:
        with opener(request, timeout=30):
            pass
    except HTTPError as error:
        if error.code == 404:
            return
        raise ReleaseLookupError(
            f"registry manifest lookup failed with HTTP {error.code}"
        ) from error
    except OSError as error:
        raise ReleaseLookupError("registry manifest lookup failed") from error
    raise RegistryTagAlreadyExists(
        f"Registry tag {image}:{version_tag} already exists; refusing to overwrite it."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument("--version-tag")
    args = parser.parse_args(argv)
    try:
        ensure_release_absent(args.repository, args.tag, os.environ.get("GH_TOKEN", ""))
        if bool(args.image) != bool(args.version_tag):
            raise ReleaseLookupError(
                "--image and --version-tag must be supplied together"
            )
        for image in args.image:
            ensure_registry_tag_absent(
                image,
                args.version_tag,
                os.environ.get("GITHUB_ACTOR", ""),
                os.environ.get("GH_TOKEN", ""),
            )
    except (
        RegistryTagAlreadyExists,
        ReleaseAlreadyExists,
        ReleaseLookupError,
    ) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"No existing GitHub release owns {args.tag}.")
    if args.image:
        print(f"No requested registry image owns {args.version_tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
