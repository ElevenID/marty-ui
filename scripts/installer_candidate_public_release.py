"""Bound the GitHub published-release identity before candidate authorization."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import installer_candidate_public_bootstrap as public_bootstrap
import installer_release as release


def require(value: object) -> None:
    if not value:
        raise ValueError("published release identity refused")


def expected_assets() -> dict[str, int]:
    limits = {"installer-inventory.json": 65536, **release.ARTIFACT_MAX_BYTES}
    return {name + suffix: (1048576 if suffix else limit)
            for name, limit in limits.items()
            for suffix in ("", ".sigstore.json", ".provenance.jsonl")}


def observe(api, tag: str, source_sha: str) -> dict:
    """Use authenticated API observations; reject movable or mismatched identity."""
    release.sha(source_sha)
    require(release.classify_release_tag(tag)[0] == "nightly")
    escaped = quote(tag, safe="")
    published = api("releases/tags/" + escaped)
    require(published["tag_name"] == tag and published["draft"] is False
            and published["prerelease"] is True and published["immutable"] is True)
    release.positive(published["id"])
    reference = api("git/ref/tags/" + escaped)
    require(reference["ref"] == "refs/tags/" + tag)
    target = reference["object"]
    release.sha(target["sha"])
    require(target["type"] in ("tag", "commit"))
    chain = [{"type": target["type"], "sha": target["sha"]}]
    if target["type"] == "tag":
        annotated = api("git/tags/" + target["sha"])
        require(annotated["sha"] == target["sha"] and annotated["tag"] == tag)
        target = annotated["object"]
        require(target["type"] == "commit")
        release.sha(target["sha"])
        chain.append({"type": "commit", "sha": target["sha"]})
    require(target["sha"] == source_sha)
    limits = expected_assets()
    entries = published["assets"]
    require(isinstance(entries, list) and len(entries) <= 100)
    selected = [item for item in entries if item.get("name") in limits]
    require(len(selected) == len(limits) and {item["name"] for item in selected} == set(limits))
    assets = []
    for item in selected:
        name = item["name"]
        release.positive(item["id"])
        require(item["state"] == "uploaded" and type(item["size"]) is int
                and 0 < item["size"] <= limits[name])
        digest = item["digest"]
        require(isinstance(digest, str) and digest.startswith("sha256:"))
        release.sha(digest[7:], 64)
        assets.append({"name": name, "id": item["id"], "size": item["size"],
                       "digest": digest, "state": item["state"]})
    require(len({item["id"] for item in assets}) == len(assets))
    return {"schema": "elevenid.installer-published-release-observation/v1",
            "repository": "ElevenID/marty-ui", "release_id": published["id"],
            "tag": tag, "source_sha": source_sha, "immutable": True,
            "tag_chain": chain, "assets": sorted(assets, key=lambda item: item["name"])}


def verify_downloads(snapshot: dict, directory: Path) -> None:
    """Bind the anonymous controller downloads to the observed asset metadata."""
    held = public_bootstrap.private_directory(directory)
    try:
        public_bootstrap.same_directory(held, directory)
    finally:
        import os
        os.close(held)
    assets = snapshot["assets"]
    require({path.name for path in directory.iterdir()} == {item["name"] for item in assets})
    for item in assets:
        path = directory / item["name"]
        digest, size = public_bootstrap.private_digest(path, item["size"])
        require(size == item["size"] and "sha256:" + digest == item["digest"])
