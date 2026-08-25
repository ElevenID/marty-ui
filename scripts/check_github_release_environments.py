#!/usr/bin/env python3
"""Fail closed when GitHub release environments are not protected or complete."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PreflightError(RuntimeError):
    """Raised when release configuration is absent or unsafe."""


@dataclass(frozen=True)
class GitHubApi:
    repository: str
    token: str
    api_url: str = "https://api.github.com"

    def get(self, path: str) -> dict[str, Any]:
        url = f"{self.api_url.rstrip('/')}/{path.lstrip('/')}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raise PreflightError(f"GitHub API returned {exc.code} for {path}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise PreflightError(
                f"GitHub API request failed for {path}: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise PreflightError(f"GitHub API returned a non-object for {path}")
        return payload

    def repository_variables(self) -> dict[str, str]:
        payload = self.get(f"repos/{self.repository}/actions/variables?per_page=100")
        variables = payload.get("variables")
        if not isinstance(variables, list):
            raise PreflightError("Repository variable response is malformed")
        return {
            str(item.get("name")): str(item.get("value", ""))
            for item in variables
            if isinstance(item, dict) and item.get("name")
        }

    def environment(self, name: str) -> dict[str, Any]:
        encoded = urllib.parse.quote(name, safe="")
        return self.get(f"repos/{self.repository}/environments/{encoded}")

    def environment_names(self, name: str, resource: str) -> set[str]:
        encoded = urllib.parse.quote(name, safe="")
        payload = self.get(
            f"repos/{self.repository}/environments/{encoded}/{resource}?per_page=100"
        )
        items = payload.get(resource)
        if not isinstance(items, list):
            raise PreflightError(
                f"Environment {resource} response is malformed for {name}"
            )
        return {
            str(item.get("name"))
            for item in items
            if isinstance(item, dict) and item.get("name")
        }


def _missing(required: list[str], present: set[str]) -> list[str]:
    return sorted(set(required) - present)


def validate_environment(
    name: str,
    requirement: dict[str, Any],
    environment: dict[str, Any],
    secrets: set[str],
    variables: set[str],
    *,
    check_inputs: bool = True,
) -> list[str]:
    errors: list[str] = []
    rules = environment.get("protection_rules")
    rules = rules if isinstance(rules, list) else []
    reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    reviewers = [
        reviewer
        for rule in reviewer_rules
        for reviewer in (rule.get("reviewers") or [])
        if isinstance(reviewer, dict)
    ]

    if requirement.get("require_reviewers") and not reviewers:
        errors.append(f"{name}: at least one required reviewer must be configured")
    if requirement.get("prevent_self_review") and not any(
        rule.get("prevent_self_review") is True for rule in reviewer_rules
    ):
        errors.append(f"{name}: self-review must be disabled")
    if (
        requirement.get("prevent_admin_bypass")
        and environment.get("can_admins_bypass") is not False
    ):
        errors.append(f"{name}: administrator bypass must be disabled")

    branch_policy = environment.get("deployment_branch_policy")
    branch_restricted = isinstance(branch_policy, dict) and (
        branch_policy.get("protected_branches") is True
        or branch_policy.get("custom_branch_policies") is True
    )
    if requirement.get("require_branch_policy") and not branch_restricted:
        errors.append(f"{name}: deployment branches must be restricted")

    if check_inputs:
        missing_secrets = _missing(requirement.get("required_secrets", []), secrets)
        if missing_secrets:
            errors.append(f"{name}: missing secrets: {', '.join(missing_secrets)}")
        missing_variables = _missing(
            requirement.get("required_variables", []), variables
        )
        if missing_variables:
            errors.append(f"{name}: missing variables: {', '.join(missing_variables)}")
    return errors


def validate_configuration(
    api: GitHubApi,
    manifest: dict[str, Any],
    selected_environments: set[str] | None = None,
    *,
    check_inputs: bool = True,
) -> list[str]:
    errors: list[str] = []
    if check_inputs:
        repository_variables = api.repository_variables()
        for name in manifest.get("repository_variables", []):
            value = repository_variables.get(name, "")
            if len(value) != 40 or any(
                char not in "0123456789abcdef" for char in value
            ):
                errors.append(
                    f"repository variable {name} must be a lowercase 40-character SHA"
                )

    environments = manifest.get("environments")
    if not isinstance(environments, dict) or not environments:
        return errors + ["manifest must declare release environments"]

    selected = (
        set(environments) if selected_environments is None else selected_environments
    )
    unknown = sorted(selected - set(environments))
    if unknown:
        errors.append(f"manifest does not declare environments: {', '.join(unknown)}")

    for name, requirement in environments.items():
        if name not in selected:
            continue
        if not isinstance(requirement, dict):
            errors.append(f"{name}: environment requirement must be an object")
            continue
        try:
            environment = api.environment(name)
            secrets = api.environment_names(name, "secrets") if check_inputs else set()
            variables = (
                api.environment_names(name, "variables") if check_inputs else set()
            )
        except PreflightError as exc:
            errors.append(f"{name}: {exc}")
            continue
        errors.extend(
            validate_environment(
                name,
                requirement,
                environment,
                secrets,
                variables,
                check_inputs=check_inputs,
            )
        )
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("deploy-config/github-release-environments.json"),
    )
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--token", default=os.getenv("GH_TOKEN", ""))
    parser.add_argument(
        "--api-url", default=os.getenv("GITHUB_API_URL", "https://api.github.com")
    )
    parser.add_argument(
        "--environment",
        action="append",
        dest="environments",
        help="Validate only this declared environment; may be repeated.",
    )
    parser.add_argument(
        "--protection-only",
        action="store_true",
        help="Check deployment protections without listing secret or variable names.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.repository or "/" not in args.repository:
        print("A GitHub owner/repository is required.", file=sys.stderr)
        return 2
    if not args.token:
        print("GH_TOKEN is required.", file=sys.stderr)
        return 2

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            raise PreflightError(
                "release environment manifest schema_version must be 1"
            )
        errors = validate_configuration(
            GitHubApi(args.repository, args.token, args.api_url),
            manifest,
            set(args.environments) if args.environments else None,
            check_inputs=not args.protection_only,
        )
    except (OSError, json.JSONDecodeError, PreflightError) as exc:
        print(f"Release environment preflight failed: {exc}", file=sys.stderr)
        return 1

    if errors:
        print("Release environment preflight failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    if args.protection_only:
        print("GitHub release environment protections are complete.")
    else:
        print("GitHub release environments are protected and complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
