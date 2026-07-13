from __future__ import annotations

from scripts.check_github_release_environments import (
    PreflightError,
    validate_configuration,
    validate_environment,
)


def protected_environment() -> dict:
    return {
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{"type": "Team", "reviewer": {"id": 1}}],
            }
        ],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }


def requirement() -> dict:
    return {
        "prevent_admin_bypass": True,
        "prevent_self_review": True,
        "require_reviewers": True,
        "require_branch_policy": True,
        "required_secrets": ["SECRET_A"],
        "required_variables": ["VARIABLE_A"],
    }


def test_environment_accepts_protected_complete_configuration() -> None:
    assert validate_environment(
        "beta",
        requirement(),
        protected_environment(),
        {"SECRET_A"},
        {"VARIABLE_A"},
    ) == []


def test_environment_reports_every_missing_protection_and_input() -> None:
    errors = validate_environment("beta", requirement(), {}, set(), set())

    assert errors == [
        "beta: at least one required reviewer must be configured",
        "beta: self-review must be disabled",
        "beta: administrator bypass must be disabled",
        "beta: deployment branches must be restricted",
        "beta: missing secrets: SECRET_A",
        "beta: missing variables: VARIABLE_A",
    ]


class FakeApi:
    def __init__(self) -> None:
        self.environments = {"beta": protected_environment()}

    def repository_variables(self) -> dict[str, str]:
        return {"MARTY_REF": "a" * 40}

    def environment(self, name: str) -> dict:
        if name not in self.environments:
            raise PreflightError("GitHub API returned 404")
        return self.environments[name]

    def environment_names(self, name: str, resource: str) -> set[str]:
        return {"SECRET_A"} if resource == "secrets" else {"VARIABLE_A"}


def test_configuration_checks_repository_shas_and_missing_environments() -> None:
    manifest = {
        "repository_variables": ["MARTY_REF", "MISSING_REF"],
        "environments": {
            "beta": requirement(),
            "missing": requirement(),
        },
    }

    errors = validate_configuration(FakeApi(), manifest)

    assert errors == [
        "repository variable MISSING_REF must be a lowercase 40-character SHA",
        "missing: GitHub API returned 404",
    ]
