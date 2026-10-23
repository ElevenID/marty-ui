"""The workspace Rust lane must actually execute each declared vector owner."""

import pytest

import scripts.ci.check_public_vector_execution as execution
from scripts.check_gateway_public_protocol_contract import VectorTestOwner


@pytest.fixture
def two_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        execution,
        "VECTOR_TEST_OWNERS",
        {
            "first.json": VectorTestOwner(
                "rust/services/gateway/src/alpha.rs", "first"
            ),
            "second.json": VectorTestOwner(
                "rust/services/gateway/src/beta.rs", "second"
            ),
        },
    )


def test_exact_successful_execution_for_every_owner(two_owners: None) -> None:
    execution.assert_public_vector_tests_executed(
        "test alpha::tests::first ... ok\ntest beta::tests::second ... ok\n"
    )


@pytest.mark.parametrize(
    "similar_line",
    [
        "test alpha::tests::first ... ignored",
        "test alpha::tests::first ... FAILED",
        "test other::tests::first ... ok",
        "test alpha::tests::first_extra ... ok",
        "prefix test alpha::tests::first ... ok",
        "test alpha::tests::first ... ok suffix",
    ],
)
def test_nonexecuting_or_similar_lines_do_not_satisfy_owner(
    two_owners: None, similar_line: str
) -> None:
    with pytest.raises(AssertionError, match="first.json"):
        execution.assert_public_vector_tests_executed(
            similar_line + "\ntest beta::tests::second ... ok\n"
        )


def test_missing_one_owner_fails_closed(two_owners: None) -> None:
    with pytest.raises(AssertionError, match="second.json"):
        execution.assert_public_vector_tests_executed(
            "test alpha::tests::first ... ok\n"
        )
