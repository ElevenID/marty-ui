"""Default metadata registration hooks remain strict without a Docker daemon."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from repair_beta_release_metadata import Operation


def test_registration_snapshot_delegates_raw_ps_ids_and_stem():
    calls = []

    class Transport:
        def observe_lines(self, args, stem):
            calls.append((args, stem))
            return ["b" * 64, "a" * 64]

    operation = Operation.__new__(Operation)
    operation.g = Transport()
    assert operation.registration_snapshot("all-before") == {"a" * 64, "b" * 64}
    assert calls == [(["ps", "-aq", "--no-trunc"], "all-before")]


@pytest.mark.parametrize("phase", ["execute-before", "execute-after", "recovery-before", "recovery-after"])
def test_registration_cohort_default_refuses_missing_or_extra_ids(phase):
    operation = Operation.__new__(Operation)
    expected = {"a" * 64, "b" * 64}
    operation.assert_registration_cohort(expected, expected, "REGISTRATION_CHANGED", phase=phase)
    for actual in ({"a" * 64}, expected | {"c" * 64}):
        with pytest.raises(ValueError, match="REGISTRATION_CHANGED"):
            operation.assert_registration_cohort(actual, expected, "REGISTRATION_CHANGED", phase=phase)


def test_registration_cohort_preserves_caller_list_shape_and_order():
    operation = Operation.__new__(Operation)
    operation.assert_registration_cohort(["a", "b"], ["a", "b"], "BASELINE_REGISTRATIONS_CHANGED", phase="execute-before")
    with pytest.raises(ValueError, match="BASELINE_REGISTRATIONS_CHANGED"):
        operation.assert_registration_cohort(["b", "a"], ["a", "b"], "BASELINE_REGISTRATIONS_CHANGED", phase="execute-before")
