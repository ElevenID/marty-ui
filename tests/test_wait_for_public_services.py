import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wait_for_public_services", ROOT / "scripts" / "wait_for_public_services.py")
assert SPEC and SPEC.loader
waiter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(waiter)


def test_unhealthy_services_requires_the_full_public_contract() -> None:
    payload = {"services": {name: {"status": "healthy"} for name in waiter.REQUIRED_SERVICES}}
    assert waiter.unhealthy_services(payload) == set()
    payload["services"]["issuance"] = {"status": "unreachable"}
    assert waiter.unhealthy_services(payload) == {"issuance"}


def test_unhealthy_services_rejects_malformed_gateway_responses() -> None:
    assert waiter.unhealthy_services({}) == set(waiter.REQUIRED_SERVICES)
