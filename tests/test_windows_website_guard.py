"""Exercise the shared selection lock and website guard on private NTFS."""
from pathlib import Path

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_selfhost_windows_selection import fixture
from tests.test_windows_website_plan import planned, rehash
import selfhost_windows_selection as selection
import selfhost_windows_website as website
import selfhost_windows_website_guard as guard
import selfhost_windows_website_plan as plan_contract


@pytest.mark.parametrize('fault', [None, 'wrong-plan', 'native-proof', 'journal-interrupted'])
def test_website_guard_uses_existing_selection_fence_and_pinned_pending_reader(monkeypatch, planned, fault):
    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, cfg):
        cfg['tls_init_receipt'] = {'id': '1'*64, 'image': 'sha256:'+'2'*64, 'config_hash': '3'*64}
        path.write_bytes(selection.packed(cfg))
        selection.adopt(path)
        attempt = root / ('windows-website-' + 'a'*32)
        fence = selection.renewal.product_transition_guard(cfg)
        proofs = []
        plans = []
        original_prove = selection._prove

        def prove(*args, **kwargs):
            assert not fence.exists()
            proofs.append(kwargs['expected_data'])
            if fault == 'native-proof':
                raise ValueError('synthetic native refusal')
            return original_prove(*args, **kwargs)

        def preflight(config, _choice, _values, _record, _assets, *, plan_owner,
                      plan_attempt_directory, held_plan_only=False, **_kwargs):
            plan = plan_contract.plan(**planned)
            body = Path(config['compose_file']).read_bytes()
            model_hash = selection.digest(selection.packed(selection.decode(body)))
            plan['owner'] = {**plan_owner, 'model_sha256': model_hash}
            plan['states']['combined']['model_sha256'] = model_hash
            plan['states']['combined']['data_sha256'] = plan_owner['data_sha256']
            plan['backout']['preserved_selected_sha256'] = plan_owner['selected_sha256']
            plan['attempt_directory'] = str(plan_attempt_directory)
            plan['route_directory'] = str(plan_attempt_directory / 'routes')
            rehash(plan)
            plans.append(plan)
            return plan if held_plan_only else {'plan_sha256': plan['plan_sha256']}

        monkeypatch.setattr(selection, '_prove', prove)
        monkeypatch.setattr(website, 'inspect_composition', preflight)
        if fault == 'journal-interrupted':
            def interrupted(_plan):
                assert fence.is_file()
                raise RuntimeError('synthetic interruption after guard publication')
            monkeypatch.setattr(guard.store, 'initialize', interrupted)

        kwargs = dict(gh=None, cosign=None, registry_config=None, plan_attempt_directory=attempt)
        with selection.selected_inputs(path) as lease:
            check = lease.check_website_composition(root, **kwargs)
            assert not fence.exists() and not attempt.exists()
            expected = '0'*64 if fault == 'wrong-plan' else check['plan_sha256']
            if fault:
                with pytest.raises((ValueError, RuntimeError)):
                    lease.begin_website_transition(root, expected_plan_sha256=expected, **kwargs)
                with pytest.raises(ValueError):
                    lease.check_current()
            else:
                admitted = lease.begin_website_transition(root, expected_plan_sha256=expected, **kwargs)
                with pytest.raises(ValueError):
                    lease.check_current()
        assert proofs == ([] if fault == 'wrong-plan' else [phase['data']])
        if fault in {'wrong-plan', 'native-proof'}:
            assert not fence.exists() and not attempt.exists()
            return

        assert selection.renewal.recovery_pending(cfg)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):
                pytest.fail('ordinary owner entered a pending website transition')
        with pytest.raises(ValueError):
            selection.renew_once(path, 'marty-selfhost-synthetic')
        plan = plans[-1]
        body = fence.read_bytes()
        guard_pin = selection.digest(body)
        anchor_pin = guard.store.initial_anchor_sha256(plan)
        assert body == selection.packed(guard.marker(plan))
        if fault == 'journal-interrupted':
            with pytest.raises(ValueError):
                selection.inspect_website_transition(path, plan, guard_sha256=guard_pin,
                                                     expected_anchor_sha256=anchor_pin)
            assert fence.read_bytes() == body
            return
        assert admitted == selection.inspect_website_transition(path, plan, guard_sha256=guard_pin,
                                                               expected_anchor_sha256=anchor_pin)
        for bad_guard, bad_anchor in (('1'*64, anchor_pin), (guard_pin, '1'*64)):
            with pytest.raises(ValueError):
                selection.inspect_website_transition(path, plan, guard_sha256=bad_guard,
                                                     expected_anchor_sha256=bad_anchor)
        selection.renewal.renewal_staging_guard(cfg).write_bytes(b'competing synthetic transition')
        with pytest.raises(ValueError):
            selection.inspect_website_transition(path, plan, guard_sha256=guard_pin,
                                                 expected_anchor_sha256=anchor_pin)
        assert fence.read_bytes() == body
