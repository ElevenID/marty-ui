"""Canvas may attach only to the actual beta-owned tunnel and network."""
import json

import pytest

from scripts.canvas_beta_topology import BETA_NETWORK, assert_canvas_route_owner, inspect_beta_tunnel


@pytest.mark.parametrize('mutation', ['none', 'missing_owner', 'duplicate', 'wrong_network', 'replaced'])
def test_tunnel_observation_requires_unique_running_beta_services_on_exact_network(mutation):
    network_id = 'a' * 64
    observations = {}

    def docker(*args):
        if args[0] == 'network':
            assert args[2] == BETA_NETWORK
            return network_id
        if args[0] == 'ps':
            assert 'label=com.docker.compose.project=elevenid-beta' in args
            service = next(value.split('=', 2)[2] for value in args
                           if value.startswith('label=com.docker.compose.service='))
            observations[service] = observations.get(service, 0) + 1
            if mutation == 'missing_owner':
                return ''
            original = ('b' if service == 'nginx-proxy' else 'c') * 64
            if mutation == 'duplicate':
                return original + '\n' + 'd' * 64
            if mutation == 'replaced' and observations[service] > 1:
                return 'e' * 64
            return original
        assert args[0] == 'inspect'
        return json.dumps({BETA_NETWORK: {'NetworkID': 'f' * 64 if mutation == 'wrong_network' else network_id}})

    if mutation == 'none':
        proof = inspect_beta_tunnel(docker)
        assert proof['beta_network_id'] == network_id
        assert proof['beta_tunnel_container_ids'] == {'nginx-proxy': 'b' * 64, 'cloudflared': 'c' * 64}
    else:
        with pytest.raises(RuntimeError, match='beta-owned|different network|changed during'):
            inspect_beta_tunnel(docker)


@pytest.mark.parametrize('mutation', ['none', 'legacy_collision', 'wrong_project', 'wrong_role', 'before_free', 'before_owned'])
def test_canvas_public_alias_requires_one_stock_edge_or_no_owner_before_bootstrap(mutation):
    ids = ['a' * 64, 'b' * 64] if mutation == 'legacy_collision' else ['a' * 64]

    def docker(*args):
        if args[0] == 'network':
            return json.dumps({cid: {} for cid in ids})
        cid = args[1]
        if 'NetworkSettings' in args[-1]:
            return json.dumps({BETA_NETWORK: {'Aliases': [] if mutation == 'before_free' else ['canvas-real']}})
        return json.dumps(dict(id=cid, running=True, labels={
            'com.docker.compose.project': 'foreign' if mutation == 'wrong_project' else 'canvas-oss-portability',
            'com.docker.compose.service': 'other' if mutation == 'wrong_role' else 'canvas-edge'}))

    expected = None if mutation.startswith('before_') else ids[0]
    if mutation in ['none', 'before_free']:
        proof = assert_canvas_route_owner(docker, expected)
        assert proof['running_owners'] == ([] if expected is None else [expected])
    else:
        with pytest.raises(RuntimeError, match='route'):
            assert_canvas_route_owner(docker, expected)
