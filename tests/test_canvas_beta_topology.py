"""Canvas may attach only to the actual beta-owned tunnel and network."""
import json

import pytest

from scripts.canvas_beta_topology import BETA_NETWORK, inspect_beta_tunnel


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
