"""Observe the existing beta tunnel by Compose ownership, never container names."""
from __future__ import annotations

import json
import re

BETA_PROJECT = 'elevenid-beta'
BETA_NETWORK = 'elevenid-beta-network'


def inspect_beta_tunnel(docker) -> dict:
    network_id = docker('network', 'inspect', BETA_NETWORK, '--format', '{{.Id}}')
    if not re.fullmatch('[0-9a-f]{64}', network_id):
        raise RuntimeError('Beta tunnel network identity is unavailable')
    containers = {}
    for service in ['nginx-proxy', 'cloudflared']:
        selectors = ('--filter', 'label=com.docker.compose.project=' + BETA_PROJECT,
                     '--filter', 'label=com.docker.compose.service=' + service)
        ids = docker('ps', '--no-trunc', *selectors, '--format', '{{.ID}}').splitlines()
        if len(ids) != 1 or not re.fullmatch('[0-9a-f]{64}', ids[0]):
            raise RuntimeError('One running beta-owned tunnel service is required: ' + service)
        networks = json.loads(docker('inspect', ids[0], '--format', '{{json .NetworkSettings.Networks}}'))
        if networks.get(BETA_NETWORK, {}).get('NetworkID') != network_id:
            raise RuntimeError('Beta tunnel service is attached to a different network: ' + service)
        if docker('ps', '--no-trunc', *selectors, '--format', '{{.ID}}').splitlines() != ids:
            raise RuntimeError('Beta tunnel service changed during observation')
        containers[service] = ids[0]
    return dict(beta_project=BETA_PROJECT, beta_network=BETA_NETWORK,
                beta_network_id=network_id, beta_tunnel_running=True,
                beta_tunnel_container_ids=containers)
