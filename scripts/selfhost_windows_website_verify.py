"""Qualify ingress and the retained application under the managed Windows owner."""
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import parse_qs, urlsplit

from installer_live_tls_probe import DISCOVERY_PATH, ISSUER_PATH, public_origin
import selfhost_windows_selection as selection
import selfhost_windows_website_edge as edge
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store
import website_release as web


require = selection.require
renewal = selection.renewal
PHASES = {'verify-website': ('split', edge.FORWARD), 'verify-combined': ('staged', edge.BACKOUT)}
WEBSITE_MARKER = '/marty-website-release.json'
APPLICATION_MARKER = '/marty-ui-release.json'
READY = '/ready'
LOGIN = '/v1/auth/login?redirect_uri=%2Fconsole'
SESSION = '/v1/auth/me'
AUTH = ISSUER_PATH + '/protocol/openid-connect/auth'
MAX_BODY = 4 * 1024 * 1024
REDIRECTS = {301, 302, 307, 308}


@dataclass(frozen=True)
class Response:
    status: int
    headers: http.client.HTTPMessage
    body: bytes
    peer: dict | None = None

    def header(self, name):
        values = self.headers.get_all(name, [])
        require(len(values) <= 1)
        return values[0] if values else ''

    def record(self):
        return {'status': self.status, 'body_sha256': selection.digest(self.body), 'tls': self.peer}


def _public_addresses(host):
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    addresses = {ipaddress.ip_address(record[4][0]) for record in records}
    require(0 < len(addresses) <= 16 and all(address.is_global and not address.is_multicast
            and getattr(address, 'ipv4_mapped', None) is None for address in addresses))
    return tuple(str(address) for address in sorted(addresses, key=lambda item: (item.version, int(item))))


def _request(host, path, addresses, port, context, deadline):
    """Connect to the observed DNS answers, with SNI, hostname checks and no proxy."""
    require(re.fullmatch(r'/[A-Za-z0-9_./%?=&-]*', path) is not None and not path.startswith('//'))
    for address in addresses:
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        try:
            plain = socket.create_connection((address, port), timeout=min(remaining, 8))
        except OSError:
            continue
        break
    else:
        raise ValueError('Managed website endpoint is unreachable')
    with plain:
        transport = context.wrap_socket(plain, server_hostname=host) if context is not None else plain
        with transport:
            peer = None
            if context is not None:
                protocol = transport.version()
                certificate = transport.getpeercert(binary_form=True)
                require(protocol in {'TLSv1.2', 'TLSv1.3'} and 0 < len(certificate) <= 16384)
                peer = {'address': address, 'version': protocol, 'leaf_sha256': hashlib.sha256(certificate).hexdigest()}
            request = f'GET {path} HTTP/1.1\r\nHost: {host}\r\n'
            request += 'Connection: close\r\nCache-Control: no-cache\r\nAccept-Encoding: identity\r\n\r\n'
            transport.sendall(request.encode('ascii'))
            with http.client.HTTPResponse(transport, method='GET') as incoming:
                incoming.begin()
                response = Response(incoming.status, incoming.headers, incoming.read(MAX_BODY + 1), peer)
            require(len(response.body) <= MAX_BODY and time.monotonic() < deadline
                    and response.header('Content-Encoding').lower() in {'', 'identity'})
            return response


def _installed_ingress(row, model):
    service = model['services']['edge']
    domain = service['environment']['PUBLIC_DOMAIN']
    origin = public_origin('https://' + domain)
    require(origin.netloc == domain and origin.port is None and domain.count('.') >= 1
            and re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z][a-z0-9-]*', domain))
    env = row['Config']['Env']
    require([entry for entry in env if entry.startswith('PUBLIC_DOMAIN=')] == ['PUBLIC_DOMAIN=' + domain])
    actual = row['NetworkSettings']['Ports']
    require(set(actual) == {'80/tcp'} and len(actual['80/tcp']) == 1)
    binding = actual['80/tcp'][0]
    port = binding['HostPort']
    require(binding['HostIp'] == '127.0.0.1' and re.fullmatch(r'[1-9][0-9]{0,4}', port) and 1024 <= int(port) <= 65535)
    declared = service['ports']
    require(len(declared) == 1 and declared[0]['host_ip'] == '127.0.0.1' and declared[0]['target'] == 80
            and str(declared[0]['published']) == port and declared[0].get('protocol', 'tcp') == 'tcp')
    return domain, int(port)


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = set()
        self.canonicals = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script':
            source = attrs.get('src')
            if source and re.fullmatch(r'/[A-Za-z0-9_./-]+\.js', source) and not source.startswith('//'):
                self.paths.add(source)
        elif tag == 'link' and 'canonical' in (attrs.get('rel') or '').lower().split():
            self.canonicals.append(attrs.get('href') or '')


def _scripts(response, *, canonical_path=None):
    require(response.status == 200 and response.header('Content-Type').split(';')[0].strip().lower() == 'text/html')
    parsed = _Scripts()
    parsed.feed(response.body.decode('utf-8'))
    if canonical_path is not None:
        require(len(parsed.canonicals) == 1 and urlsplit(parsed.canonicals[0]).path == canonical_path)
    return parsed.paths


def _application_scripts(response):
    paths = _scripts(response)
    require(not any(path.startswith('/_website/') for path in paths))
    scripts = {path for path in paths if path.startswith('/assets/') or path in {'/runtime-config.js', '/startup.js'}}
    require(any(path.startswith('/assets/') for path in scripts))
    return scripts


def _json(response, status=200):
    require(response.status == status and
            response.header('Content-Type').split(';')[0].strip().lower() == 'application/json')
    value = selection.decode(response.body)
    require(type(value) is dict)
    return value


def _slash_route(fetch, origin, path):
    response = fetch(path)
    if response.status in REDIRECTS:
        require(response.header('Location') in {path + '/', origin + path + '/'})
        response = fetch(path + '/')
    return response


def _split_routes(public, local, origin, metadata, routes):
    boundary = routes['website']
    require({'/', WEBSITE_MARKER, '/product', '/resources', '/pricing', '/pricing/'} <= set(boundary['exact_paths'])
            and '/_website/' in boundary['path_prefixes'])
    revision = metadata['revision']
    require(revision == web.revision(metadata['source_sha'], metadata['commerce_extension']['source_sha']))
    prefix = '/_website/' + revision + '/'
    report = {}
    assets = None
    for source, fetch in (('public', public), ('loopback', local)):
        homepage, marker = fetch('/'), fetch(WEBSITE_MARKER)
        scripts = _scripts(homepage)
        candidates = {path for path in scripts if path.startswith(prefix)}
        require(candidates and (assets is None or assets == candidates))
        assets = candidates
        require(_json(marker) == metadata)
        product = _slash_route(fetch, origin, '/product')
        require(any(path.startswith(prefix) for path in _scripts(product)))
        resources = fetch('/resources')
        require(not resources.header('Location') and any(path.startswith(prefix)
                for path in _scripts(resources, canonical_path='/resources')))
        withheld = {path: fetch(path) for path in ('/pricing', '/pricing/')}
        require(all(row.status == 404 and not row.header('Location') for row in withheld.values()))
        runtime_path = '/_website/runtime-config.js'
        alternate = ('1' if revision.startswith('0') else '0') + revision[1:]
        missing_path = '/_website/' + alternate + '/missing.js'
        script = sorted(assets)[0]
        runtime, asset, missing = fetch(runtime_path), fetch(script), fetch(missing_path)
        require(all(row.status == 200 and row.body and row.header('Content-Type').split(';')[0].strip().lower()
                    in {'text/javascript', 'application/javascript'} for row in (runtime, asset)))
        require(missing.status == 404 and not missing.header('Location'))
        observed = {'/': homepage, WEBSITE_MARKER: marker, '/product': product, '/resources': resources,
                    **withheld, runtime_path: runtime, script: asset}
        require(all(row.header('X-Marty-Website-Revision') == revision for row in observed.values()))
        report[source] = {path: row.record() for path, row in {**observed, missing_path: missing}.items()}
        if source == 'loopback':
            for path in (runtime_path, script):
                require(report[source][path]['body_sha256'] == report['public'][path]['body_sha256'])
    return report


def _combined_routes(public, local, origin):
    report = {}
    public_scripts = None
    for source, fetch in (('public', public), ('loopback', local)):
        homepage = fetch('/')
        product = _slash_route(fetch, origin, '/product')
        marker = fetch(WEBSITE_MARKER)
        scripts = _application_scripts(homepage)
        require(public_scripts is None or public_scripts == scripts)
        public_scripts = scripts
        _scripts(product)
        require(marker.status in {200, 404} and
                marker.header('Content-Type').split(';')[0].strip().lower() == 'text/html' and
                all(not response.header('X-Marty-Website-Revision') for response in (homepage, product, marker)))
        report[source] = {'/': homepage.record(), '/product': product.record(), WEBSITE_MARKER: marker.record()}
    return report


def _application(public, local, origin, marker):
    release_public, release_local = public(APPLICATION_MARKER), local(APPLICATION_MARKER)
    require(_json(release_public) == _json(release_local) == marker)
    console_public, console_local = public('/console'), local('/console')
    require(_application_scripts(console_public) == _application_scripts(console_local))
    require(all(not row.header('X-Marty-Website-Revision') for row in
                (release_public, release_local, console_public, console_local)))
    ready = public(READY)
    readiness = _json(ready)
    require(readiness.get('status') == 'ready' and readiness.get('service') == 'api-gateway'
            and readiness['services']['auth']['status'] == 'healthy')
    discovery = public(DISCOVERY_PATH)
    identity = _json(discovery)
    require(all(identity.get(key) == origin + path for key, path in {
        'issuer': ISSUER_PATH, 'authorization_endpoint': AUTH, 'token_endpoint': ISSUER_PATH+'/protocol/openid-connect/token',
        'jwks_uri': ISSUER_PATH+'/protocol/openid-connect/certs'}.items()))
    login = public(LOGIN)
    location = login.header('Location')
    require(location.isascii() and not any(char.isspace() for char in location))
    target = urlsplit(location)
    fields = parse_qs(target.query, keep_blank_values=True, max_num_fields=24, strict_parsing=True)
    require(login.status in {302, 303} and not target.fragment and
            (target.scheme, target.netloc, target.path) == ('https', urlsplit(origin).netloc, AUTH))
    require(all(fields.get(key) == [value] for key, value in {'client_id': 'marty-ui', 'response_type': 'code',
        'redirect_uri': origin + '/v1/auth/callback', 'code_challenge_method': 'S256'}.items()))
    require(len(fields.get('scope', [])) == 1 and 'openid' in fields['scope'][0].split(' '))
    require(len(fields.get('code_challenge', [])) == 1 and
            re.fullmatch(r'[A-Za-z0-9_-]{43}', fields['code_challenge'][0]))
    require(all(len(fields.get(key, [])) == 1 and re.fullmatch(r'[A-Za-z0-9._~-]{16,256}', fields[key][0])
                for key in ('state', 'nonce')))
    require(fields.keys().isdisjoint({'client_secret', 'access_token', 'id_token', 'error'}))
    session = public(SESSION)
    require(_json(session) == {'authenticated': False})
    return {'release': {'public': release_public.record(), 'loopback': release_local.record()},
            'console': {'public': console_public.record(), 'loopback': console_local.record()},
            'gateway': ready.record(), 'issuer': discovery.record(), 'anonymous_session': session.record(),
            'authorization': {'status': login.status, 'issuer_path': AUTH, 'callback_path': '/v1/auth/callback',
                              'client_id': 'marty-ui', 'pkce': 'S256', 'tls': login.peer},
            'authenticated_application_exercised': False}


def _observe(installed_edge, model, signed, state):
    host, port = _installed_ingress(installed_edge, model)
    origin = 'https://' + host
    deadline = time.monotonic() + 120
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    aliases = (host, host[4:]) if host.startswith('www.') else (host,)
    try:
        dns = {name: _public_addresses(name) for name in aliases}

        def public(path):
            return _request(host, path, dns[host], 443, context, deadline)

        def local(path):
            return _request(host, path, ('127.0.0.1',), port, None, deadline)

        apex = None
        if len(aliases) == 2:
            name = aliases[1]
            response = _request(name, '/', dns[name], 443, context, deadline)
            require(response.status in REDIRECTS and response.header('Location') == origin + '/')
            apex = response.record()
        application = _application(public, local, origin, signed['application'])
        routes = (_split_routes(public, local, origin, signed['website'], signed['routes']) if state == 'split'
                  else _combined_routes(public, local, origin))
        require(dns == {name: _public_addresses(name) for name in aliases})
    except (OSError, http.client.HTTPException, UnicodeError):
        raise ValueError('Managed website ingress qualification failed') from None
    return {'origin': origin, 'dns': dns, 'apex_redirect': apex, 'routes': routes}, application


def run(config, choice, values, record, plan, status, phase, *, assets, gh, cosign, registry_config,
        authority_file, held):
    """Verify a completed edge phase without stranding ordinary probe failures."""
    require(phase in PHASES and status['classification'] == 'phase-boundary' and
            phase in status['permitted_record_phases'])
    state, prior_phase = PHASES[phase]
    require(state == status['model_state'] and status['completed_phases'][-1] == prior_phase)
    context, proposal, prior, check_routes = edge._prepare(config, choice, values, record, plan, status,
        prior_phase=prior_phase, current=state, target=state, create_routes=False, candidate_ready=state == 'split',
        assets=assets, gh=gh, cosign=cosign, registry_config=registry_config, authority_file=authority_file,
        held=held, include_http=True)
    initial = context.check(before_intent=True)
    installed = edge._edge(edge._owned(initial, context.project))
    configuration = edge._probe(context.docker, installed, proposal, state)
    require(configuration == prior['edge_configuration'])
    _command, model, _hashes = context.layouts[state]
    public_routes, application_handoffs = _observe(installed, model, proposal['http'], state)
    final = context.check(before_intent=True)
    owned = edge._owned(final, context.project)
    final_edge = edge._edge(owned)
    require(_installed_ingress(final_edge, model) == _installed_ingress(installed, model)
            and edge._probe(context.docker, final_edge, proposal, state) == configuration)
    if check_routes is not None:
        check_routes()
    attempt = Path(plan['attempt_directory'])
    started_evidence = stage._evidence(attempt / (phase + '-before.json'),
                                    edge._start_observation(plan, status, context, initial, configuration), held)
    completed_evidence = stage._evidence(attempt / (phase + '-after.json'), {
        'runtime_after': renewal.context_snapshot(owned), 'public_routes': public_routes,
        'application_handoffs': application_handoffs,
    }, held)
    started = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase,
                           event='started', evidence_sha256=started_evidence)
    completed = store.append(plan, expected_anchor_sha256=started['anchor_sha256'], phase=phase,
                             event='completed', evidence_sha256=completed_evidence)
    return {**completed, 'guard_sha256': status['guard_sha256']}
