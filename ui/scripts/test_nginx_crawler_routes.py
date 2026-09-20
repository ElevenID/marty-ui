"""Real local Nginx regression test; requires nginx, Python 3, and no network access.

Run: python3 ui/scripts/test_nginx_crawler_routes.py
Only listen/root/upstream addresses are substituted in the repository configs.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

UI_ROOT = Path(__file__).resolve().parents[1]
CRAWLER_FILES = {
    'robots.txt': ('text/plain', 'User-agent: *\nDisallow: /console\n'),
    'sitemap.xml': ('application/xml', '<?xml version="1.0"?><urlset/>'),
    'sitemap-index.xml': ('application/xml', '<?xml version="1.0"?><sitemapindex/>'),
    'sitemap-0.xml': ('application/xml', '<?xml version="1.0"?><urlset/>'),
}


class GatewayFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401 if self.path.startswith('/v1/') else 503)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"fixture":"gateway"}')

    def log_message(self, *_args):
        pass


class CrawlerContract:
    @classmethod
    def setUpClass(cls):
        nginx = shutil.which('nginx')
        if not nginx:
            raise RuntimeError('nginx is required; this regression must not silently skip')
        temp = tempfile.TemporaryDirectory(prefix='marty-crawler-')
        cls.addClassCleanup(temp.cleanup)
        root = Path(temp.name)
        cls.html = root / 'html'
        cls.html.mkdir()
        (root / 'logs').mkdir()
        (cls.html / 'console').mkdir()
        (cls.html / 'demos' / 'manifests').mkdir(parents=True)
        (cls.html / 'index.html').write_text('<h1>marketing fixture</h1>')
        (cls.html / 'console' / 'index.html').write_text('<h1>console fixture</h1>')
        for name, (_, body) in CRAWLER_FILES.items():
            (cls.html / name).write_text(body)
        gateway = ThreadingHTTPServer(('127.0.0.1', 0), GatewayFixture)
        cls.addClassCleanup(gateway.server_close)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        cls.addClassCleanup(gateway.shutdown)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        server = (UI_ROOT / cls.config_name).read_text()
        server = server.replace('listen 80;', f'listen 127.0.0.1:{cls.port};')
        server = server.replace('/usr/share/nginx/html', str(cls.html))
        server = server.replace('gateway:8000', f'127.0.0.1:{gateway.server_port}')
        config = root / 'nginx.conf'
        config.write_text(
            'daemon off; master_process off; worker_processes 1;\n'
            f'pid {root}/nginx.pid; error_log {root}/error.log;\n'
            'events {}\nhttp { access_log off;\n'
            'types { text/html html; text/plain txt; application/xml xml; }\n'
            + server + '\n}\n'
        )
        command = [nginx, '-p', str(root) + '/', '-c', str(config)]
        subprocess.run(command + ['-t'], check=True, capture_output=True)
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        cls.addClassCleanup(stop)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError((root / 'error.log').read_text())
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)
        raise RuntimeError('Nginx did not start within the bounded startup wait')

    def request(self, path, method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            connection.request(method, path, headers={'User-Agent': 'Googlebot'})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def test_present_files_are_not_html_or_redirects(self):
        for name, (content_type, body) in CRAWLER_FILES.items():
            for suffix in ('', '?check=1'):
                with self.subTest(path=name + suffix):
                    status, headers, actual = self.request('/' + name + suffix)
                    self.assertEqual(status, 200)
                    self.assertEqual(headers['Content-Type'], content_type)
                    self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                    self.assertEqual(headers['X-Frame-Options'], 'SAMEORIGIN')
                    self.assertNotIn('Location', headers)
                    self.assertEqual(actual, body)
                    self.assertEqual(self.request('/' + name + suffix, 'HEAD')[0], 200)

    def test_missing_files_are_404_not_spa_success(self):
        for name, (_, body) in CRAWLER_FILES.items():
            with self.subTest(path=name):
                (self.html / name).unlink()
                try:
                    status, _, actual = self.request('/' + name + '?check=1')
                    self.assertEqual(status, 404)
                    self.assertNotIn('marketing fixture', actual)
                    self.assertEqual(self.request('/' + name, 'HEAD')[0], 404)
                finally:
                    (self.html / name).write_text(body)

    def test_marketing_and_console_routes_are_preserved(self):
        for path in ('/', '/product', '/demos', '/demos/'):
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertIn('marketing fixture', body)
        for path in ('/console', '/console/credentials'):
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertIn('console fixture', body)


class ProductionCrawlerTests(CrawlerContract, unittest.TestCase):
    config_name = 'nginx.prod.conf'

    def test_gateway_authentication_and_failure_statuses_are_preserved(self):
        for path, expected in (('/v1/private-fixture', 401), ('/api/failure-fixture', 503)):
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(status, expected)
                self.assertIn('gateway', body)


class StaticCrawlerTests(CrawlerContract, unittest.TestCase):
    config_name = 'nginx.spa.conf'

    def test_unproxied_readiness_stays_unavailable(self):
        for path in ('/ready', '/health/ready'):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 503)


if __name__ == '__main__':
    unittest.main(verbosity=2)
