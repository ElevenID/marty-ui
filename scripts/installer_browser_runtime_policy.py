"""Reviewed Linux x64 runtime pins for the signed installer browser harness.

Archive identities come from the locked Playwright package, official Node
SHASUMS256, and the exact official Chrome-for-Testing release. The manifest
binds every extracted file; no runtime-supplied descriptor grants authority.
"""

MANIFEST_SHA256 = 'ba70f33e77e6139e1ae52d81c2839a887456a1ca7a4dae1852c8fe45956ff4ba'

POLICY = {'archives': {'chromium': {'destination': 'chrome-linux64',
                           'format': 'zip',
                           'members': None,
                           'name': 'chrome-linux64.zip',
                           'prefix': 'chrome-linux64/',
                           'sha256': 'ae8736ac28bc69278551500f219fc749575648263c43ec5990749eff43b9fcf8',
                           'size': 193282658,
                           'url': 'https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.34/linux64/chrome-linux64.zip'},
              'node': {'destination': 'node',
                       'format': 'tar.xz',
                       'members': ['bin/node', 'LICENSE'],
                       'name': 'node-v24.22.1-linux-x64.tar.xz',
                       'prefix': 'node-v24.22.1-linux-x64/',
                       'sha256': '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6',
                       'size': 32026916,
                       'url': 'https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz'},
              'playwright': {'destination': 'playwright-core',
                             'format': 'tar.gz',
                             'members': None,
                             'name': 'playwright-core-1.62.1.tgz',
                             'prefix': 'package/',
                             'sha256': '954be1e183d0ddb9748fe0d2d08b0b66a9210c74dd75c397aeb70303b9f08a00',
                             'size': 3070300,
                             'url': 'https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz'}},
 'executables': {'chromium': 'chrome-linux64/chrome',
                 'node': 'node/bin/node',
                 'playwright': 'playwright-core'},
 'platform': 'linux-x64',
 'schema': 'elevenid.installer-browser-runtime-policy/v1',
 'versions': {'chromium': '151.0.7922.34',
              'chromium_revision': '1234',
              'node': '24.22.1',
              'playwright': '1.62.1'}}
