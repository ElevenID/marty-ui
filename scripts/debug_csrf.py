#!/usr/bin/env python3
"""Debug Canvas CSRF token extraction."""
import urllib.request
import re

resp = urllib.request.urlopen('http://localhost:8088/login/canvas')
html = resp.read().decode('utf-8')

# Find all authenticity tokens
pattern = r'authenticity_token.*?value="(.*?)"'
matches = list(re.finditer(pattern, html, re.DOTALL))
for i, m in enumerate(matches):
    raw = m.group(1)
    token = raw.replace('\n', '').replace('\r', '').strip()
    print(f'Token {i}: cleaned_len={len(token)}, has_newline={chr(10) in raw}')
    print(f'  First 30 chars: {token[:30]}')

# Also try a simple approach
print()
print('--- Simple regex approach ---')
simple_match = re.search(r'name="authenticity_token" value="([^"]+)"', html)
if simple_match:
    raw = simple_match.group(1)
    token = raw.replace('\n', '').replace('\r', '').strip()
    print(f'Token: {token[:40]}...')
    print(f'Length: {len(token)}')
    print(f'Has newline: {chr(10) in raw}')
