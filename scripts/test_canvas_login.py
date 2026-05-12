#!/usr/bin/env python3
"""Test Canvas login WITHOUT authenticity_token to bypass CSRF check."""
import urllib.request, urllib.parse, http.cookiejar, re

cj = http.cookiejar.CookieJar()
o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# First GET login page to get session cookie (needed for CSRF bypass)
r = o.open('http://localhost:8088/login/canvas')
h = r.read().decode('utf-8')
print(f'Got login page: {len(h)} bytes')

# Login WITHOUT authenticity_token 
d = urllib.parse.urlencode({
    'pseudonym_session[unique_id]': 'admin@example.com',
    'pseudonym_session[password]': 'readystack123',
}).encode()

req = urllib.request.Request('http://localhost:8088/login/canvas', data=d, method='POST')
req.add_header('Content-Type', 'application/x-www-form-urlencoded')
req.add_header('Referer', 'http://localhost:8088/login/canvas')

try:
    r2 = o.open(req)
    final = r2.read().decode('utf-8')
    print(f'Status: {r2.status}')
    print(f'Final URL: {r2.url}')
    
    if 'dashboard' in final.lower():
        print('SUCCESS: Logged into Canvas!')
    elif 'login' in str(r2.url).lower():
        print('FAILED: Still on login page')
        flash = re.search(r'class="[^"]*flash[^"]*"[^>]*>([^<]+)', final)
        if flash: print(f'Flash: {flash.group(1)}')
    else:
        print(f'Redirected to: {r2.url}')
    
    title = re.search(r'<title>([^<]+)</title>', final)
    print(f'Title: {title.group(1) if title else "N/A"}')
    
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', errors='replace')
    print(f'HTTP {e.code}')
    flash = re.search(r'class="[^"]*flash[^"]*"[^>]*>([^<]+)', body)
    if flash: print(f'Flash: {flash.group(1)}')
    # Also check for any error message
    error = re.search(r'class="[^"]*error[^"]*"[^>]*>([^<]+)', body)
    if error: print(f'Error: {error.group(1)}')
    
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', errors='replace')
    print(f'HTTP {e.code}: {body[:500]}')
