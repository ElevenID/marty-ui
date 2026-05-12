#!/usr/bin/env python3
"""Login to Canvas and extract session cookie."""
import urllib.request
import urllib.parse
import http.cookiejar
import re
import sys

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Get login page and extract token
resp = opener.open('http://localhost:8088/login/canvas')
html = resp.read().decode('utf-8')
match = re.search(r'name="authenticity_token" value="([^"]+)"', html)
token = match.group(1) if match else ''
print(f'Token: {token[:20]}...')

# Login
data = urllib.parse.urlencode({
    'authenticity_token': token,
    'pseudonym_session[unique_id]': 'admin@example.com',
    'pseudonym_session[password]': 'readystack123'
}).encode()

req = urllib.request.Request('http://localhost:8088/login/canvas', data=data, method='POST')
resp = opener.open(req)
print(f'Login status: {resp.status}')
print(f'Final URL: {resp.url}')

# Check if we're on dashboard
final_html = resp.read().decode('utf-8')
if 'dashboard' in final_html.lower() or 'courses' in final_html.lower():
    print('SUCCESS: Logged in to Canvas!')
    
    # Save cookies
    cookie_file = r'c:\temp\canvas_cookies.txt'
    with open(cookie_file, 'w') as f:
        for cookie in cj:
            f.write(f'{cookie.name}={cookie.value}; domain={cookie.domain}; path={cookie.path}\n')
    print(f'Cookies saved to {cookie_file}')
else:
    print('Login might have failed.')
    if 'Invalid' in final_html:
        print('ERROR: Invalid credentials')
    elif 'login' in str(resp.url).lower():
        print('Still on login page')
    
    # Check for error messages
    error_match = re.search(r'class="flash_error_message[^"]*"[^>]*>([^<]+)', final_html)
    if error_match:
        print(f'Canvas error: {error_match.group(1)}')
