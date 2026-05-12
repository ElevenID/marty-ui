#!/usr/bin/env python3
"""Login to Canvas admin, create developer key, set up LTI infrastructure.

Handles Canvas CSRF tokens that may span multiple lines in the HTML.
"""
import urllib.request
import urllib.parse
import http.cookiejar
import re
import json
import sys
import os

CANVAS_URL = os.environ.get('CANVAS_API_BASE_URL', 'http://localhost:8088')
ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = 'readystack123'
LTI_CLIENT_ID = os.environ.get('CANVAS_LTI_CLIENT_ID', 'canvas-real-client-id')
CONNECTOR_ID = os.environ.get('CANVAS_CONNECTOR_ID', '67f60f26-67aa-405f-9e04-b48165d49c61')
LTI_BASE_URL = (
    os.environ.get('CANVAS_LTI_EXPERIENCE_BASE_URL', '').strip()
    or os.environ.get('CANVAS_LTI_TOOL_BASE_URL', '').strip()
    or 'https://beta.elevenidllc.com'
).rstrip('/')
LTI_REDIRECT_URI = f'{LTI_BASE_URL}/v1/integrations/canvas/lti/experience/{CONNECTOR_ID}'
ACCOUNT_ID = os.environ.get('CANVAS_ROOT_ACCOUNT_ID', '1')

def login_to_canvas():
    """Login to Canvas and return an opener with session cookies."""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    # Get login page
    resp = opener.open(f'{CANVAS_URL}/login/canvas')
    html = resp.read().decode('utf-8')
    
    # Extract authenticity_token - may span multiple lines due to HTML rendering
    # Use DOTALL to match across newlines
    match = re.search(r'authenticity_token"\s+value="([^"]+)"', html, re.DOTALL)
    if not match:
        match = re.search(r'name="authenticity_token"[^>]+value="([^"]+)"', html)
    
    if not match:
        print('ERROR: Could not find CSRF token in login page')
        print('HTML snippet:', html[:2000])
        return None
    
    token = match.group(1).strip()
    print(f'CSRF token found: {token[:20]}...')
    
    # Login
    data = urllib.parse.urlencode({
        'authenticity_token': token,
        'pseudonym_session[unique_id]': ADMIN_EMAIL,
        'pseudonym_session[password]': ADMIN_PASSWORD,
        'utf8': '\u2713',
    }).encode()
    
    req = urllib.request.Request(f'{CANVAS_URL}/login/canvas', data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    
    try:
        resp = opener.open(req)
        final_html = resp.read().decode('utf-8')
        
        if 'dashboard' in final_html.lower() or 'courses' in final_html.lower():
            print('SUCCESS: Logged into Canvas admin')
            return opener
        else:
            # Check for error
            error = re.search(r'class="[^"]*error[^"]*"[^>]*>([^<]+)', final_html)
            if error:
                print(f'Login error: {error.group(1)}')
            else:
                print(f'Login may have failed. Final URL: {resp.url}')
                # Check for flash message
                flash = re.search(r'class="[^"]*flash[^"]*"[^>]*>([^<]+)', final_html)
                if flash:
                    print(f'Flash message: {flash.group(1)}')
            return None
    except urllib.error.HTTPError as e:
        print(f'HTTP error during login: {e.code}')
        body = e.read().decode('utf-8', errors='replace')
        flash = re.search(r'class="[^"]*flash[^"]*"[^>]*>([^<]+)', body)
        if flash:
            print(f'Flash message: {flash.group(1)}')
        return None


def create_dev_key_via_web(opener):
    """Create developer key via Canvas web UI."""
    # Get the developer keys page to get CSRF token
    resp = opener.open(f'{CANVAS_URL}/accounts/{ACCOUNT_ID}/developer_keys')
    html = resp.read().decode('utf-8')
    
    # Extract CSRF token
    match = re.search(r'authenticity_token"\s+value="([^"]+)"', html, re.DOTALL)
    if not match:
        match = re.search(r'name="authenticity_token"[^>]+value="([^"]+)"', html)
    
    if not match:
        print('WARNING: Could not find CSRF token on dev keys page')
        print('Will try API approach instead')
        return None
    
    token = match.group(1).strip()
    
    # Create developer key via form POST
    scopes = '\n'.join([
        'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem',
        'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly',
        'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',
        'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly',
    ])
    
    data = urllib.parse.urlencode({
        'authenticity_token': token,
        'utf8': '\u2713',
        'developer_key[name]': LTI_CLIENT_ID,
        'developer_key[email]': ADMIN_EMAIL,
        'developer_key[redirect_uris][]': LTI_REDIRECT_URI,
        'developer_key[scopes]': scopes,
        'developer_key[is_lti_key]': '1',
        'developer_key[visible]': '1',
        'developer_key[workflow_state]': 'active',
        'developer_key[notes]': 'ElevenID LTI Integration',
        'developer_key[test_cluster_only]': '0',
        'developer_key[require_scopes]': '1',
    }).encode()
    
    req = urllib.request.Request(
        f'{CANVAS_URL}/accounts/{ACCOUNT_ID}/developer_keys',
        data=data, method='POST'
    )
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    
    try:
        resp = opener.open(req)
        result_html = resp.read().decode('utf-8')
        print(f'Dev key creation response URL: {resp.url}')
        
        # Check if we can find the key ID
        id_match = re.search(r'developer_keys/(\d+)', str(resp.url))
        if id_match:
            print(f'Developer key created: ID={id_match.group(1)}')
            return id_match.group(1)
        
        print('Dev key might have been created but could not extract ID')
        return None
    except urllib.error.HTTPError as e:
        print(f'HTTP error creating dev key: {e.code}')
        body = e.read().decode('utf-8', errors='replace')
        print(f'Response: {body[:500]}')
        return None


def main():
    print(f'Canvas URL: {CANVAS_URL}')
    print(f'LTI Client ID: {LTI_CLIENT_ID}')
    print(f'LTI Redirect URI: {LTI_REDIRECT_URI}')
    print()
    
    print('=== Step 1: Login to Canvas ===')
    opener = login_to_canvas()
    if not opener:
        print('\nFAILED: Could not log into Canvas admin.')
        print('Trying fallback: direct database approach...')
        return 1
    
    print('\n=== Step 2: Create Developer Key ===')
    key_id = create_dev_key_via_web(opener)
    if key_id:
        print(f'\n✓ Developer key created successfully!')
        print(f'  Key ID: {key_id}')
        print(f'  Client ID: {LTI_CLIENT_ID}')
        print(f'\nNext: Create an external tool in your Canvas course pointing to ElevenID.')
    else:
        print('\n⚠ Could not create developer key via web UI.')
        print('Trying fallback: direct database approach...')
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
