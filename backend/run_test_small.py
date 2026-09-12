import requests, json, time, sys
API = 'http://127.0.0.1:8000/api'
cfg_path = '/tmp/test_small.cfg'
with open(cfg_path, 'rb') as f:
    files = {'file': ('test_small.cfg', f, 'text/plain')}
    resp = requests.post(f'{API}/scans/upload', files=files)
    resp.raise_for_status()
    data = resp.json()
    scan_id = data.get('id')
    print('UPLOAD_SCAN_ID', scan_id)
    # poll status
    while True:
        r = requests.get(f'{API}/scans/{scan_id}')
        r.raise_for_status()
        status = r.json().get('status')
        print('STATUS', status)
        if status in ('completed', 'review', 'blocked'):
            rem = requests.get(f'{API}/scans/{scan_id}/remediation')
            rem.raise_for_status()
            print('REMEDIATION', json.dumps(rem.json(), indent=2))
            break
        time.sleep(1)
