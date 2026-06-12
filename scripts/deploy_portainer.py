#!/usr/bin/env python3
import io, json, os, re, ssl, tarfile, time, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'system-tools-suite:latest'
CONTAINER = 'system-tools-suite'
VOLUME = 'system-tools-suite-data'
PORT = '10233/tcp'
ENDPOINT_ID = 2
HOST = '10.10.10.237'

def load_env():
    env={}
    for line in Path('/home/michaeld/.hermes/.env').read_text(errors='ignore').splitlines():
        if '=' in line and not line.strip().startswith('#'):
            k,v=line.split('=',1); env[k]=v.strip().strip('"').strip("'")
    return env

env = load_env()
BASE = env['PORTAINER_URL'].rstrip('/')
CTX = ssl._create_unverified_context()

def api(path, method='GET', data=None, headers=None, raw=False, timeout=60):
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data=json.dumps(data).encode()
    h={} if raw else {'Content-Type':'application/json'}
    if headers: h.update(headers)
    req=urllib.request.Request(BASE+path, data=data, method=method, headers=h)
    with urllib.request.urlopen(req, context=CTX, timeout=timeout) as resp:
        b=resp.read()
        if raw: return b.decode('utf-8','replace')
        return json.loads(b) if b else None

tok=api('/api/auth','POST',{'Username':env['PORTAINER_USERNAME'],'Password':env['PORTAINER_PASSWORD']})['jwt']
AUTH={'Authorization':'Bearer '+tok}

def docker(path, method='GET', data=None, headers=None, raw=False, timeout=60):
    h=dict(AUTH); h.update(headers or {})
    return api(f'/api/endpoints/{ENDPOINT_ID}/docker{path}', method, data, h, raw, timeout)

# build context
exclude_dirs={'.git','node_modules','.venv','dist','data','.pytest_cache'}
exclude_files={'.env'}
buf=io.BytesIO()
with tarfile.open(fileobj=buf, mode='w') as tar:
    for p in ROOT.rglob('*'):
        rel=p.relative_to(ROOT)
        if any(part in exclude_dirs for part in rel.parts):
            continue
        if p.name in exclude_files or p.name.endswith('.pyc'):
            continue
        tar.add(p, arcname=str(rel), recursive=False)
buf.seek(0)
print(f'context_bytes={len(buf.getvalue())}')

print('building image through Portainer Docker API')
qs=urllib.parse.urlencode({'t': IMAGE, 'rm': '1', 'forcerm': '1'})
stream=docker(f'/build?{qs}', 'POST', buf.getvalue(), {'Content-Type':'application/x-tar'}, raw=True, timeout=900)
lines=[]; errors=[]
for line in stream.splitlines():
    try:
        obj=json.loads(line)
        msg=obj.get('stream') or obj.get('status') or obj.get('error') or ''
        if obj.get('error'): errors.append(obj.get('error'))
        if msg.strip(): lines.append(msg.rstrip())
    except Exception:
        if line.strip(): lines.append(line.strip())
print('\n'.join(lines[-40:]))
if errors:
    raise SystemExit('build errors: '+ '; '.join(errors[-3:]))

# ensure volume
try:
    docker('/volumes/create', 'POST', {'Name': VOLUME}, timeout=60)
except Exception as e:
    print(f'volume create warning: {e}')

# remove existing
containers=docker('/containers/json?all=1', timeout=60)
for c in containers:
    names=[n.strip('/') for n in c.get('Names',[])]
    if CONTAINER in names:
        cid=c['Id']
        print(f'removing old container {cid[:12]} status={c.get("State")}')
        try: docker(f'/containers/{cid}/stop?t=20','POST',timeout=60)
        except Exception as e: print(f'stop warning: {e}')
        docker(f'/containers/{cid}?v=false&force=true','DELETE',timeout=60)

create={
    'Image': IMAGE,
    'Env': [
        'DATA_DIR=/data',
        'DIST_DIR=/app/dist',
        f"VIRUSTOTAL_API_KEY={env.get('VIRUSTOTAL_API_KEY','')}",
        f"ABUSEIPDB_API_KEY={env.get('ABUSEIPDB_API_KEY','')}",
        f"HIBP_API_KEY={env.get('HIBP_API_KEY','')}",
        f"URLSCAN_API_KEY={env.get('URLSCAN_API_KEY','')}",
    ],
    'ExposedPorts': {PORT:{}},
    'HostConfig': {
        'RestartPolicy': {'Name':'unless-stopped'},
        'PortBindings': {PORT:[{'HostIp':'0.0.0.0','HostPort':'10233'}]},
        'Mounts': [{'Type':'volume','Source':VOLUME,'Target':'/data'}],
    },
    'Healthcheck': {
        'Test': ['CMD','python','-c',"import urllib.request; urllib.request.urlopen('http://127.0.0.1:10233/api/health', timeout=5).read()"],
        'Interval': 30000000000,
        'Timeout': 10000000000,
        'Retries': 3,
        'StartPeriod': 20000000000,
    }
}
res=docker(f'/containers/create?name={urllib.parse.quote(CONTAINER)}','POST',create,timeout=60)
cid=res['Id']
docker(f'/containers/{cid}/start','POST',timeout=60)
print(f'started_container={cid[:12]}')

# poll health
for i in range(30):
    info=docker(f'/containers/{cid}/json',timeout=60)
    state=info.get('State',{})
    health=state.get('Health',{}).get('Status')
    print(f'poll={i} state={state.get("Status")} health={health}')
    if state.get('Status')=='running' and health in ('healthy', None):
        break
    time.sleep(5)

# app health from endpoint host
for i in range(20):
    try:
        with urllib.request.urlopen(f'http://{HOST}:10233/api/health', timeout=10) as resp:
            print('health_http='+resp.read().decode())
            break
    except Exception as e:
        last=e; time.sleep(3)
else:
    raise SystemExit(f'health failed: {last}')

with urllib.request.urlopen(f'http://{HOST}:10233/', timeout=20) as resp:
    html=resp.read(20000).decode('utf-8','replace')
asset_matches=re.findall(r'(?:src="|href=")(/assets/[^"\']+\.js)', html)
bundle_text=''
for asset in asset_matches[:5]:
    try:
        bundle_text += urllib.request.urlopen(f'http://{HOST}:10233{asset}', timeout=20).read().decode('utf-8','replace')[:300000]
    except Exception as e:
        print(f'asset warning {asset}: {e}')
probe = html + bundle_text
for term in ['System Tools Suite','MXToolbox','HaveIBeenPwned','URLScan.io','SSL Labs Grade','Email Header Analyzer','Case Manager']:
    print(f'live_has_{term.replace(" ", "_")}=' + str(term in probe))
blocked_terms = ['IT-'+'Tools','Roman '+'Numeral','BI'+'P39','UUID '+'Generator']
for forbidden in blocked_terms:
    print(f'live_forbidden_{forbidden.replace(" ", "_").replace("-", "_")}=' + str(forbidden in probe))
print('done')
