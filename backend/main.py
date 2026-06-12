import asyncio, base64, hashlib, ipaddress, json, os, re, socket, ssl, sqlite3, struct, subprocess, time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
import dns.reversename, dns.resolver
import httpx
try:
    import whois as whois_mod
except Exception:
    whois_mod=None
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

APP_NAME='System Tools Suite'
DATA_DIR=Path(os.getenv('DATA_DIR','/data')); DATA_DIR.mkdir(parents=True, exist_ok=True)
DB=DATA_DIR/'system_tools.db'
DIST=Path(__file__).resolve().parent.parent/'dist'
app=FastAPI(title=APP_NAME, version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

def db():
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row
    con.execute('create table if not exists cases(id integer primary key, title text not null, description text, created_at text not null)')
    con.execute('create table if not exists evidence(id integer primary key, case_id integer, name text, kind text, sha256 text, notes text, created_at text not null)')
    con.execute('create table if not exists notes(id integer primary key, case_id integer, body text, created_at text not null)')
    con.execute('create table if not exists timeline(id integer primary key, case_id integer, occurred_at text, event text, created_at text not null)')
    return con
@app.on_event('startup')
def startup():
    con=db(); con.commit(); con.close()

def now(): return datetime.now(timezone.utc).isoformat()
def valid_host(s):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}', s or ''): raise HTTPException(400,'Invalid host/IP format')
    return s
def run_cmd(args, timeout=12):
    try:
        p=subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return {'command':args,'returncode':p.returncode,'stdout':p.stdout[-12000:],'stderr':p.stderr[-4000:]}
    except FileNotFoundError: raise HTTPException(501, f'{args[0]} is not installed in the container')
    except subprocess.TimeoutExpired as e: return {'command':args,'timeout':True,'stdout':(e.stdout or '')[-12000:],'stderr':(e.stderr or '')[-4000:]}
async def fetch_json(url, **kw):
    async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as c:
        r=await c.get(url, **kw); return r

def dns_records(name, rtype):
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, rtype, lifetime=5)]
    except Exception as e: return [f'error: {e}']


SLUG_ALIASES={
    'whois-lookup':'whois','bgp-asn-lookup':'bgp-asn','smart-health':'smart-checker','virustotal-checker':'virustotal',
    'file-hash-verifier':'file-hash','http-header-inspector':'http-headers','website-response-time':'response-time',
    'network-address-translator':'nat-translator','blacklist-rbl-checker':'rbl-checker','reverse-dns-lookup':'reverse-dns'
}

def unparams(payload):
    if isinstance(payload, dict) and isinstance(payload.get('params'), dict):
        merged=dict(payload.get('params') or {})
        for k,v in payload.items():
            if k!='params': merged[k]=v
        return merged
    return payload or {}

def rdap_lookup(query):
    try:
        with httpx.Client(timeout=12, follow_redirects=True) as c:
            r=c.get('https://rdap.org/domain/'+query)
            if r.status_code==404:
                r=c.get('https://rdap.org/ip/'+query)
            data=r.json()
        ents=[]
        for e in data.get('entities',[]) or []:
            v=e.get('vcardArray',[None,[]])[1] if isinstance(e.get('vcardArray'),list) and len(e.get('vcardArray'))>1 else []
            vals={item[0]:item[3] for item in v if isinstance(item,list) and len(item)>=4}
            ents.append({'roles':e.get('roles'), 'name':vals.get('fn'), 'email':vals.get('email')})
        return {'source':'rdap.org','handle':data.get('handle'),'ldhName':data.get('ldhName'),'name':data.get('name'),'status':data.get('status'),'registrar':next((e.get('handle') for e in data.get('entities',[]) if 'registrar' in (e.get('roles') or [])),None),'events':data.get('events',[]),'nameservers':[n.get('ldhName') for n in data.get('nameservers',[])],'entities':ents,'raw':data}
    except Exception as e:
        return {'source':'rdap.org','error':str(e)}


def clean_domain(value):
    value=(value or '').strip().lower()
    value=re.sub(r'^https?://','',value).split('/')[0].split(':')[0].strip('.')
    if not re.fullmatch(r'[a-z0-9.-]{1,253}', value) or '..' in value:
        raise HTTPException(400,'Invalid domain format')
    return value

def resolver_lookup(name, rtype, nameserver=None, timeout=5):
    res=dns.resolver.Resolver()
    res.lifetime=timeout; res.timeout=timeout
    if nameserver: res.nameservers=[nameserver]
    try:
        return {'ok':True,'records':[r.to_text() for r in res.resolve(name, rtype)]}
    except Exception as e:
        return {'ok':False,'records':[],'error':str(e)}

def dnsbl_lookup_ip(ip, zones=None):
    zones=zones or ['zen.spamhaus.org','bl.spamcop.net','b.barracudacentral.org','dnsbl.sorbs.net']
    try:
        ip_obj=ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            return {z:{'listed':False,'note':'IPv6 DNSBL check skipped'} for z in zones}
    except Exception as e:
        return {'error':str(e)}
    rev='.'.join(reversed(str(ip).split('.')))
    out={}
    for z in zones:
        q=f'{rev}.{z}'
        ans=resolver_lookup(q,'A',timeout=4)
        out[z]={'listed':ans['ok'],'query':q,'records':ans.get('records',[]),'error':ans.get('error') if not ans['ok'] else None}
    return out

async def hibp_breaches(email):
    key=os.getenv('HIBP_API_KEY')
    if not key:
        return {'configured':False,'email':email,'message':'HIBP_API_KEY is not configured. Set it in the container environment to enable HaveIBeenPwned API v3 checks.'}
    headers={'hibp-api-key':key,'user-agent':'MRDTech-System-Tools-Suite'}
    url='https://haveibeenpwned.com/api/v3/breachedaccount/'+urllib_quote(email)+'?truncateResponse=false'
    async with httpx.AsyncClient(timeout=20) as c:
        r=await c.get(url, headers=headers)
    if r.status_code==404:
        return {'configured':True,'email':email,'breached':False,'breaches':[]}
    if r.status_code in (401,403):
        return {'configured':True,'email':email,'error':'HIBP rejected the API key or request','status_code':r.status_code}
    if r.status_code==429:
        return {'configured':True,'email':email,'error':'HIBP rate limit reached','status_code':429,'retry_after':r.headers.get('retry-after')}
    if r.status_code>=400:
        return {'configured':True,'email':email,'error':r.text[:500],'status_code':r.status_code}
    data=r.json()
    return {'configured':True,'email':email,'breached':bool(data),'count':len(data),'breaches':data}

def urllib_quote(value):
    from urllib.parse import quote
    return quote(value, safe='')

async def urlscan_submit(url):
    key=os.getenv('URLSCAN_API_KEY')
    if not key:
        return {'configured':False,'url':url,'message':'URLSCAN_API_KEY is not configured. Set it in the container environment to enable URLScan.io submissions.'}
    if not re.match(r'^https?://', url or ''):
        raise HTTPException(400,'URL must start with http:// or https://')
    headers={'API-Key':key,'Content-Type':'application/json'}
    async with httpx.AsyncClient(timeout=20) as c:
        r=await c.post('https://urlscan.io/api/v1/scan/', headers=headers, json={'url':url,'visibility':'private'})
        if r.status_code>=400:
            return {'configured':True,'url':url,'status_code':r.status_code,'error':r.text[:1000]}
        submit=r.json(); api=submit.get('api') or submit.get('result')
        result=None
        if api:
            for _ in range(6):
                await asyncio.sleep(5)
                rr=await c.get(api)
                if rr.status_code==200:
                    result=rr.json(); break
                if rr.status_code not in (404,429):
                    result={'status_code':rr.status_code,'error':rr.text[:500]}; break
    if not result:
        return {'configured':True,'url':url,'submitted':submit,'pending':True,'message':'Scan submitted. Result was not ready during the short polling window.'}
    page=result.get('page') or {}; verdicts=result.get('verdicts') or {}; lists=result.get('lists') or {}; meta=result.get('meta') or {}
    tech=[t.get('name') if isinstance(t,dict) else str(t) for t in (lists.get('technologies') or [])]
    return {'configured':True,'url':url,'submitted':submit,'verdicts':verdicts,'page':{'url':page.get('url'),'domain':page.get('domain'),'ip':page.get('ip'),'asn':page.get('asn'),'asnname':page.get('asnname'),'country':page.get('country'),'server':page.get('server')},'technologies':tech,'ips':lists.get('ips',[]),'domains':lists.get('domains',[]),'certificates':lists.get('certificates',[]),'meta':meta}

async def ssllabs_grade(host):
    host=clean_domain(host)
    params={'host':host,'publish':'off','all':'done','fromCache':'on','ignoreMismatch':'on'}
    async with httpx.AsyncClient(timeout=20) as c:
        data=None
        for _ in range(4):
            r=await c.get('https://api.ssllabs.com/api/v3/analyze', params=params)
            if r.status_code>=400:
                return {'host':host,'status_code':r.status_code,'error':r.text[:1000]}
            data=r.json()
            if data.get('status') in ('READY','ERROR'):
                break
            params['startNew']='off'
            await asyncio.sleep(8)
    endpoints=[]
    for e in data.get('endpoints',[]) or []:
        endpoints.append({'ipAddress':e.get('ipAddress'),'serverName':e.get('serverName'),'statusMessage':e.get('statusMessage'),'grade':e.get('grade'),'gradeTrustIgnored':e.get('gradeTrustIgnored'),'hasWarnings':e.get('hasWarnings')})
    return {'host':host,'status':data.get('status'),'statusMessage':data.get('statusMessage'),'testTime':data.get('testTime'),'endpoints':endpoints,'summary_grade':next((e.get('grade') for e in endpoints if e.get('grade')),None)}


def parse_ports(spec):
    out=[]
    for part in str(spec or '').split(','):
        part=part.strip()
        if not part: continue
        if '-' in part:
            a,b=part.split('-',1); out.extend(range(int(a),int(b)+1))
        else: out.append(int(part))
    return sorted(set(p for p in out if 1<=p<=65535))[:2000]

def ssl_check(host, port=443):
    ctx=ssl.create_default_context()
    with socket.create_connection((host,int(port)),timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der=ssock.getpeercert(binary_form=True)
    cert=x509.load_der_x509_certificate(der)
    fp=cert.fingerprint(hashes.SHA256()).hex()
    sans=[]
    try: sans=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception: pass
    return {'subject':cert.subject.rfc4514_string(),'issuer':cert.issuer.rfc4514_string(),'not_before':cert.not_valid_before_utc.isoformat(),'not_after':cert.not_valid_after_utc.isoformat(),'serial':str(cert.serial_number),'sans':sans,'sha256_fingerprint':':'.join(fp[i:i+2] for i in range(0,len(fp),2))}

def scan_port(host, port):
    s=socket.socket(); s.settimeout(.8)
    try: return 'open' if s.connect_ex((host,port))==0 else 'closed'
    except socket.timeout: return 'filtered'
    except Exception as e: return f'error: {e}'
    finally: s.close()

def magic(mac,broadcast='255.255.255.255',port=9):
    clean=re.sub('[^0-9A-Fa-f]','',mac)
    if len(clean)!=12: raise HTTPException(400,'Invalid MAC address')
    pkt=b'\xff'*6+bytes.fromhex(clean)*16
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); s.sendto(pkt,(broadcast,int(port))); s.close()
    return {'sent':True,'mac':mac,'broadcast':broadcast,'port':port}

def smart_parse(text):
    def find(p):
        m=re.search(p,text,re.I); return m.group(1).strip() if m else None
    return {'health':find(r'(?:SMART overall-health self-assessment test result|SMART Health Status):\s*(.+)'), 'temperature_c':find(r'Temperature[^\n]*?\s(\d+)\s*(?:Celsius|\(Min|$)'), 'reallocated_sectors':find(r'Reallocated_Sector_Ct\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)'), 'power_on_hours':find(r'Power_On_Hours\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)'), 'raw_excerpt':text[:4000]}

def classify(i):
    i=i.strip();
    if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}',i): return 'hash'
    try: ipaddress.ip_address(i); return 'ip'
    except Exception: pass
    if i.startswith('http://') or i.startswith('https://'): return 'url'
    return 'domain'

@app.get('/api/health')
def health(): return {'app':APP_NAME,'status':'ok','data_dir':str(DATA_DIR),'database':str(DB)}

@app.post('/api/tools/{slug}')
@app.post('/api/tools/{slug}/run')
async def run_tool(slug:str, payload:dict[str,Any]):
    slug=SLUG_ALIASES.get(slug, slug)
    payload=unparams(payload)
    if slug=='ping-traceroute':
        target=valid_host(payload.get('target','')); mode=payload.get('mode','ping')
        count=str(max(1,min(10,int(payload.get('count') or 4)))); hops=str(max(1,min(64,int(payload.get('max_hops') or 20))))
        return run_cmd(['traceroute','-m',hops,target],20) if mode=='traceroute' else run_cmd(['ping','-c',count,'-W','2',target],12)
    if slug=='port-scanner':
        host=valid_host(payload.get('host',''))
        if payload.get('ports'):
            ports=parse_ports(payload.get('ports'))
            if len(ports)>2000: raise HTTPException(400,'Port list too large')
        else:
            start=max(1,int(payload.get('start_port',1))); end=min(65535,int(payload.get('end_port',1024)))
            if end<start or end-start>2000: raise HTTPException(400,'Port range must be 1-2000 ports')
            ports=list(range(start,end+1))
        timeout=float(payload.get('timeout') or .8)
        async def scan(p):
            s=socket.socket(); s.settimeout(timeout)
            try: return 'open' if s.connect_ex((host,p))==0 else 'closed'
            except socket.timeout: return 'filtered'
            except Exception as e: return f'error: {e}'
            finally: s.close()
        results=await asyncio.gather(*[asyncio.to_thread(lambda p=p: asyncio.run(scan(p))) for p in ports])
        return {'host':host,'ports':dict(zip(map(str,ports),results)),'open':[p for p,s in zip(ports,results) if s=='open']}
    if slug=='dns-lookup':
        domain=valid_host(payload.get('domain') or payload.get('target','')); rt=(payload.get('record_type') or payload.get('rtype') or 'A').upper(); types=['A','AAAA','MX','TXT','PTR','CNAME','NS'] if rt=='ALL' else [rt]
        return {t:dns_records(domain,t) for t in types}
    if slug=='reverse-dns':
        rev=dns.reversename.from_address(payload.get('ip','')); return {'ip':payload.get('ip'),'ptr':dns_records(str(rev),'PTR')}
    if slug=='whois':
        domain=valid_host(payload.get('domain') or payload.get('target') or '')
        result={}
        if whois_mod:
            try:
                result=json.loads(json.dumps(whois_mod.whois(domain), default=str))
            except Exception as e:
                result={'python_whois_error':str(e)}
        # python-whois frequently returns mostly null. RDAP is less theatrical.
        useful=[v for v in result.values() if v] if isinstance(result,dict) else []
        if not useful or len(useful)<3:
            rdap=rdap_lookup(domain); rdap['python_whois']=result; return rdap
        result['source']='python-whois'; return result
    if slug=='ssl-checker': return ssl_check(valid_host(payload.get('host','')), int(payload.get('port',443)))
    if slug=='bgp-asn':
        asn=str(payload.get('asn') or payload.get('query','')).upper().replace('AS','')
        try:
            r=await fetch_json(f'https://api.bgpview.io/asn/{asn}'); data=r.json(); prefixes=await fetch_json(f'https://api.bgpview.io/asn/{asn}/prefixes')
            return {'asn':asn,'details':data.get('data'), 'prefixes':prefixes.json().get('data',{})}
        except Exception as e:
            try:
                txt=dns_records(f'AS{asn}.asn.cymru.com','TXT')
                parts=[x.strip('\"') for x in txt][0].split('|') if txt and not str(txt[0]).startswith('error:') else []
                details={'asn':asn,'country':parts[1].strip() if len(parts)>1 else None,'registry':parts[2].strip() if len(parts)>2 else None,'allocated':parts[3].strip() if len(parts)>3 else None,'name':parts[4].strip() if len(parts)>4 else None,'source':'Team Cymru DNS fallback'}
                return {'asn':asn,'details':details,'prefixes':{},'warning':f'BGPView unavailable: {type(e).__name__}: {e}'}
            except Exception as ee:
                return {'asn':asn,'details':{'asn':asn,'source':'fallback unavailable'},'prefixes':{},'warning':f'BGP lookup failed: {type(e).__name__}: {e}; fallback failed: {ee}'}
    if slug=='ip-geolocation':
        ip=payload.get('ip','')
        try:
            r=await fetch_json(f'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query')
            return r.json()
        except Exception as e:
            return {'query':ip,'status':'error','message':f'IP geolocation lookup failed: {type(e).__name__}: {e}'}
    if slug=='wake-on-lan': return magic(payload.get('mac',''), payload.get('broadcast','255.255.255.255'), payload.get('port',9))
    if slug=='http-headers':
        r=await fetch_json(payload.get('url','')); return {'url':str(r.url),'status_code':r.status_code,'headers':dict(r.headers)}
    if slug=='response-time':
        t=time.perf_counter(); r=await fetch_json(payload.get('url','')); ms=(time.perf_counter()-t)*1000
        return {'url':str(r.url),'status_code':r.status_code,'response_time_ms':round(ms,2)}
    if slug=='nat-translator':
        priv=ipaddress.ip_network(payload.get('private_cidr'), strict=False); pub=ipaddress.ip_network(payload.get('public_cidr'), strict=False); addr=ipaddress.ip_address(payload.get('address'))
        if priv.num_addresses!=pub.num_addresses: raise HTTPException(400,'CIDR ranges must be same size for deterministic one-to-one NAT')
        offset=int(addr)-int(priv.network_address); return {'private':str(addr),'public':str(ipaddress.ip_address(int(pub.network_address)+offset)),'offset':offset}
    if slug=='rbl-checker':
        ip=ipaddress.ip_address(payload.get('ip')); rev='.'.join(reversed(str(ip).split('.'))); zones=['zen.spamhaus.org','bl.spamcop.net','b.barracudacentral.org','dnsbl.sorbs.net']
        return {z:dns_records(f'{rev}.{z}','A') for z in zones}
    if slug=='smart-checker':
        sample=payload.get('sample') or ''
        text=sample if sample.strip() else run_cmd(['smartctl','-a',payload.get('device','/dev/sda')],15).get('stdout','')
        return smart_parse(text)
    if slug=='certificate-decoder':
        pem=payload.get('pem','')
        if 'BEGIN CERTIFICATE' not in pem: raise HTTPException(400,'Paste a PEM certificate')
        cert=x509.load_pem_x509_certificate(pem.encode())
        fp=cert.fingerprint(hashes.SHA256()).hex()
        return {'subject':cert.subject.rfc4514_string(),'issuer':cert.issuer.rfc4514_string(),'not_before':cert.not_valid_before_utc.isoformat(),'not_after':cert.not_valid_after_utc.isoformat(),'serial':str(cert.serial_number),'sha256_fingerprint':':'.join(fp[i:i+2] for i in range(0,len(fp),2))}
    if slug=='log-analyzer':
        text=payload.get('log_text') or payload.get('content') or ''
        pats=['failed password','invalid user','sudo','segfault','malware','powershell','encodedcommand','mimikatz','ransom','denied']
        hits=[{'line':n,'text':line[:500]} for n,line in enumerate(text.splitlines(),1) if any(p in line.lower() for p in pats)]
        return {'lines':text.count('\n')+1 if text else 0,'suspicious_count':len(hits),'hits':hits[:300]}
    if slug=='mxtoolbox':
        domain=clean_domain(payload.get('domain') or payload.get('target') or '')
        mx=resolver_lookup(domain,'MX')
        spf=[r for r in resolver_lookup(domain,'TXT').get('records',[]) if 'v=spf1' in r.lower()]
        dmarc=resolver_lookup('_dmarc.'+domain,'TXT')
        dmarc_records=[r for r in dmarc.get('records',[]) if 'v=dmarc1' in r.lower()]
        mx_hosts=[]
        for rec in mx.get('records',[]):
            parts=rec.split()
            host=parts[-1].rstrip('.') if parts else rec.rstrip('.')
            if host in ('', '.'):
                mx_hosts.append({'host':host,'ips':[],'note':'Null MX: domain does not accept email'})
                continue
            ips=[]
            for rt in ('A','AAAA'):
                ips.extend(resolver_lookup(host,rt).get('records',[]))
            mx_hosts.append({'host':host,'ips':ips})
        blacklist={}
        for host in mx_hosts:
            for ip in host.get('ips',[]):
                if ':' not in ip:
                    blacklist[ip]=dnsbl_lookup_ip(ip)
        return {'domain':domain,'mx':mx,'mx_hosts':mx_hosts,'spf':{'present':bool(spf),'records':spf},'dmarc':{'present':bool(dmarc_records),'records':dmarc_records,'lookup':dmarc},'blacklist':blacklist}
    if slug=='dns-propagation':
        domain=clean_domain(payload.get('domain') or payload.get('target') or '')
        rtype=(payload.get('record_type') or 'A').upper()
        resolvers={'Cloudflare':'1.1.1.1','Google':'8.8.8.8','Quad9':'9.9.9.9','OpenDNS':'208.67.222.222','AdGuard':'94.140.14.14','ControlD':'76.76.2.0','DNS.WATCH':'84.200.69.80'}
        results={name:resolver_lookup(domain,rtype,ip,timeout=5) for name,ip in resolvers.items()}
        normalized=['|'.join(sorted(v.get('records',[]))) for v in results.values() if v.get('ok')]
        consensus=max(set(normalized), key=normalized.count) if normalized else None
        return {'domain':domain,'record_type':rtype,'resolvers':results,'consensus':consensus,'consistent':len(set(normalized))<=1 if normalized else False}
    if slug=='hibp-check':
        email=(payload.get('email') or '').strip()
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email): raise HTTPException(400,'Invalid email address')
        return await hibp_breaches(email)
    if slug=='urlscan':
        return await urlscan_submit((payload.get('url') or '').strip())
    if slug=='ssl-labs-grade':
        return await ssllabs_grade(payload.get('domain') or payload.get('host') or '')
    if slug=='cve-lookup':
        q=payload.get('query',''); url='https://services.nvd.nist.gov/rest/json/cves/2.0'
        params={'cveId':q} if q.upper().startswith('CVE-') else {'keywordSearch':q}
        try:
            r=await fetch_json(url, params=params); data=r.json(); return {'total':data.get('totalResults'), 'items':data.get('vulnerabilities',[])[:10]}
        except Exception as e:
            return {'query':q,'error':f'NVD lookup failed: {type(e).__name__}: {e}','total':0,'items':[]}
    if slug=='virustotal':
        key=os.getenv('VIRUSTOTAL_API_KEY'); ind=payload.get('indicator',''); typ=classify(ind)
        if not key: return {'configured':False,'indicator':ind,'type':typ,'message':'VIRUSTOTAL_API_KEY not set'}
        base={'ip':'ip_addresses','domain':'domains','hash':'files','url':'urls'}[typ]; val=base64.urlsafe_b64encode(ind.encode()).decode().strip('=') if typ=='url' else ind
        async with httpx.AsyncClient(timeout=20) as c: r=await c.get(f'https://www.virustotal.com/api/v3/{base}/{val}',headers={'x-apikey':key})
        return {'status_code':r.status_code,'result':r.json()}
    if slug=='ioc-scanner':
        items=[x.strip() for x in (payload.get('items') or payload.get('content') or '').splitlines() if x.strip()][:100]
        return {'count':len(items),'items':[{'indicator':i,'type':classify(i),'virustotal_configured':bool(os.getenv('VIRUSTOTAL_API_KEY')),'abuseipdb_configured':bool(os.getenv('ABUSEIPDB_API_KEY'))} for i in items]}
    if slug=='unifi-client':
        return {'message':'UniFi lookup requires controller-specific API auth/session support. Supplied values were not persisted.', 'query':payload.get('query'), 'controller_url':payload.get('controller_url')}
    if slug=='case-manager':
        action=(payload.get('case_action') or 'create').lower(); con=db()
        try:
            if action=='list':
                cases=[dict(r) for r in con.execute('select * from cases order by id desc').fetchall()]
                return {'cases':cases}
            if action=='create':
                cur=con.execute('insert into cases(title,description,created_at) values(?,?,?)',(payload.get('case_title','Untitled'),payload.get('case_description',''),now())); con.commit()
                return dict(con.execute('select * from cases where id=?',(cur.lastrowid,)).fetchone())
            cid=int(payload.get('case_id'))
            if action=='add_note':
                cur=con.execute('insert into notes(case_id,body,created_at) values(?,?,?)',(cid,payload.get('note_body',''),now())); con.commit(); return dict(con.execute('select * from notes where id=?',(cur.lastrowid,)).fetchone())
            if action=='add_evidence':
                cur=con.execute('insert into evidence(case_id,name,kind,sha256,notes,created_at) values(?,?,?,?,?,?)',(cid,payload.get('evidence_name','Evidence'),payload.get('evidence_kind','unknown'),payload.get('evidence_sha256',''),payload.get('case_description',''),now())); con.commit(); return dict(con.execute('select * from evidence where id=?',(cur.lastrowid,)).fetchone())
            if action=='add_timeline':
                cur=con.execute('insert into timeline(case_id,occurred_at,event,created_at) values(?,?,?,?)',(cid,payload.get('occurred_at') or now(),payload.get('timeline_event',''),now())); con.commit(); return dict(con.execute('select * from timeline where id=?',(cur.lastrowid,)).fetchone())
            if action=='export':
                case=con.execute('select * from cases where id=?',(cid,)).fetchone()
                if not case: raise HTTPException(404,'Case not found')
                bundle={'case':dict(case),'evidence':[dict(r) for r in con.execute('select * from evidence where case_id=?',(cid,)).fetchall()],'notes':[dict(r) for r in con.execute('select * from notes where case_id=?',(cid,)).fetchall()],'timeline':[dict(r) for r in con.execute('select * from timeline where case_id=? order by occurred_at',(cid,)).fetchall()],'exported_at':now(),'pdf_note':'Use browser print-to-PDF from this JSON export for a static case packet.'}
                return bundle
            if action=='delete':
                for table in ('evidence','notes','timeline'): con.execute(f'delete from {table} where case_id=?',(cid,))
                con.execute('delete from cases where id=?',(cid,)); con.commit(); return {'deleted_case_id':cid}
            raise HTTPException(400,'Unsupported case_action')
        finally:
            con.close()
    raise HTTPException(404,'Tool not implemented')

@app.post('/api/tools/{slug}/file')
@app.post('/api/tools/{slug}/upload')
async def upload_tool(slug:str, file:UploadFile=File(...)):
    slug=SLUG_ALIASES.get(slug, slug)
    data=await file.read(25*1024*1024)
    if slug=='file-hash': return {'filename':file.filename,'size':len(data),'md5':hashlib.md5(data).hexdigest(),'sha256':hashlib.sha256(data).hexdigest(),'sha512':hashlib.sha512(data).hexdigest()}
    if slug=='string-finder':
        strings=re.findall(rb'[ -~]{4,}',data)[:1000]; return {'filename':file.filename,'count':len(strings),'strings':[s.decode('utf-8','replace') for s in strings]}
    if slug=='log-analyzer':
        text=data.decode('utf-8','replace'); pats=['failed password','invalid user','sudo','segfault','malware','powershell','encodedcommand','mimikatz','ransom','denied']; hits=[]
        for n,line in enumerate(text.splitlines(),1):
            if any(p in line.lower() for p in pats): hits.append({'line':n,'text':line[:500]})
        return {'filename':file.filename,'lines':text.count('\n')+1,'suspicious_count':len(hits),'hits':hits[:300]}
    if slug=='metadata-extractor':
        meta={'filename':file.filename,'size':len(data),'content_type':file.content_type}
        if (file.filename or '').lower().endswith('.pdf'):
            from io import BytesIO
            from pypdf import PdfReader
            r=PdfReader(BytesIO(data)); meta.update({'pages':len(r.pages),'pdf_metadata':{str(k):str(v) for k,v in (r.metadata or {}).items()}})
        elif (file.content_type or '').startswith('image/'):
            from io import BytesIO
            from PIL import Image
            im=Image.open(BytesIO(data)); meta.update({'format':im.format,'size_px':im.size,'exif':{str(k):str(v) for k,v in im.getexif().items()}})
        else: meta['note']='Basic metadata only for this type.'
        return meta
    raise HTTPException(404,'Upload tool not implemented')

@app.get('/api/cases')
def cases():
    con=db(); rows=[dict(r) for r in con.execute('select * from cases order by id desc').fetchall()]; con.close(); return {'cases': rows}

@app.post('/api/cases')
def create_case(payload:dict[str,Any]):
    con=db()
    try:
        cur=con.execute('insert into cases(title,description,created_at) values(?,?,?)',(payload.get('title') or 'Untitled', payload.get('summary') or payload.get('description') or '', now())); con.commit()
        return dict(con.execute('select * from cases where id=?',(cur.lastrowid,)).fetchone())
    finally:
        con.close()

if DIST.exists():
    app.mount('/assets', StaticFiles(directory=DIST/'assets'), name='assets')
    @app.get('/{path:path}')
    def spa(path:str):
        target=DIST/path
        if path and target.exists() and target.is_file(): return FileResponse(target)
        return FileResponse(DIST/'index.html')
else:
    @app.get('/')
    def no_dist(): return PlainTextResponse('Frontend dist not built yet')
