<script setup lang="ts">
import { computed, reactive, ref } from 'vue'

type Field = { name: string; label: string; type?: 'text' | 'textarea' | 'number' | 'select' | 'file'; placeholder?: string; options?: string[]; value?: string }
type Tool = { slug: string; title: string; category: string; description: string; mode: 'frontend' | 'backend' | 'file' | 'case'; fields: Field[] }

const categories = ['Network Tools', 'System Tools', 'Security Tools', 'DevOps Tools', 'UniFi Tools', 'Forensic Tools']

const tools: Tool[] = [
  { slug:'ping-traceroute', title:'Ping / Traceroute', category:'Network Tools', description:'Run bounded reachability and route probes from the server.', mode:'backend', fields:[{name:'target',label:'Target',placeholder:'10.10.10.1 or example.com'},{name:'mode',label:'Mode',type:'select',options:['ping','traceroute'],value:'ping'},{name:'count',label:'Ping count',type:'number',value:'4'},{name:'max_hops',label:'Traceroute max hops',type:'number',value:'20'}] },
  { slug:'port-scanner', title:'Port Scanner', category:'Network Tools', description:'Scan up to 2,000 TCP ports with concurrency and timeouts.', mode:'backend', fields:[{name:'host',label:'Host',placeholder:'10.10.10.237'},{name:'ports',label:'Ports',placeholder:'22,80,443,8000-8100'},{name:'timeout',label:'Timeout seconds',type:'number',value:'0.4'}] },
  { slug:'dns-lookup', title:'DNS Lookup', category:'Network Tools', description:'Resolve A, AAAA, MX, TXT, NS, CNAME, and PTR records.', mode:'backend', fields:[{name:'target',label:'Name or IP',placeholder:'mrdtech.local'},{name:'rtype',label:'Record Type',type:'select',options:['A','AAAA','MX','TXT','NS','CNAME','PTR'],value:'A'}] },
  { slug:'whois-lookup', title:'WHOIS Lookup', category:'Network Tools', description:'Fetch WHOIS ownership and registrar data.', mode:'backend', fields:[{name:'domain',label:'Domain or IP',placeholder:'example.com'}] },
  { slug:'ssl-checker', title:'SSL Certificate Checker', category:'Network Tools', description:'Inspect live TLS certificate dates, issuer, SANs, and fingerprint.', mode:'backend', fields:[{name:'host',label:'Host',placeholder:'example.com'},{name:'port',label:'Port',type:'number',value:'443'}] },
  { slug:'subnet-calculator', title:'Subnet Calculator', category:'Network Tools', description:'Calculate network, broadcast, host range, wildcard, and usable hosts.', mode:'frontend', fields:[{name:'cidr',label:'CIDR',placeholder:'192.168.10.0/24'}] },
  { slug:'vlan-calculator', title:'VLAN Calculator', category:'Network Tools', description:'Validate VLAN IDs and show 802.1Q priority/hex details.', mode:'frontend', fields:[{name:'vlan',label:'VLAN ID',type:'number',placeholder:'100'},{name:'pcp',label:'802.1p priority',type:'number',value:'0'}] },
  { slug:'bgp-asn-lookup', title:'BGP ASN Lookup', category:'Network Tools', description:'Look up ASN owner, country, and announced prefixes.', mode:'backend', fields:[{name:'query',label:'ASN',placeholder:'15169'}] },
  { slug:'bandwidth-calculator', title:'Network Bandwidth Calculator', category:'Network Tools', description:'Convert transfer size, link speed, and estimate transfer time.', mode:'frontend', fields:[{name:'size',label:'Size',type:'number',value:'100'},{name:'size_unit',label:'Size unit',type:'select',options:['MB','GB','TB'],value:'GB'},{name:'speed',label:'Speed',type:'number',value:'1'},{name:'speed_unit',label:'Speed unit',type:'select',options:['Mbps','Gbps'],value:'Gbps'}] },
  { slug:'ip-geolocation', title:'IP Geolocation', category:'Network Tools', description:'Look up IP country, city, ASN, and ISP.', mode:'backend', fields:[{name:'ip',label:'IP Address',placeholder:'8.8.8.8'}] },
  { slug:'wake-on-lan', title:'Wake on LAN', category:'Network Tools', description:'Send a magic packet to a device by MAC address.', mode:'backend', fields:[{name:'mac',label:'MAC Address',placeholder:'00:11:22:33:44:55'},{name:'broadcast',label:'Broadcast Address',value:'255.255.255.255'},{name:'port',label:'UDP Port',type:'number',value:'9'}] },

  { slug:'smart-health', title:'SMART Disk Health Checker', category:'System Tools', description:'Parse pasted smartctl output or run smartctl against a device.', mode:'backend', fields:[{name:'device',label:'Device path',placeholder:'/dev/sda'},{name:'smartctl_output',label:'Pasted smartctl output',type:'textarea'}] },
  { slug:'event-id-lookup', title:'Windows Event ID Lookup', category:'System Tools', description:'Lookup common Windows, Security, Sysmon, and AD event IDs.', mode:'frontend', fields:[{name:'event_id',label:'Event ID',placeholder:'4625'}] },
  { slug:'syslog-severity', title:'Syslog Severity Calculator', category:'System Tools', description:'Convert syslog PRI into facility and severity.', mode:'frontend', fields:[{name:'pri',label:'PRI value',type:'number',placeholder:'134'}] },
  { slug:'ldap-dn-builder', title:'AD / LDAP DN Builder', category:'System Tools', description:'Build distinguished names and LDAP paths from domain/OUs/CN.', mode:'frontend', fields:[{name:'domain',label:'Domain',placeholder:'corp.mrdtech.local'},{name:'ous',label:'OUs, slash separated',placeholder:'Servers/Linux'},{name:'cn',label:'CN',placeholder:'svc-backup'}] },
  { slug:'gpo-path-calculator', title:'GPO Path Calculator', category:'System Tools', description:'Build SYSVOL policy paths from domain and GPO GUID.', mode:'frontend', fields:[{name:'domain',label:'Domain FQDN',placeholder:'corp.mrdtech.local'},{name:'guid',label:'GPO GUID',placeholder:'{31B2F340-016D-11D2-945F-00C04FB984F9}'}] },
  { slug:'cron-builder', title:'Cron Expression Builder', category:'System Tools', description:'Build common cron schedules and explain their fields.', mode:'frontend', fields:[{name:'minute',label:'Minute',value:'0'},{name:'hour',label:'Hour',value:'2'},{name:'day',label:'Day of month',value:'*'},{name:'month',label:'Month',value:'*'},{name:'weekday',label:'Weekday',value:'*'}] },
  { slug:'uptime-calculator', title:'Service Uptime Calculator', category:'System Tools', description:'Translate uptime percentage and window into allowed downtime.', mode:'frontend', fields:[{name:'percent',label:'Uptime %',type:'number',value:'99.9'},{name:'period_days',label:'Period days',type:'number',value:'30'}] },

  { slug:'password-generator', title:'Password Generator', category:'Security Tools', description:'Generate high-entropy operational passwords in the browser.', mode:'frontend', fields:[{name:'length',label:'Length',type:'number',value:'24'},{name:'count',label:'Count',type:'number',value:'5'},{name:'exclude_ambiguous',label:'Exclude ambiguous? yes/no',value:'yes'}] },
  { slug:'password-strength', title:'Password Strength Analyzer', category:'Security Tools', description:'Estimate entropy, crack time, and obvious weaknesses.', mode:'frontend', fields:[{name:'password',label:'Password',type:'textarea'}] },
  { slug:'certificate-decoder', title:'Certificate Decoder', category:'Security Tools', description:'Decode PEM certificates with OpenSSL on the backend.', mode:'backend', fields:[{name:'pem',label:'PEM certificate',type:'textarea',placeholder:'-----BEGIN CERTIFICATE-----'}] },
  { slug:'jwt-decoder', title:'JWT Decoder', category:'Security Tools', description:'Decode JWT header and payload without verifying signature.', mode:'frontend', fields:[{name:'jwt',label:'JWT',type:'textarea'}] },
  { slug:'ssh-key-generator', title:'SSH Key Generator', category:'Security Tools', description:'Generate RSA or ED25519 keypairs in the browser using WebCrypto.', mode:'frontend', fields:[{name:'key_type',label:'Key Type',type:'select',options:['ed25519','rsa'],value:'ed25519'},{name:'bits',label:'RSA Bits',type:'select',options:['2048','4096'],value:'4096'},{name:'comment',label:'Comment',placeholder:'michaeld@mrdtech'}] },
  { slug:'hash-generator', title:'Hash Generator / Verifier', category:'Security Tools', description:'Generate MD5/SHA hashes and compare expected values.', mode:'frontend', fields:[{name:'text',label:'Text',type:'textarea'},{name:'algorithm',label:'Algorithm',type:'select',options:['SHA-1','SHA-256','SHA-512'],value:'SHA-256'},{name:'expected',label:'Expected hash',placeholder:'optional'}] },
  { slug:'cidr-firewall-builder', title:'CIDR Firewall Rule Builder', category:'Security Tools', description:'Generate readable allow/deny firewall rule snippets.', mode:'frontend', fields:[{name:'action',label:'Action',type:'select',options:['allow','deny'],value:'allow'},{name:'cidr',label:'CIDR',placeholder:'10.10.10.0/24'},{name:'port',label:'Port/service',placeholder:'443'},{name:'protocol',label:'Protocol',type:'select',options:['tcp','udp','icmp','any'],value:'tcp'}] },
  { slug:'cve-lookup', title:'CVE Lookup', category:'Security Tools', description:'Query NVD for CVE ID or keyword results.', mode:'backend', fields:[{name:'query',label:'CVE ID or keyword',placeholder:'CVE-2024-3094'}] },
  { slug:'virustotal-checker', title:'VirusTotal Checker', category:'Security Tools', description:'Check URL, IP, domain, or file hash against VirusTotal.', mode:'backend', fields:[{name:'indicator',label:'Indicator',placeholder:'domain, URL, IP, or hash'}] },
  { slug:'base64-codec', title:'Base64 Encoder / Decoder', category:'Security Tools', description:'Encode or decode Base64 strings locally in the browser.', mode:'frontend', fields:[{name:'mode',label:'Mode',type:'select',options:['encode','decode'],value:'decode'},{name:'text',label:'Text',type:'textarea'}] },
  { slug:'ioc-scanner', title:'IOC Scanner', category:'Security Tools', description:'Extract and enrich IPs, domains, URLs, and hashes.', mode:'backend', fields:[{name:'content',label:'Indicators / text',type:'textarea'}] },

  { slug:'docker-compose-converter', title:'Docker Run to Compose Converter', category:'DevOps Tools', description:'Convert common docker run flags into Compose YAML.', mode:'frontend', fields:[{name:'command',label:'docker run command',type:'textarea',placeholder:'docker run -d --name app -p 8080:80 -v data:/data nginx'}] },
  { slug:'k8s-resource-calculator', title:'Kubernetes Resource Calculator', category:'DevOps Tools', description:'Estimate aggregate CPU and memory requests/limits.', mode:'frontend', fields:[{name:'replicas',label:'Replicas',type:'number',value:'3'},{name:'cpu_m',label:'CPU per pod (m)',type:'number',value:'250'},{name:'memory_mi',label:'Memory per pod (Mi)',type:'number',value:'512'}] },
  { slug:'terraform-variable-formatter', title:'Terraform Variable Formatter', category:'DevOps Tools', description:'Format KEY=value lines as Terraform variable definitions.', mode:'frontend', fields:[{name:'vars',label:'Variables',type:'textarea',placeholder:'vm_count=3\nenvironment=prod'}] },
  { slug:'data-converter', title:'YAML / JSON / TOML Converter', category:'DevOps Tools', description:'Convert simple JSON to YAML/TOML or parse YAML-like key values.', mode:'frontend', fields:[{name:'input',label:'Input',type:'textarea',placeholder:'{"name":"app","replicas":3}'},{name:'target',label:'Target',type:'select',options:['json','yaml','toml'],value:'yaml'}] },
  { slug:'pipeline-template', title:'CI/CD Pipeline Template Generator', category:'DevOps Tools', description:'Generate starter GitHub Actions or GitLab CI pipelines.', mode:'frontend', fields:[{name:'platform',label:'Platform',type:'select',options:['GitHub Actions','GitLab CI'],value:'GitHub Actions'},{name:'runtime',label:'Runtime',type:'select',options:['Python','Node','Docker'],value:'Docker'}] },

  { slug:'unifi-vlan-builder', title:'UniFi VLAN Builder', category:'UniFi Tools', description:'Generate UniFi-style network JSON for VLANs, subnets, and DHCP.', mode:'frontend', fields:[{name:'name',label:'Network Name',placeholder:'Servers'},{name:'vlan',label:'VLAN ID',type:'number',value:'20'},{name:'subnet',label:'Subnet CIDR',placeholder:'10.10.20.0/24'},{name:'dhcp_start',label:'DHCP Start',placeholder:'10.10.20.50'},{name:'dhcp_stop',label:'DHCP Stop',placeholder:'10.10.20.250'}] },
  { slug:'unifi-port-profile', title:'UniFi Port Profile Builder', category:'UniFi Tools', description:'Generate switch port profile JSON for access, trunk, and voice ports.', mode:'frontend', fields:[{name:'name',label:'Profile Name',placeholder:'AP Trunk'},{name:'mode',label:'Mode',type:'select',options:['access','trunk','voice'],value:'trunk'},{name:'native_vlan',label:'Native VLAN',type:'number',value:'1'},{name:'tagged_vlans',label:'Tagged VLANs',placeholder:'10,20,30'},{name:'voice_vlan',label:'Voice VLAN',placeholder:'40'}] },
  { slug:'unifi-client-lookup', title:'UniFi Client Lookup', category:'UniFi Tools', description:'Build an API lookup request for a UniFi client by MAC or IP.', mode:'frontend', fields:[{name:'controller',label:'Controller URL',placeholder:'https://10.10.10.1'},{name:'api_key',label:'API Key / Token',placeholder:'not submitted unless you copy it'},{name:'query',label:'MAC or IP',placeholder:'aa:bb:cc:dd:ee:ff'}] },

  { slug:'file-hash-verifier', title:'File Hash Verifier', category:'Forensic Tools', description:'Hash uploaded files and compare evidence fingerprints.', mode:'file', fields:[{name:'file',label:'File',type:'file'},{name:'expected',label:'Expected SHA-256',placeholder:'optional'}] },
  { slug:'metadata-extractor', title:'Metadata Extractor', category:'Forensic Tools', description:'Extract MIME, size, timestamps, and exiftool metadata when available.', mode:'file', fields:[{name:'file',label:'File',type:'file'}] },
  { slug:'string-finder', title:'String Finder', category:'Forensic Tools', description:'Upload a binary file and extract readable ASCII/Unicode strings.', mode:'file', fields:[{name:'file',label:'Binary File',type:'file'}] },
  { slug:'log-analyzer', title:'Log Analyzer', category:'Forensic Tools', description:'Upload or paste logs and parse suspicious entries, failed logins, and privilege signals.', mode:'backend', fields:[{name:'log_text',label:'Log text',type:'textarea'}] },
  { slug:'ioc-scanner', title:'IOC Scanner', category:'Forensic Tools', description:'Extract IPs, domains, URLs, hashes and optionally enrich configured APIs.', mode:'backend', fields:[{name:'content',label:'Content',type:'textarea'}] },
  { slug:'case-manager', title:'Case Manager', category:'Forensic Tools', description:'Persist forensic cases and notes in the Docker /data volume.', mode:'case', fields:[{name:'title',label:'Case title',placeholder:'Ransomware triage'},{name:'summary',label:'Summary',type:'textarea'}] },
]

const selectedCategory = ref(categories[0])
const query = ref('')
const selected = ref<Tool>(tools[0])
const favorites = ref<string[]>(JSON.parse(localStorage.getItem('sts:favorites') || '[]'))
const newestTools = computed(() => tools.slice(-6).reverse())
const form = reactive<Record<string,string>>({})
const result = ref('')
const loading = ref(false)
const fileInput = ref<File | null>(null)
const cases = ref<any[]>([])

const filteredTools = computed(() => tools.filter(t => t.category === selectedCategory.value && `${t.title} ${t.description}`.toLowerCase().includes(query.value.toLowerCase())))
const categoryCounts = computed(() => Object.fromEntries(categories.map(c => [c, tools.filter(t => t.category === c).length])))

function choose(tool: Tool) {
  selected.value = tool
  selectedCategory.value = tool.category
  result.value = ''
  Object.keys(form).forEach(k => delete form[k])
  for (const field of tool.fields) form[field.name] = field.value || ''
  fileInput.value = null
  if (tool.mode === 'case') loadCases()
}
function toggleFavorite(slug:string, ev?:Event) {
  ev?.stopPropagation()
  favorites.value = favorites.value.includes(slug) ? favorites.value.filter(x => x !== slug) : [...favorites.value, slug]
  localStorage.setItem('sts:favorites', JSON.stringify(favorites.value))
}
choose(tools[0])

function pretty(x: unknown) { return typeof x === 'string' ? x : JSON.stringify(x, null, 2) }
function output(x: unknown) { result.value = pretty(x) }
function toNum(v: string, d=0) { const n = Number(v); return Number.isFinite(n) ? n : d }
function ipToInt(ip: string) { return ip.split('.').reduce((a,b)=>((a<<8) + Number(b)) >>> 0, 0) >>> 0 }
function intToIp(n: number) { return [24,16,8,0].map(s => (n>>>s)&255).join('.') }
function b64json(part: string) { return JSON.parse(decodeURIComponent(escape(atob(part.replace(/-/g,'+').replace(/_/g,'/'))))) }
async function digestText(text: string, alg: string) { const buf = await crypto.subtle.digest(alg, new TextEncoder().encode(text)); return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('') }
function pem(label:string, buf:ArrayBuffer) { const b64=btoa(String.fromCharCode(...new Uint8Array(buf))).match(/.{1,64}/g)?.join('\n') || ''; return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----` }
async function browserKeypair() {
  if (form.key_type === 'rsa') {
    const pair = await crypto.subtle.generateKey({ name:'RSASSA-PKCS1-v1_5', modulusLength:Number(form.bits||4096), publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['sign','verify']) as CryptoKeyPair
    return { type:'rsa', public_key_spki_pem:pem('PUBLIC KEY', await crypto.subtle.exportKey('spki', pair.publicKey)), private_key_pkcs8_pem:pem('PRIVATE KEY', await crypto.subtle.exportKey('pkcs8', pair.privateKey)), comment:form.comment, note:'Generated locally with browser WebCrypto. Convert to OpenSSH format with ssh-keygen if required by a legacy target.' }
  }
  const subtle:any = crypto.subtle
  const pair = await subtle.generateKey({ name:'Ed25519' }, true, ['sign','verify'])
  return { type:'ed25519', public_key_raw_base64:btoa(String.fromCharCode(...new Uint8Array(await subtle.exportKey('raw', pair.publicKey)))), private_key_pkcs8_pem:pem('PRIVATE KEY', await subtle.exportKey('pkcs8', pair.privateKey)), comment:form.comment, note:'Generated locally with browser WebCrypto. Ed25519 support depends on browser version.' }
}
async function digestFile(file: File) { const buf = await crypto.subtle.digest('SHA-256', await file.arrayBuffer()); return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('') }

async function backend(slug: string, params: Record<string,string>) {
  const res = await fetch(`/api/tools/${slug}`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ params }) })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || JSON.stringify(data))
  return data
}

function calcSubnet(cidr: string) {
  const [ip, bitsRaw] = cidr.split('/'); const bits = Number(bitsRaw)
  if (!ip || bits < 0 || bits > 32) throw new Error('Use CIDR like 192.168.1.0/24')
  const mask = bits === 0 ? 0 : (0xffffffff << (32-bits)) >>> 0
  const net = ipToInt(ip) & mask; const broadcast = (net | (~mask >>> 0)) >>> 0
  const usable = bits >= 31 ? 0 : Math.max(0, broadcast - net - 1)
  return { cidr, network:intToIp(net), netmask:intToIp(mask), wildcard:intToIp((~mask)>>>0), broadcast:intToIp(broadcast), first_host: usable?intToIp(net+1):null, last_host: usable?intToIp(broadcast-1):null, usable_hosts: usable }
}

async function runFrontend(slug: string) {
  switch(slug) {
    case 'subnet-calculator': return calcSubnet(form.cidr)
    case 'vlan-calculator': { const vlan=toNum(form.vlan), pcp=toNum(form.pcp); return { vlan, valid: vlan>=1 && vlan<=4094, reserved: vlan===0 || vlan===4095, tag_control_information_hex:'0x'+(((pcp&7)<<13)|(vlan&0xfff)).toString(16).padStart(4,'0'), note:'VLAN IDs 1-4094 are usable; 0 and 4095 are reserved.' } }
    case 'bandwidth-calculator': { const bytes=toNum(form.size)*(form.size_unit==='TB'?1e12:form.size_unit==='GB'?1e9:1e6); const bps=toNum(form.speed)*(form.speed_unit==='Gbps'?1e9:1e6); const seconds=(bytes*8)/bps; return { bytes, bits:bytes*8, seconds, human:`${Math.floor(seconds/3600)}h ${Math.floor(seconds%3600/60)}m ${Math.round(seconds%60)}s` } }
    case 'event-id-lookup': { const map:Record<string,string>={ '4624':'Successful logon','4625':'Failed logon','4634':'Logoff','4648':'Explicit credentials logon','4672':'Special privileges assigned','4688':'Process creation','4720':'User account created','4726':'User account deleted','4732':'Member added to local group','4740':'Account locked out','4768':'Kerberos TGT requested','4769':'Kerberos service ticket requested','4771':'Kerberos pre-auth failed','7045':'Service installed','1102':'Security audit log cleared','1':'Sysmon process creation','3':'Sysmon network connection','7':'Sysmon image loaded','10':'Sysmon process access','11':'Sysmon file created','22':'Sysmon DNS query' }; return { event_id:form.event_id, meaning:map[form.event_id] || 'Not in local lookup table', advice:'Correlate with host, user SID, logon type, source IP, and nearby process events.' } }
    case 'syslog-severity': { const pri=toNum(form.pri); const severities=['Emergency','Alert','Critical','Error','Warning','Notice','Informational','Debug']; const facilities=['kern','user','mail','daemon','auth','syslog','lpr','news','uucp','clock','authpriv','ftp','ntp','audit','alert','clock2','local0','local1','local2','local3','local4','local5','local6','local7']; return { pri, facility_code:Math.floor(pri/8), facility:facilities[Math.floor(pri/8)] || 'unknown', severity_code:pri%8, severity:severities[pri%8] } }
    case 'ldap-dn-builder': { const dc=form.domain.split('.').filter(Boolean).map(x=>`DC=${x}`).join(','); const ou=form.ous.split('/').filter(Boolean).reverse().map(x=>`OU=${x}`).join(','); const cn=form.cn?`CN=${form.cn}`:''; return { distinguished_name:[cn,ou,dc].filter(Boolean).join(','), ldap_path:`LDAP://${[cn,ou,dc].filter(Boolean).join(',')}` } }
    case 'gpo-path-calculator': { const g=form.guid.replace(/[{}]/g,'').toUpperCase(); return { sysvol_path:`\\\\${form.domain}\\SYSVOL\\${form.domain}\\Policies\\{${g}}`, gpt_ini:`\\\\${form.domain}\\SYSVOL\\${form.domain}\\Policies\\{${g}}\\GPT.INI` } }
    case 'cron-builder': return { expression:`${form.minute} ${form.hour} ${form.day} ${form.month} ${form.weekday}`, fields:{ minute:form.minute, hour:form.hour, day_of_month:form.day, month:form.month, weekday:form.weekday }, note:'Standard 5-field cron. Validate timezone in scheduler separately.' }
    case 'uptime-calculator': { const total=toNum(form.period_days)*86400; const down=total*(1-toNum(form.percent)/100); return { uptime_percent:toNum(form.percent), period_days:toNum(form.period_days), allowed_downtime_seconds:down, allowed_downtime_minutes:down/60, allowed_downtime_human:`${Math.floor(down/3600)}h ${Math.floor(down%3600/60)}m ${Math.round(down%60)}s` } }
    case 'password-generator': { const base = form.exclude_ambiguous?.toLowerCase().startsWith('y') ? 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?'; const count=Math.min(50,Math.max(1,toNum(form.count,5))); const len=Math.min(128,Math.max(8,toNum(form.length,24))); return Array.from({length:count},()=>Array.from(crypto.getRandomValues(new Uint32Array(len)), n=>base[n%base.length]).join('')) }
    case 'password-strength': { const p=form.password||''; let pool=0; if(/[a-z]/.test(p))pool+=26; if(/[A-Z]/.test(p))pool+=26; if(/\d/.test(p))pool+=10; if(/[^A-Za-z0-9]/.test(p))pool+=33; const entropy=p.length*Math.log2(Math.max(pool,1)); const guesses=2**Math.min(entropy,60); return { length:p.length, entropy_bits:Math.round(entropy*10)/10, score: entropy>80?'strong':entropy>55?'fair':'weak', estimated_offline_crack_time:`${Math.round(guesses/1e10)} seconds at 10B guesses/sec`, weaknesses:[p.length<14?'too short':null,!/[^A-Za-z0-9]/.test(p)?'no symbols':null,!/\d/.test(p)?'no digits':null].filter(Boolean) } }
    case 'jwt-decoder': { const [h,p,s]=form.jwt.split('.'); return { header:b64json(h), payload:b64json(p), signature_present:Boolean(s), warning:'Signature is decoded, not verified.' } }
    case 'ssh-key-generator': return browserKeypair()
    case 'hash-generator': { const hash=await digestText(form.text || '', form.algorithm || 'SHA-256'); return { algorithm:form.algorithm, hash, expected:form.expected || null, matches:form.expected ? hash.toLowerCase()===form.expected.toLowerCase() : null } }
    case 'base64-codec': return form.mode === 'encode' ? btoa(unescape(encodeURIComponent(form.text || ''))) : decodeURIComponent(escape(atob(form.text || '')))
    case 'cidr-firewall-builder': return { nftables:`ip saddr ${form.cidr} ${form.protocol==='any'?'':form.protocol} dport ${form.port} ${form.action==='allow'?'accept':'drop'}`, ufw:`ufw ${form.action==='allow'?'allow':'deny'} from ${form.cidr}${form.port?` to any port ${form.port}`:''}${form.protocol!=='any'?` proto ${form.protocol}`:''}`, windows:`New-NetFirewallRule -DisplayName "STS ${form.action}" -Direction Inbound -Action ${form.action==='allow'?'Allow':'Block'} -RemoteAddress ${form.cidr} -Protocol ${form.protocol.toUpperCase()} ${form.port?`-LocalPort ${form.port}`:''}`, pfsense:{ action:form.action, source:form.cidr, protocol:form.protocol, destination_port:form.port || 'any' }, note:'Review direction/interface before applying.' }
    case 'docker-compose-converter': return dockerRunToCompose(form.command)
    case 'k8s-resource-calculator': { const r=toNum(form.replicas), cpu=toNum(form.cpu_m), mem=toNum(form.memory_mi); return { replicas:r, total_cpu_m: r*cpu, total_cpu_cores:(r*cpu)/1000, total_memory_mi:r*mem, total_memory_gi:(r*mem)/1024, yaml:`resources:\n  requests:\n    cpu: ${cpu}m\n    memory: ${mem}Mi\n  limits:\n    cpu: ${cpu*2}m\n    memory: ${mem*2}Mi` } }
    case 'terraform-variable-formatter': return terraformVars(form.vars)
    case 'data-converter': return dataConvert(form.input, form.target)
    case 'pipeline-template': return pipeline(form.platform, form.runtime)
    case 'unifi-vlan-builder': return { name:form.name, purpose:'corporate', vlan_enabled:true, vlan:Number(form.vlan), subnet:form.subnet, dhcpd_enabled:true, dhcpd_start:form.dhcp_start, dhcpd_stop:form.dhcp_stop, igmp_snooping:true }
    case 'unifi-port-profile': return { name:form.name, op_mode:form.mode, native_networkconf_id:`vlan-${form.native_vlan}`, tagged_vlan_mgmt:form.mode==='trunk'?'custom':'none', tagged_vlans:form.tagged_vlans.split(',').map(x=>x.trim()).filter(Boolean), voice_networkconf_id:form.voice_vlan?`vlan-${form.voice_vlan}`:null, poe_mode:'auto' }
    case 'unifi-client-lookup': return { controller:form.controller, query:form.query, example_curl:`curl -k -H "X-API-KEY: ${form.api_key ? '<redacted>' : '<api-key>'}" "${form.controller.replace(/\/$/,'')}/proxy/network/api/s/default/stat/sta" | jq '.data[] | select(.mac=="${form.query}" or .ip=="${form.query}")'`, note:'Generated locally. Token is not sent from this frontend helper.' }
    default: throw new Error('No frontend implementation for '+slug)
  }
}

function dockerRunToCompose(cmd:string) { const parts=cmd.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map(x=>x.replace(/^['"]|['"]$/g,'')) || []; const svc:any={image:'', container_name:'', ports:[], volumes:[], environment:[], restart:'unless-stopped'}; for(let i=0;i<parts.length;i++){ const p=parts[i]; if(p==='--name') svc.container_name=parts[++i]; else if(p==='-p'||p==='--publish') svc.ports.push(parts[++i]); else if(p==='-v'||p==='--volume') svc.volumes.push(parts[++i]); else if(p==='-e'||p==='--env') svc.environment.push(parts[++i]); else if(!p.startsWith('-') && p!=='docker' && p!=='run') svc.image=p } return `services:\n  ${svc.container_name||'app'}:\n    image: ${svc.image||'IMAGE'}\n    container_name: ${svc.container_name||'app'}\n    restart: unless-stopped\n${svc.ports.length?'    ports:\n'+svc.ports.map((p:string)=>`      - "${p}"`).join('\n')+'\n':''}${svc.volumes.length?'    volumes:\n'+svc.volumes.map((v:string)=>`      - ${v}`).join('\n')+'\n':''}${svc.environment.length?'    environment:\n'+svc.environment.map((e:string)=>`      - ${e}`).join('\n')+'\n':''}` }
function terraformVars(s:string) { return s.split('\n').filter(Boolean).map(line=>{ const [k,...rest]=line.split('='); const v=rest.join('=').trim(); const type=/^\d+$/.test(v)?'number':/^(true|false)$/.test(v)?'bool':'string'; return `variable "${k.trim()}" {\n  type = ${type}\n  default = ${type==='string'?JSON.stringify(v):v}\n}` }).join('\n\n') }
function dataConvert(input:string,target:string) { let obj:any; try{obj=JSON.parse(input)}catch{ obj=Object.fromEntries(input.split('\n').filter(l=>l.includes(':')).map(l=>{const [k,...r]=l.split(':'); return [k.trim(), r.join(':').trim()]})) } if(target==='json') return JSON.stringify(obj,null,2); if(target==='toml') return Object.entries(obj).map(([k,v])=>`${k} = ${JSON.stringify(v)}`).join('\n'); return Object.entries(obj).map(([k,v])=>`${k}: ${typeof v==='object'?JSON.stringify(v):v}`).join('\n') }
function pipeline(platform:string,runtime:string) { if(platform==='GitLab CI') return `stages: [test, build, deploy]\n\n${runtime.toLowerCase()}-pipeline:\n  stage: build\n  script:\n    - echo "build ${runtime}"\n`; return `name: ${runtime} CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Build ${runtime}\n        run: echo "build ${runtime}"\n` }

async function runTool() {
  loading.value = true; result.value = ''
  try {
    if (selected.value.mode === 'backend') output(await backend(selected.value.slug, form))
    else if (selected.value.mode === 'frontend') output(await runFrontend(selected.value.slug))
    else if (selected.value.mode === 'file') await runFileTool()
    else if (selected.value.mode === 'case') await createCase()
  } catch (e:any) { result.value = `ERROR: ${e.message || e}` }
  finally { loading.value = false }
}
async function runFileTool() {
  if (!fileInput.value) throw new Error('Choose a file')
  const fd = new FormData(); fd.append('file', fileInput.value)
  const endpoint = `/api/tools/${selected.value.slug}/file`
  const res = await fetch(endpoint, { method:'POST', body: fd })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || JSON.stringify(data))
  if (selected.value.slug === 'file-hash-verifier' && form.expected) data.matches = String(data.sha256).toLowerCase() === form.expected.toLowerCase()
  output(data)
}
async function loadCases() { const r=await fetch('/api/cases'); cases.value=(await r.json()).cases || [] }
async function createCase() { const r=await fetch('/api/cases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:form.title,summary:form.summary})}); const data=await r.json(); await loadCases(); output(data) }
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="mark"><div class="logo">STS</div><div><strong>System Tools</strong><span>MRDTech Ops Suite</span></div></div>
      <nav>
        <button v-for="c in categories" :key="c" :class="{active:selectedCategory===c}" @click="selectedCategory=c; choose(tools.find(t=>t.category===c)!)">
          <span>{{ c }}</span><b>{{ categoryCounts[c] }}</b>
        </button>
      </nav>
    </aside>
    <main>
      <header class="topbar">
        <div><h1>System Tools Suite</h1><p>Original sysadmin, network, security, DevOps, and forensic tools. No novelty converters. No inherited cruft.</p></div>
        <input v-model="query" class="search" placeholder="Search tools..." />
      </header>
      <section class="newest">
        <div class="section-title"><span>Newest tools</span><b>{{ newestTools.length }}</b></div>
        <div class="new-row">
          <div v-for="tool in newestTools" :key="tool.slug" class="mini-card" @click="choose(tool)">
            <span>{{ tool.category.replace(' Tools','') }}</span><strong>{{ tool.title }}</strong>
          </div>
        </div>
      </section>
      <section class="grid">
        <div v-for="tool in filteredTools" :key="tool.slug" class="card" :class="{picked:selected.slug===tool.slug}" @click="choose(tool)">
          <button class="heart" :class="{on:favorites.includes(tool.slug)}" @click="toggleFavorite(tool.slug, $event)">♥</button>
          <span>{{ tool.category.replace(' Tools','') }}</span><h3>{{ tool.title }}</h3><p>{{ tool.description }}</p>
        </div>
      </section>
      <section class="workspace">
        <div class="panel form-panel">
          <div class="panel-title"><div><span>{{ selected.category }}</span><h2>{{ selected.title }}</h2></div><button @click="runTool" :disabled="loading">{{ loading ? 'Running...' : selected.mode === 'case' ? 'Create Case' : 'Run Tool' }}</button></div>
          <p class="desc">{{ selected.description }}</p>
          <div class="fields">
            <label v-for="f in selected.fields" :key="f.name">
              <span>{{ f.label }}</span>
              <textarea v-if="f.type==='textarea'" v-model="form[f.name]" :placeholder="f.placeholder" rows="7" />
              <select v-else-if="f.type==='select'" v-model="form[f.name]"><option v-for="o in f.options" :key="o" :value="o">{{ o }}</option></select>
              <input v-else-if="f.type==='file'" type="file" @change="fileInput = ($event.target as HTMLInputElement).files?.[0] || null" />
              <input v-else :type="f.type || 'text'" v-model="form[f.name]" :placeholder="f.placeholder" />
            </label>
          </div>
          <div v-if="selected.mode==='case'" class="cases"><h3>Cases in /data</h3><div v-for="c in cases" :key="c.id" class="case-row"><b>#{{ c.id }} {{ c.title }}</b><span>{{ c.status }} · {{ c.updated_at }}</span><p>{{ c.summary }}</p></div></div>
        </div>
        <div class="panel output-panel"><div class="panel-title"><div><span>Output</span><h2>Result</h2></div></div><pre>{{ result || 'Run a tool to see structured output here.' }}</pre></div>
      </section>
    </main>
  </div>
</template>
