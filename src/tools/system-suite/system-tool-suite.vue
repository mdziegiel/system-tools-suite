<script setup lang="ts">
import CryptoJS from 'crypto-js';
import YAML from 'yaml';
import * as TOML from 'iarna-toml-esm';
import { useRoute } from 'vue-router';
import { suiteToolsBySlug, type SuiteField } from './systemTools';

const route = useRoute();
const slug = computed(() => String(route.path).replace(/^\//, ''));
const def = computed(() => suiteToolsBySlug[slug.value]);
const form = reactive<Record<string, any>>({});
const output = ref('');
const loading = ref(false);
const selectedFile = ref<File | null>(null);
const cases = ref<any[]>([]);
const selectedCase = ref<any>(null);
const caseTitle = ref('');
const caseSummary = ref('');
const evidenceLabel = ref('');
const evidenceDetails = ref('');
const noteBody = ref('');

watch(def, () => reset(), { immediate: true });
function reset() {
  output.value = '';
  selectedFile.value = null;
  Object.keys(form).forEach(k => delete form[k]);
  def.value?.fields.forEach((f: SuiteField) => form[f.key] = f.default ?? '');
  if (def.value?.mode === 'case') loadCases();
}

function onFile(e: Event) { selectedFile.value = (e.target as HTMLInputElement).files?.[0] ?? null; }
function render(x: any) { output.value = typeof x === 'string' ? x : JSON.stringify(x, null, 2); }
function b64urlDecode(s: string) { const pad = '='.repeat((4 - s.length % 4) % 4); return decodeURIComponent(escape(atob((s + pad).replace(/-/g, '+').replace(/_/g, '/')))); }
function cidrInfo(cidr: string) {
  const [ip, prefixRaw] = cidr.split('/'); const prefix = Number(prefixRaw); const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => n < 0 || n > 255) || prefix < 0 || prefix > 32) throw new Error('Invalid IPv4 CIDR');
  const ipNum = parts.reduce((a, n) => (a << 8) + n, 0) >>> 0; const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0; const broadcast = (network | (~mask >>> 0)) >>> 0; const usable = prefix >= 31 ? 0 : Math.max(0, broadcast - network - 1);
  const fmt = (n: number) => [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.');
  return { cidr, network: fmt(network), broadcast: fmt(broadcast), netmask: fmt(mask), wildcard: fmt((~mask) >>> 0), firstUsable: usable ? fmt(network + 1) : null, lastUsable: usable ? fmt(broadcast - 1) : null, usableHosts: usable };
}
function parseVlanList(s: string) { const out:number[]=[]; for (const part of s.split(',')) { const p=part.trim(); if (!p) continue; if (p.includes('-')) { const [a,b]=p.split('-').map(Number); for(let i=a;i<=b;i++) out.push(i); } else out.push(Number(p)); } return [...new Set(out)].filter(n=>n>=1&&n<=4094).sort((a,b)=>a-b); }
function eventLookup(id: string) { const map:any = { '4624':['Security','Successful logon','Information'], '4625':['Security','Failed logon','Warning'], '4634':['Security','Logoff','Information'], '4648':['Security','Explicit credentials logon','Information'], '4720':['Security','User account created','Audit Success'], '4726':['Security','User account deleted','Audit Success'], '4732':['Security','Member added to local group','Audit Success'], '4740':['Security','Account locked out','Warning'], '4768':['Security','Kerberos TGT requested','Information'], '4769':['Security','Kerberos service ticket requested','Information'], '4771':['Security','Kerberos pre-auth failed','Warning'], '1102':['Security','Audit log cleared','Critical'], '7045':['System','Service installed','Warning'], '7036':['System','Service state changed','Information'], '1000':['Application','Application error','Error'] }; const x=map[id]||['Unknown','No offline description in bundled lookup table','Unknown']; return { eventId:id, source:x[0], description:x[1], severity:x[2] }; }
function pemWrap(label:string, b64:string) { return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g)?.join('\n')}\n-----END ${label}-----`; }
async function sshKey() { const bits = form.algorithm === 'RSA-4096' ? 4096 : 2048; const kp = await crypto.subtle.generateKey({ name:'RSASSA-PKCS1-v1_5', modulusLength:bits, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['sign','verify']); const pub = await crypto.subtle.exportKey('spki', kp.publicKey); const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey); return { algorithm: form.algorithm, note:'Generated in browser. Convert public key to OpenSSH format with ssh-keygen if needed.', publicKeyPem:pemWrap('PUBLIC KEY', btoa(String.fromCharCode(...new Uint8Array(pub)))), privateKeyPem:pemWrap('PRIVATE KEY', btoa(String.fromCharCode(...new Uint8Array(priv)))) }; }
function localRun() {
  const name = def.value.slug;
  if (name === 'subnet-calculator-plus') return cidrInfo(form.cidr);
  if (name === 'vlan-calculator') { const allowed = parseVlanList(form.allowedVlans); const vlan=Number(form.vlanId); return { vlanId:vlan, valid:vlan>=1&&vlan<=4094, reserved:vlan===1?'default/native VLAN by convention':vlan>=1002&&vlan<=1005?'legacy token-ring/FDDI reserved range':'no', nativeVlan:Number(form.nativeVlan), allowedVlans:allowed, trunkSummary:`switchport trunk native vlan ${form.nativeVlan}\nswitchport trunk allowed vlan ${form.allowedVlans}`, accessSummary:`switchport mode access\nswitchport access vlan ${vlan}` }; }
  if (name === 'bandwidth-calculator') { const gb=Number(form.sizeGb), mbps=Number(form.mbps), overhead=Number(form.overhead)/100; const bits=gb*8*1024; const seconds=bits/(mbps*(1-overhead)); return { dataSizeGB:gb, effectiveMbps:mbps*(1-overhead), seconds, minutes:seconds/60, hours:seconds/3600 }; }
  if (name === 'windows-event-id-lookup') return eventLookup(String(form.eventId));
  if (name === 'syslog-severity-calculator') { const sev=['Emergency','Alert','Critical','Error','Warning','Notice','Informational','Debug']; const n=Number(form.severity); return { number:n, name:sev[n]??'Invalid', description:['System unusable','Immediate action required','Critical condition','Error condition','Warning condition','Normal but significant','Informational message','Debug-level message'][n]??'Use 0-7' }; }
  if (name === 'ldap-dn-builder') { const esc=(s:string)=>s.trim().replace(/([,=+<>#;\\"])/g,'\\$1'); return `CN=${esc(form.cn)},${String(form.ous).split(',').filter(Boolean).map((x:string)=>`OU=${esc(x)}`).join(',')},${String(form.domain).split('.').map((x:string)=>`DC=${esc(x)}`).join(',')}`; }
  if (name === 'gpo-path-calculator') { const id = String(form.gpo).startsWith('{') ? form.gpo : `{${CryptoJS.SHA1(String(form.gpo)).toString().slice(0,8)}-${CryptoJS.SHA1(String(form.gpo)).toString().slice(8,12)}-${CryptoJS.SHA1(String(form.gpo)).toString().slice(12,16)}-${CryptoJS.SHA1(String(form.gpo)).toString().slice(16,20)}-${CryptoJS.SHA1(String(form.gpo)).toString().slice(20,32)}}`; return `\\\\${form.domain}\\SYSVOL\\${form.domain}\\Policies\\${id}`; }
  if (name === 'cron-builder-plus') { const preset:any={ 'every-minute':'* * * * *', hourly:'0 * * * *', daily:`${form.minute} ${form.hour} * * *`, weekly:`${form.minute} ${form.hour} * * ${form.weekday}`, monthly:`${form.minute} ${form.hour} ${form.day} * *` }; const expr = preset[form.preset] || `${form.minute} ${form.hour} ${form.day} ${form.month} ${form.weekday}`; return { expression:expr, summary:`minute=${expr.split(' ')[0]}, hour=${expr.split(' ')[1]}, day=${expr.split(' ')[2]}, month=${expr.split(' ')[3]}, weekday=${expr.split(' ')[4]}` }; }
  if (name === 'uptime-calculator') { const period=Number(form.periodHours)*60; const down=Number(form.downtimeMinutes); return { periodMinutes:period, downtimeMinutes:down, uptimePercent:((period-down)/period*100).toFixed(5), downtimeBudgetFor99_9_minutes:(period*0.001).toFixed(2), downtimeBudgetFor99_99_minutes:(period*0.0001).toFixed(2) }; }
  if (name === 'password-generator-plus') { const pools:any={ upper:'ABCDEFGHJKLMNPQRSTUVWXYZ', lower:'abcdefghijkmnopqrstuvwxyz', digits:'23456789', symbols:'!@#$%^&*()-_=+[]{};:,.?' }; if (String(form.excludeAmbiguous).toLowerCase()!=='yes') { pools.upper+='OIL'; pools.lower+='ol'; pools.digits+='01'; } let chars=''; let pwd=''; for (const k of ['upper','lower','digits','symbols']) { chars+=pools[k]; for(let i=0;i<Number(form[k]);i++) pwd+=pools[k][crypto.getRandomValues(new Uint32Array(1))[0]%pools[k].length]; } while (pwd.length<Number(form.length)) pwd+=chars[crypto.getRandomValues(new Uint32Array(1))[0]%chars.length]; return pwd.split('').sort(()=>crypto.getRandomValues(new Uint32Array(1))[0]-2147483648).join(''); }
  if (name === 'jwt-decoder-plus') { const [h,p,s]=String(form.jwt).trim().split('.'); return { header: JSON.parse(b64urlDecode(h)), payload: JSON.parse(b64urlDecode(p)), signaturePresent: Boolean(s) }; }
  if (name === 'hash-generator-verifier') { const text=String(form.text); const hashes:any={ md5:CryptoJS.MD5(text).toString(), sha1:CryptoJS.SHA1(text).toString(), sha256:CryptoJS.SHA256(text).toString(), sha512:CryptoJS.SHA512(text).toString() }; hashes.matchesExpected = form.expected ? Object.values(hashes).some(v => String(v).toLowerCase() === String(form.expected).toLowerCase()) : null; return hashes; }
  if (name === 'firewall-rule-builder') { const act=form.action==='allow'?'ACCEPT':'DROP'; const ufw=form.action==='allow'?'allow':'deny'; return { iptables:`iptables -A INPUT -p ${form.protocol==='any'?'all':form.protocol} -s ${form.cidr} ${form.port?`--dport ${form.port}`:''} -j ${act}`.replace(' -p all --dport',' --dport'), ufw:`ufw ${ufw} from ${form.cidr} to any port ${form.port} proto ${form.protocol}`, cisco:`access-list 100 ${form.action==='allow'?'permit':'deny'} ${form.protocol} ${form.cidr} any eq ${form.port}`, pfsense:`Action=${form.action}, Source=${form.cidr}, Protocol=${form.protocol}, Destination port=${form.port}` }; }
  if (name === 'docker-run-compose-plus') { const cmd=String(form.dockerRun); const image=(cmd.match(/\s([\w./:-]+)\s*$/)||[])[1]||'image:tag'; const nameArg=(cmd.match(/--name\s+(\S+)/)||[])[1]||'app'; const ports=[...cmd.matchAll(/-p\s+(\S+)/g)].map(m=>m[1]); const envs=[...cmd.matchAll(/-e\s+(\S+)/g)].map(m=>m[1]); return YAML.stringify({ services:{ [nameArg]:{ image, container_name:nameArg, restart:'unless-stopped', ports, environment:Object.fromEntries(envs.map(e=>{const [k,v='']=e.split('='); return [k,v];})) } } }); }
  if (name === 'kubernetes-resource-calculator') { const r=Number(form.replicas); return { replicas:r, totalCpuRequestCores:r*Number(form.cpuRequest)/1000, totalCpuLimitCores:r*Number(form.cpuLimit)/1000, totalMemoryRequestMiB:r*Number(form.memRequest), totalMemoryLimitMiB:r*Number(form.memLimit), yaml:{ resources:{ requests:{ cpu:`${form.cpuRequest}m`, memory:`${form.memRequest}Mi` }, limits:{ cpu:`${form.cpuLimit}m`, memory:`${form.memLimit}Mi` } } } }; }
  if (name === 'terraform-variable-formatter') return `variable "${form.name}" {\n  type        = ${form.type}\n  description = "${form.description}"\n  default     = ${form.default}\n}`;
  if (name === 'data-format-converter-plus') { let obj:any; if(form.from==='json') obj=JSON.parse(form.input); else if(form.from==='yaml') obj=YAML.parse(form.input); else obj=TOML.parse(form.input); if(form.to==='json') return JSON.stringify(obj,null,2); if(form.to==='yaml') return YAML.stringify(obj); return TOML.stringify(obj); }
  if (name === 'cicd-template-generator') { if (form.platform==='gitlab') return `stages: [test, build]\n\ntest:\n  image: ${form.language==='python'?'python:3.12':'node:20'}\n  script:\n    - ${form.language==='python'?'python -m compileall .':'npm ci && npm test'}\n`; return `name: CI\non: [push, pull_request]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ${form.language==='python'?'actions/setup-python@v5\n        with:\n          python-version: "3.12"':'actions/setup-node@v4\n        with:\n          node-version: "20"'}\n      - run: ${form.language==='python'?'python -m compileall .':'npm ci && npm test'}\n`; }
  throw new Error('Local handler missing. Apparently entropy won.');
}

async function run() {
  loading.value = true; output.value = '';
  try {
    if (def.value.mode === 'api') {
      const apiTool = def.value.slug === 'ping-traceroute' && form.mode === 'traceroute' ? 'traceroute' : def.value.apiTool;
      const res = await fetch('/api/tool', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ tool: apiTool, params: form }) });
      render(await res.json());
    } else if (def.value.mode === 'file') {
      if (!selectedFile.value) throw new Error('Choose a file first. Revolutionary concept.');
      const fd = new FormData(); fd.append('file', selectedFile.value);
      const endpoint:any = { hash:'/api/file/hash', metadata:'/api/file/metadata', strings:'/api/file/strings', log:'/api/log/analyze' };
      const res = await fetch(endpoint[def.value.apiTool || 'hash'], { method:'POST', body:fd }); render(await res.json());
    } else if (def.value.mode === 'local') {
      if (def.value.slug === 'ssh-key-generator') render(await sshKey()); else render(localRun());
    }
  } catch (e:any) { output.value = e?.message || String(e); }
  finally { loading.value = false; }
}
async function loadCases() { const r=await fetch('/api/cases'); cases.value=await r.json(); }
async function createCase() { await fetch('/api/cases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:caseTitle.value,summary:caseSummary.value})}); caseTitle.value=''; caseSummary.value=''; await loadCases(); }
async function openCase(id:number) { const r=await fetch(`/api/cases/${id}`); selectedCase.value=await r.json(); }
async function addEvidence() { if(!selectedCase.value) return; await fetch(`/api/cases/${selectedCase.value.case.id}/evidence`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind:'evidence',label:evidenceLabel.value,details:evidenceDetails.value})}); evidenceLabel.value=''; evidenceDetails.value=''; await openCase(selectedCase.value.case.id); await loadCases(); }
async function addNote() { if(!selectedCase.value) return; await fetch(`/api/cases/${selectedCase.value.case.id}/notes`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({body:noteBody.value})}); noteBody.value=''; await openCase(selectedCase.value.case.id); await loadCases(); }
</script>

<template>
  <div v-if="def" class="suite-tool">
    <h1>{{ def.name }}</h1>
    <p class="muted">{{ def.description }}</p>

    <div v-if="def.mode !== 'case'" class="panel">
      <div v-for="field in def.fields" :key="field.key" class="field">
        <label>{{ field.label }}</label>
        <textarea v-if="field.type === 'textarea'" v-model="form[field.key]" :placeholder="field.placeholder" rows="7" />
        <select v-else-if="field.type === 'select'" v-model="form[field.key]"><option v-for="opt in field.options" :key="opt" :value="opt">{{ opt }}</option></select>
        <input v-else-if="field.type === 'file'" type="file" @change="onFile">
        <input v-else :type="field.type === 'number' ? 'number' : 'text'" v-model="form[field.key]" :placeholder="field.placeholder">
      </div>
      <button :disabled="loading" @click="run">{{ loading ? 'Running...' : 'Run tool' }}</button>
    </div>

    <div v-else class="case-grid">
      <div class="panel"><h3>Create case</h3><input v-model="caseTitle" placeholder="Case title"><textarea v-model="caseSummary" placeholder="Summary" rows="4"/><button @click="createCase">Create</button><h3>Cases</h3><button @click="loadCases">Refresh</button><ul><li v-for="c in cases" :key="c.id"><button class="link" @click="openCase(c.id)">#{{ c.id }} {{ c.title }} — {{ c.status }}</button></li></ul></div>
      <div class="panel" v-if="selectedCase"><h3>#{{ selectedCase.case.id }} {{ selectedCase.case.title }}</h3><p>{{ selectedCase.case.summary }}</p><a :href="`/api/cases/${selectedCase.case.id}/export`" target="_blank">Export text/PDF-printable report</a><h4>Add evidence</h4><input v-model="evidenceLabel" placeholder="Evidence label"><textarea v-model="evidenceDetails" placeholder="Details" rows="4"/><button @click="addEvidence">Add evidence</button><h4>Add note</h4><textarea v-model="noteBody" placeholder="Note" rows="3"/><button @click="addNote">Add note</button><h4>Evidence</h4><pre>{{ JSON.stringify(selectedCase.evidence, null, 2) }}</pre><h4>Notes</h4><pre>{{ JSON.stringify(selectedCase.notes, null, 2) }}</pre></div>
    </div>

    <pre v-if="output" class="output">{{ output }}</pre>
  </div>
</template>

<style scoped>
.suite-tool { max-width: 1100px; margin: 0 auto; padding: 24px; }
.muted { color: #8a8f98; }
.panel { border: 1px solid rgba(128,128,128,.25); border-radius: 12px; padding: 18px; background: rgba(128,128,128,.06); }
.field { margin-bottom: 14px; }
label { display:block; font-weight:600; margin-bottom:6px; }
input, textarea, select { width:100%; border:1px solid rgba(128,128,128,.35); border-radius:8px; padding:10px; background:rgba(0,0,0,.08); color:inherit; font:inherit; }
button { border:0; border-radius:8px; padding:10px 14px; background:#18a058; color:white; cursor:pointer; margin:4px 0; }
button:disabled { opacity:.6; cursor:not-allowed; }
button.link { background:transparent; color:#36ad6a; padding:2px; text-align:left; }
.output { margin-top:18px; padding:16px; border-radius:12px; overflow:auto; background:#111827; color:#e5e7eb; min-height:120px; }
.case-grid { display:grid; grid-template-columns: 1fr 2fr; gap:16px; }
@media (max-width: 900px) { .case-grid { grid-template-columns:1fr; } }
</style>
