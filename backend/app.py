import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DIST_DIR = Path(os.getenv("DIST_DIR", "/app/dist"))
DB_PATH = DATA_DIR / "cases.sqlite3"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="System Tools Suite API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ToolRequest(BaseModel):
    tool: str
    params: dict[str, Any] = {}


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            summary TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            details TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
        """)

@app.on_event("startup")
def startup() -> None:
    init_db()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_cmd(args: list[str], timeout: int = 20) -> dict[str, Any]:
    try:
        cp = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return {"command": " ".join(shlex.quote(a) for a in args), "exit_code": cp.returncode, "stdout": cp.stdout[-20000:], "stderr": cp.stderr[-12000:]}
    except subprocess.TimeoutExpired as e:
        return {"command": " ".join(shlex.quote(a) for a in args), "exit_code": 124, "stdout": (e.stdout or "")[-20000:], "stderr": "command timed out"}
    except FileNotFoundError as e:
        return {"command": " ".join(args), "exit_code": 127, "stdout": "", "stderr": str(e)}


def require_target(target: str) -> str:
    target = (target or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", target):
        raise HTTPException(400, "Invalid target. Use a hostname or IP address, not a shell incantation.")
    return target


def ping(params):
    target = require_target(params.get("target", ""))
    count = max(1, min(int(params.get("count", 4)), 10))
    return run_cmd(["ping", "-c", str(count), "-W", "3", target], timeout=count * 4 + 5)


def traceroute(params):
    target = require_target(params.get("target", ""))
    max_hops = max(1, min(int(params.get("max_hops", 20)), 64))
    return run_cmd(["traceroute", "-m", str(max_hops), target], timeout=40)


def port_scan(params):
    host = require_target(params.get("host", ""))
    port_range = str(params.get("ports", "1-1024")).replace(" ", "")
    ports: list[int] = []
    for part in port_range.split(','):
        if '-' in part:
            a, b = [int(x) for x in part.split('-', 1)]
            ports.extend(range(max(1, a), min(65535, b) + 1))
        elif part:
            ports.append(int(part))
    ports = sorted(set(p for p in ports if 1 <= p <= 65535))[:2000]
    if not ports:
        raise HTTPException(400, "No valid ports specified")
    timeout = float(params.get("timeout", 0.4))
    async def check(p: int):
        try:
            fut = asyncio.open_connection(host, p)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return p
        except Exception:
            return None
    async def scan():
        sem = asyncio.Semaphore(200)
        async def guarded(p):
            async with sem:
                return await check(p)
        return [p for p in await asyncio.gather(*(guarded(p) for p in ports)) if p]
    open_ports = asyncio.run(scan())
    return {"host": host, "scanned": len(ports), "open_ports": open_ports}


def dns_lookup(params):
    target = require_target(params.get("target", ""))
    rtype = str(params.get("rtype", "A")).upper()
    if rtype not in {"A", "AAAA", "MX", "TXT", "PTR", "CNAME", "NS"}:
        raise HTTPException(400, "Invalid DNS record type")
    q = target
    if rtype == "PTR":
        try:
            q = ipaddress.ip_address(target).reverse_pointer
        except ValueError:
            pass
    return run_cmd(["dig", "+short", rtype, q], timeout=15)


def whois_lookup(params):
    domain = require_target(params.get("domain", ""))
    return run_cmd(["whois", domain], timeout=25)


def ssl_check(params):
    host = require_target(params.get("host", ""))
    port = int(params.get("port", 443))
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            der = ssock.getpeercert(binary_form=True)
    not_after = cert.get("notAfter")
    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
    return {
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "days_remaining": (expires - datetime.now(timezone.utc)).days if expires else None,
        "san": cert.get("subjectAltName", []),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
    }


def asn_lookup(params):
    q = str(params.get("query", "")).strip().upper().replace("AS", "")
    if not re.fullmatch(r"\d{1,10}", q):
        raise HTTPException(400, "Use a numeric ASN like 15169")
    url = f"https://api.bgpview.io/asn/{q}"
    with urlopen(url, timeout=15) as resp:
        data = json.load(resp)
    d = data.get("data", {})
    return {"asn": d.get("asn"), "name": d.get("name"), "description_short": d.get("description_short"), "country_code": d.get("country_code"), "prefixes_v4": d.get("ipv4_prefixes", [])[:50], "prefixes_v6": d.get("ipv6_prefixes", [])[:50]}


def cve_lookup(params):
    q = str(params.get("query", "")).strip()
    if not q:
        raise HTTPException(400, "Provide CVE ID or keyword")
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", q, re.I):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(q.upper())}"
    else:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(q)}&resultsPerPage=10"
    req = Request(url, headers={"User-Agent": "system-tools-suite/1.0"})
    with urlopen(req, timeout=20) as resp:
        data = json.load(resp)
    out = []
    for item in data.get("vulnerabilities", [])[:10]:
        c = item.get("cve", {})
        metrics = c.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        desc = next((d.get("value") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({"id": c.get("id"), "published": c.get("published"), "lastModified": c.get("lastModified"), "score": score, "description": desc[:800]})
    return {"query": q, "results": out}


def parse_smart_text(text: str):
    health = "UNKNOWN"
    m = re.search(r"SMART overall-health self-assessment test result:\s*(\w+)", text, re.I)
    if m: health = m.group(1).upper()
    attrs = []
    for line in text.splitlines():
        if re.match(r"\s*\d+\s+", line):
            parts = line.split()
            if len(parts) >= 10:
                attrs.append({"id": parts[0], "name": parts[1], "value": parts[3] if len(parts)>3 else "", "worst": parts[4] if len(parts)>4 else "", "threshold": parts[5] if len(parts)>5 else "", "raw": parts[-1]})
    warnings = [a for a in attrs if a["name"].lower() in {"reallocated_sector_ct", "current_pending_sector", "offline_uncorrectable", "reported_uncorrect"} and a["raw"] not in {"0", "0x0"}]
    return {"health": health, "warning_attributes": warnings, "attributes": attrs[:80]}


def smart_check(params):
    text = str(params.get("smartctl_output", "")).strip()
    device = str(params.get("device", "")).strip()
    if text:
        return parse_smart_text(text)
    if device:
        if not re.fullmatch(r"/dev/[A-Za-z0-9/_-]+", device):
            raise HTTPException(400, "Device path must be under /dev")
        r = run_cmd(["smartctl", "-a", device], timeout=30)
        r["parsed"] = parse_smart_text(r.get("stdout", ""))
        return r
    raise HTTPException(400, "Paste smartctl output or provide a /dev device path")


def decode_cert(params):
    pem = str(params.get("pem", ""))
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(pem)
        name = f.name
    try:
        return run_cmd(["openssl", "x509", "-in", name, "-noout", "-text", "-fingerprint", "-sha256"], timeout=15)
    finally:
        try: os.unlink(name)
        except OSError: pass


def ioc_scan(params):
    indicators = [x.strip() for x in re.split(r"[\s,]+", str(params.get("indicators", ""))) if x.strip()]
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    results = []
    for ioc in indicators[:50]:
        entry = {"indicator": ioc, "type": "hash" if re.fullmatch(r"[a-fA-F0-9]{32,128}", ioc) else "ip" if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ioc) else "domain", "checks": []}
        if entry["type"] == "ip" and abuse_key:
            req = Request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ioc)}&maxAgeInDays=90", headers={"Key": abuse_key, "Accept": "application/json"})
            try:
                with urlopen(req, timeout=15) as resp: entry["checks"].append({"source": "AbuseIPDB", "data": json.load(resp).get("data", {})})
            except Exception as e: entry["checks"].append({"source": "AbuseIPDB", "error": str(e)})
        if vt_key:
            path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[entry["type"]]
            req = Request(f"https://www.virustotal.com/api/v3/{path}/{quote(ioc)}", headers={"x-apikey": vt_key})
            try:
                with urlopen(req, timeout=15) as resp: entry["checks"].append({"source": "VirusTotal", "data": json.load(resp).get("data", {}).get("attributes", {})})
            except Exception as e: entry["checks"].append({"source": "VirusTotal", "error": str(e)})
        if not entry["checks"]:
            entry["checks"].append({"source": "local", "note": "No API key configured. Indicator classified only."})
        results.append(entry)
    return {"results": results}

TOOL_HANDLERS = {
    "ping": ping, "traceroute": traceroute, "port-scan": port_scan, "dns-lookup": dns_lookup, "whois-lookup": whois_lookup,
    "ssl-checker": ssl_check, "bgp-asn-lookup": asn_lookup, "cve-lookup": cve_lookup, "smart-health": smart_check,
    "certificate-decoder": decode_cert, "ioc-scanner": ioc_scan,
}

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "System Tools Suite", "data_dir": str(DATA_DIR), "time": now()}

@app.post("/api/tool")
def run_tool(req: ToolRequest):
    handler = TOOL_HANDLERS.get(req.tool)
    if not handler:
        raise HTTPException(404, f"No backend handler for {req.tool}")
    return handler(req.params)

@app.post("/api/file/hash")
async def file_hash(file: UploadFile = File(...)):
    h = {"md5": hashlib.md5(), "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    size = 0
    while chunk := await file.read(1024 * 1024):
        size += len(chunk)
        for x in h.values(): x.update(chunk)
    return {"filename": file.filename, "size": size, "hashes": {k: v.hexdigest() for k, v in h.items()}}

@app.post("/api/file/strings")
async def file_strings(file: UploadFile = File(...), min_length: int = Form(4)):
    data = await file.read(10 * 1024 * 1024)
    s = re.findall(rb"[\x20-\x7E]{%d,}" % max(3, min(min_length, 20)), data)
    return {"filename": file.filename, "strings": [x.decode('utf-8', 'replace') for x in s[:1000]], "truncated": len(s) > 1000}

@app.post("/api/file/metadata")
async def file_metadata(file: UploadFile = File(...)):
    data = await file.read(25 * 1024 * 1024)
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(data); tmp.close()
    try:
        base = {"filename": file.filename, "size": len(data), "content_type": file.content_type}
        ident = run_cmd(["file", tmp.name], timeout=10)
        base["file"] = ident.get("stdout", "")
        exif = run_cmd(["exiftool", "-json", tmp.name], timeout=20)
        if exif["exit_code"] == 0:
            try: base["metadata"] = json.loads(exif["stdout"])[0]
            except Exception: base["metadata_raw"] = exif["stdout"]
        else:
            base["metadata_note"] = "exiftool unavailable or no metadata found"
        return base
    finally:
        try: os.unlink(tmp.name)
        except OSError: pass

@app.post("/api/log/analyze")
async def log_analyze(file: UploadFile = File(...)):
    raw = await file.read(25 * 1024 * 1024)
    patterns = [r"failed password", r"authentication failure", r"sudo", r"segfault", r"panic", r"malware", r"blocked", r"denied", r"error", r"critical", r"powershell", r"mimikatz", r"rundll32", r"encodedcommand", r"4625", r"4740", r"4688", r"1102", r"7045"]
    hits = []
    filename = file.filename or "upload"
    if filename.lower().endswith(".evtx"):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(raw); tmp.close()
        try:
            from Evtx.Evtx import Evtx  # type: ignore
            with Evtx(tmp.name) as log:
                for n, record in enumerate(log.records(), 1):
                    xml = record.xml()
                    if any(re.search(p, xml, re.I) for p in patterns):
                        compact = re.sub(r"\s+", " ", xml)[:2000]
                        hits.append({"record": n, "text": compact})
                        if len(hits) >= 500: break
            return {"filename": filename, "format": "evtx", "suspicious_count": len(hits), "hits": hits}
        except Exception as e:
            return {"filename": filename, "format": "evtx", "error": str(e), "suspicious_count": 0, "hits": []}
        finally:
            try: os.unlink(tmp.name)
            except OSError: pass
    data = raw.decode('utf-8', 'replace')
    for n, line in enumerate(data.splitlines(), 1):
        if any(re.search(p, line, re.I) for p in patterns):
            hits.append({"line": n, "text": line[:1000]})
            if len(hits) >= 500: break
    return {"filename": filename, "format": "text", "suspicious_count": len(hits), "hits": hits}

@app.get("/api/cases")
def list_cases():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM cases ORDER BY updated_at DESC")]

@app.post("/api/cases")
def create_case(payload: dict[str, Any]):
    ts = now()
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute("INSERT INTO cases(title, status, summary, created_at, updated_at) VALUES(?,?,?,?,?)", (payload.get("title", "Untitled case"), payload.get("status", "open"), payload.get("summary", ""), ts, ts))
        case_id = cur.lastrowid
    return {"id": case_id, "created_at": ts}

@app.get("/api/cases/{case_id}")
def get_case(case_id: int):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case: raise HTTPException(404, "Case not found")
        evidence = [dict(r) for r in con.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY created_at", (case_id,))]
        notes = [dict(r) for r in con.execute("SELECT * FROM notes WHERE case_id=? ORDER BY created_at", (case_id,))]
        return {"case": dict(case), "evidence": evidence, "notes": notes}

@app.post("/api/cases/{case_id}/evidence")
def add_evidence(case_id: int, payload: dict[str, Any]):
    ts = now()
    with sqlite3.connect(DB_PATH) as con:
        con.execute("INSERT INTO evidence(case_id, kind, label, details, created_at) VALUES(?,?,?,?,?)", (case_id, payload.get("kind", "note"), payload.get("label", "Evidence"), payload.get("details", ""), ts))
        con.execute("UPDATE cases SET updated_at=? WHERE id=?", (ts, case_id))
    return {"ok": True, "created_at": ts}

@app.post("/api/cases/{case_id}/notes")
def add_note(case_id: int, payload: dict[str, Any]):
    ts = now()
    with sqlite3.connect(DB_PATH) as con:
        con.execute("INSERT INTO notes(case_id, body, created_at) VALUES(?,?,?)", (case_id, payload.get("body", ""), ts))
        con.execute("UPDATE cases SET updated_at=? WHERE id=?", (ts, case_id))
    return {"ok": True, "created_at": ts}

@app.get("/api/cases/{case_id}/export")
def export_case(case_id: int):
    data = get_case(case_id)
    lines = [f"System Tools Suite Case Export", "", f"Case: {data['case']['title']}", f"Status: {data['case']['status']}", f"Created: {data['case']['created_at']}", "", data['case'].get('summary',''), "", "Evidence:"]
    for e in data['evidence']:
        lines.append(f"- [{e['kind']}] {e['label']} ({e['created_at']})\n  {e['details']}")
    lines.append("\nNotes:")
    for n in data['notes']:
        lines.append(f"- {n['created_at']}: {n['body']}")
    return PlainTextResponse("\n".join(lines), media_type="text/plain")

if DIST_DIR.exists():
    assets = DIST_DIR / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")
    public_files = ["favicon.ico", "robots.txt", "pwa-192x192.png", "pwa-512x512.png", "safari-pinned-tab.svg", "apple-touch-icon.png"]
    for filename in public_files:
        path = DIST_DIR / filename
        if path.exists():
            @app.get(f"/{filename}", include_in_schema=False)
            def public_file(filename=filename):
                return FileResponse(DIST_DIR / filename)
    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        candidate = DIST_DIR / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(DIST_DIR / "index.html")
