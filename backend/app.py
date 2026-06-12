import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DIST_DIR = Path(os.getenv("DIST_DIR", "/app/dist"))
DB_PATH = DATA_DIR / "cases.sqlite3"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="System Tools Suite API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ToolRequest(BaseModel):
    params: dict[str, Any] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as con:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("""
        CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            summary TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS evidence(
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
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS timeline(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            event_time TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
        """)


@app.on_event("startup")
def startup() -> None:
    init_db()


def run_cmd(args: list[str], timeout: int = 25) -> dict[str, Any]:
    try:
        cp = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return {
            "command": " ".join(shlex.quote(a) for a in args),
            "exit_code": cp.returncode,
            "stdout": cp.stdout[-30000:],
            "stderr": cp.stderr[-12000:],
        }
    except subprocess.TimeoutExpired as e:
        return {"command": " ".join(shlex.quote(a) for a in args), "exit_code": 124, "stdout": (e.stdout or "")[-30000:], "stderr": "command timed out"}
    except FileNotFoundError as e:
        return {"command": " ".join(args), "exit_code": 127, "stdout": "", "stderr": str(e)}


def require_target(target: str) -> str:
    target = (target or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", target):
        raise HTTPException(400, "Invalid target. Use hostname or IP only.")
    return target


def ping_traceroute(params: dict[str, Any]) -> dict[str, Any]:
    target = require_target(params.get("target", ""))
    mode = str(params.get("mode", "ping")).lower()
    if mode == "traceroute":
        hops = max(1, min(int(params.get("max_hops", 20)), 64))
        return run_cmd(["traceroute", "-m", str(hops), target], timeout=45)
    count = max(1, min(int(params.get("count", 4)), 10))
    return run_cmd(["ping", "-c", str(count), "-W", "3", target], timeout=count * 4 + 5)


async def port_scanner(params: dict[str, Any]) -> dict[str, Any]:
    host = require_target(params.get("host", ""))
    raw = str(params.get("ports", "1-1024")).replace(" ", "")
    ports: list[int] = []
    for part in raw.split(','):
        if not part:
            continue
        if '-' in part:
            a, b = [int(x) for x in part.split('-', 1)]
            ports.extend(range(max(1, a), min(65535, b) + 1))
        else:
            ports.append(int(part))
    ports = sorted(set(p for p in ports if 1 <= p <= 65535))[:2000]
    if not ports:
        raise HTTPException(400, "No valid ports specified")
    timeout = max(0.1, min(float(params.get("timeout", 0.5)), 3.0))
    sem = asyncio.Semaphore(250)

    async def check(port: int) -> dict[str, Any]:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return {"port": port, "state": "open"}
            except asyncio.TimeoutError:
                return {"port": port, "state": "filtered"}
            except OSError:
                return {"port": port, "state": "closed"}

    results = await asyncio.gather(*(check(p) for p in ports))
    return {"host": host, "scanned": len(ports), "open": [r for r in results if r["state"] == "open"], "results": results[:5000]}


def dns_lookup(params: dict[str, Any]) -> dict[str, Any]:
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


def whois_lookup(params: dict[str, Any]) -> dict[str, Any]:
    target = require_target(params.get("domain", params.get("target", "")))
    raw = run_cmd(["whois", target], timeout=30)
    text = raw.get("stdout", "")
    fields = {}
    for key in ["Registrar", "Registry Expiry Date", "Expiration Date", "Name Server", "Creation Date", "Updated Date"]:
        vals = re.findall(rf"^{re.escape(key)}:\s*(.+)$", text, re.I | re.M)
        if vals:
            fields[key] = vals[:10]
    raw["parsed"] = fields
    return raw


def ssl_checker(params: dict[str, Any]) -> dict[str, Any]:
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


def asn_lookup(params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("query", "")).upper().replace("AS", "").strip()
    if not re.fullmatch(r"\d{1,10}", q):
        raise HTTPException(400, "Use a numeric ASN")
    with urlopen(f"https://api.bgpview.io/asn/{q}", timeout=15) as resp:
        data = json.load(resp).get("data", {})
    return {"asn": data.get("asn"), "name": data.get("name"), "description": data.get("description_short"), "country_code": data.get("country_code"), "prefixes_v4": data.get("ipv4_prefixes", [])[:100], "prefixes_v6": data.get("ipv6_prefixes", [])[:100]}


def ip_geolocation(params: dict[str, Any]) -> dict[str, Any]:
    ip = require_target(params.get("ip", params.get("target", "")))
    with urlopen(f"http://ip-api.com/json/{quote(ip)}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query", timeout=10) as resp:
        return json.load(resp)


def wake_on_lan(params: dict[str, Any]) -> dict[str, Any]:
    mac = re.sub(r"[^0-9a-fA-F]", "", str(params.get("mac", "")))
    if len(mac) != 12:
        raise HTTPException(400, "MAC must contain 12 hex digits")
    broadcast = str(params.get("broadcast", "255.255.255.255"))
    port = int(params.get("port", 9))
    packet = b"\xff" * 6 + bytes.fromhex(mac) * 16
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(packet, (broadcast, port))
    sock.close()
    return {"sent": True, "mac": ":".join(mac[i:i+2] for i in range(0, 12, 2)).lower(), "broadcast": broadcast, "port": port}


def parse_smart(text: str) -> dict[str, Any]:
    health = None
    temp = None
    realloc = pending = uncorrect = None
    m = re.search(r"SMART overall-health self-assessment test result:\s*(\w+)", text, re.I)
    if m:
        health = m.group(1).upper()
    for line in text.splitlines():
        low = line.lower()
        parts = line.split()
        raw = parts[-1] if parts else ""
        if "temperature" in low and re.search(r"\d+", raw):
            temp = int(re.search(r"\d+", raw).group(0))
        if len(parts) >= 10 and parts[1].lower() == "reallocated_sector_ct":
            realloc = int(re.sub(r"\D", "", raw) or 0)
        if len(parts) >= 10 and parts[1].lower() == "current_pending_sector":
            pending = int(re.sub(r"\D", "", raw) or 0)
        if len(parts) >= 10 and parts[1].lower() in {"offline_uncorrectable", "reported_uncorrect"}:
            uncorrect = int(re.sub(r"\D", "", raw) or 0)
    status = "warning" if any((realloc or 0, pending or 0, uncorrect or 0)) else ("healthy" if health in {"PASSED", "OK"} else "unknown")
    return {"status": status, "health": health, "temperature_c": temp, "reallocated_sectors": realloc, "pending_sectors": pending, "uncorrectable": uncorrect}


def smart_checker(params: dict[str, Any]) -> dict[str, Any]:
    text = str(params.get("smartctl_output", "")).strip()
    if text:
        return parse_smart(text)
    device = str(params.get("device", "")).strip()
    if not re.fullmatch(r"/dev/[A-Za-z0-9/_-]+", device):
        raise HTTPException(400, "Paste smartctl output or provide /dev device")
    raw = run_cmd(["smartctl", "-a", device], timeout=40)
    raw["parsed"] = parse_smart(raw.get("stdout", ""))
    return raw


def cve_lookup(params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("query", "")).strip()
    if not q:
        raise HTTPException(400, "Provide CVE ID or keyword")
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", q, re.I):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(q.upper())}"
    else:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(q)}&resultsPerPage=10"
    req = Request(url, headers={"User-Agent": "system-tools-suite/2.0"})
    with urlopen(req, timeout=25) as resp:
        data = json.load(resp)
    out = []
    for item in data.get("vulnerabilities", [])[:10]:
        cve = item.get("cve", {})
        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        refs = [r.get("url") for r in cve.get("references", {}).get("referenceData", [])[:8]]
        out.append({"id": cve.get("id"), "published": cve.get("published"), "last_modified": cve.get("lastModified"), "cvss": score, "description": desc, "references": refs})
    return {"query": q, "results": out}


def virustotal(params: dict[str, Any]) -> dict[str, Any]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {"configured": False, "error": "VIRUSTOTAL_API_KEY is not configured"}
    indicator = str(params.get("indicator", "")).strip()
    if not indicator:
        raise HTTPException(400, "Provide URL, IP, domain, or hash")
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", indicator):
        kind, value = "files", indicator
    elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", indicator):
        kind, value = "ip_addresses", indicator
    elif indicator.startswith(("http://", "https://")):
        # URL IDs are urlsafe base64 without padding.
        import base64
        kind, value = "urls", base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
    else:
        kind, value = "domains", indicator
    req = Request(f"https://www.virustotal.com/api/v3/{kind}/{quote(value)}", headers={"x-apikey": key})
    with urlopen(req, timeout=25) as resp:
        data = json.load(resp)
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"configured": True, "indicator": indicator, "type": kind, "stats": stats, "raw": data.get("data", {}).get("attributes", {})}


def extract_iocs(text: str) -> dict[str, list[str]]:
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    urls = sorted(set(re.findall(r"https?://[^\s'\"<>]+", text)))
    hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text)))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)))
    return {"ips": ips[:500], "domains": domains[:500], "urls": urls[:200], "hashes": hashes[:500]}


def ioc_scanner(params: dict[str, Any]) -> dict[str, Any]:
    content = str(params.get("content", ""))
    found = extract_iocs(content)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    abuse = []
    if abuse_key:
        for ip in found["ips"][:20]:
            try:
                req = Request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip)}&maxAgeInDays=90", headers={"Key": abuse_key, "Accept": "application/json"})
                with urlopen(req, timeout=10) as resp:
                    abuse.append(json.load(resp).get("data", {}))
            except Exception as e:
                abuse.append({"ipAddress": ip, "error": str(e)})
    return {"counts": {k: len(v) for k, v in found.items()}, "indicators": found, "abuseipdb_configured": bool(abuse_key), "abuseipdb": abuse}


def log_analyzer_text(text: str) -> dict[str, Any]:
    severities = {"error": len(re.findall(r"\berror\b", text, re.I)), "warning": len(re.findall(r"\bwarn(?:ing)?\b", text, re.I)), "critical": len(re.findall(r"\bcritical\b", text, re.I)), "failed_logon": len(re.findall(r"4625|failed password|authentication failure|failed logon", text, re.I)), "privilege": len(re.findall(r"4672|sudo|privilege|admin", text, re.I))}
    return {"lines": text.count("\n") + 1 if text else 0, "severities": severities, "top_ips": extract_iocs(text)["ips"][:50], "suspicious_lines": [l for l in text.splitlines() if re.search(r"4625|failed|error|critical|sudo|privilege|malware|denied", l, re.I)][:200]}


def log_analyzer(params: dict[str, Any]) -> dict[str, Any]:
    return log_analyzer_text(str(params.get("log_text", "")))


def cert_decoder(params: dict[str, Any]) -> dict[str, Any]:
    pem = str(params.get("pem", ""))
    if "BEGIN CERTIFICATE" not in pem:
        raise HTTPException(400, "Paste a PEM certificate")
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(pem)
        name = f.name
    try:
        return run_cmd(["openssl", "x509", "-in", name, "-noout", "-text", "-fingerprint", "-sha256"], timeout=15)
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def ssh_keygen(params: dict[str, Any]) -> dict[str, Any]:
    key_type = str(params.get("key_type", "ed25519")).lower()
    bits = str(params.get("bits", "4096"))
    comment = str(params.get("comment", "system-tools-suite"))
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "id_key"
        args = ["ssh-keygen", "-q", "-N", "", "-C", comment, "-f", str(path)]
        if key_type == "rsa":
            args += ["-t", "rsa", "-b", "2048" if bits == "2048" else "4096"]
        else:
            args += ["-t", "ed25519"]
        r = run_cmd(args, timeout=15)
        if r["exit_code"] != 0:
            return r
        return {"type": key_type, "public_key": path.with_suffix(".pub").read_text(), "private_key": path.read_text(), "warning": "Store the private key once. Do not paste it into tickets or chat."}


TOOL_HANDLERS = {
    "ping-traceroute": ping_traceroute,
    "port-scanner": port_scanner,
    "dns-lookup": dns_lookup,
    "whois-lookup": whois_lookup,
    "ssl-checker": ssl_checker,
    "bgp-asn-lookup": asn_lookup,
    "ip-geolocation": ip_geolocation,
    "wake-on-lan": wake_on_lan,
    "smart-health": smart_checker,
    "certificate-decoder": cert_decoder,
    "ssh-key-generator": ssh_keygen,
    "cve-lookup": cve_lookup,
    "virustotal-checker": virustotal,
    "ioc-scanner": ioc_scanner,
    "log-analyzer": log_analyzer,
}


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "System Tools Suite", "version": "2.0.0", "data_dir": str(DATA_DIR), "time": now()}


@app.post("/api/tools/{slug}")
async def run_tool(slug: str, req: ToolRequest):
    fn = TOOL_HANDLERS.get(slug)
    if not fn:
        raise HTTPException(404, f"Unknown backend tool: {slug}")
    if asyncio.iscoroutinefunction(fn):
        return await fn(req.params)
    return fn(req.params)


@app.post("/api/tools/file-hash-verifier/file")
async def file_hash(file: UploadFile = File(...)):
    data = await file.read()
    return {"filename": file.filename, "size": len(data), "md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest()}


@app.post("/api/tools/metadata-extractor/file")
async def metadata(file: UploadFile = File(...)):
    data = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix="_" + (file.filename or "upload")) as f:
        f.write(data)
        name = f.name
    try:
        kind = run_cmd(["file", "-b", name], timeout=10)
        exif = run_cmd(["exiftool", "-json", name], timeout=20)
        parsed = None
        try:
            parsed = json.loads(exif.get("stdout", "[]"))[0]
        except Exception:
            parsed = None
        return {"filename": file.filename, "size": len(data), "file_type": kind.get("stdout", "").strip(), "metadata": parsed, "raw": exif}
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


@app.post("/api/tools/string-finder/file")
async def strings_file(file: UploadFile = File(...)):
    data = await file.read()
    text = data.decode("utf-8", "ignore")
    ascii_strings = re.findall(r"[\x20-\x7e]{5,}", text)
    utf16 = data.decode("utf-16le", "ignore")
    unicode_strings = re.findall(r"[\x20-\x7e]{5,}", utf16)
    return {"filename": file.filename, "size": len(data), "ascii_count": len(ascii_strings), "unicode_count": len(unicode_strings), "strings": (ascii_strings + unicode_strings)[:2000]}


@app.post("/api/tools/log-analyzer/file")
async def log_file(file: UploadFile = File(...)):
    data = await file.read()
    text = data.decode("utf-8", "ignore")
    if (file.filename or "").lower().endswith(".evtx"):
        return {"filename": file.filename, "note": "EVTX uploaded. Text extraction is limited in this container; use exported XML/CSV for full parsing.", "size": len(data), "analysis": log_analyzer_text(text)}
    return {"filename": file.filename, "size": len(data), "analysis": log_analyzer_text(text)}


@app.get("/api/cases")
def list_cases():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute("SELECT * FROM cases ORDER BY updated_at DESC")]
    return {"cases": rows}


@app.post("/api/cases")
def create_case(payload: dict[str, Any]):
    ts = now()
    title = str(payload.get("title", "")).strip()
    if not title:
        raise HTTPException(400, "Case title required")
    summary = str(payload.get("summary", ""))
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute("INSERT INTO cases(title,summary,created_at,updated_at) VALUES(?,?,?,?)", (title, summary, ts, ts))
        cid = cur.lastrowid
    return {"id": cid, "title": title, "summary": summary, "created_at": ts}


@app.post("/api/cases/{case_id}/evidence")
def add_evidence(case_id: int, payload: dict[str, Any]):
    ts = now()
    with sqlite3.connect(DB_PATH) as con:
        con.execute("INSERT INTO evidence(case_id,kind,label,details,created_at) VALUES(?,?,?,?,?)", (case_id, payload.get("kind", "artifact"), payload.get("label", "Evidence"), payload.get("details", ""), ts))
        con.execute("UPDATE cases SET updated_at=? WHERE id=?", (ts, case_id))
    return {"ok": True}


@app.post("/api/cases/{case_id}/notes")
def add_note(case_id: int, payload: dict[str, Any]):
    ts = now()
    with sqlite3.connect(DB_PATH) as con:
        con.execute("INSERT INTO notes(case_id,body,created_at) VALUES(?,?,?)", (case_id, payload.get("body", ""), ts))
        con.execute("UPDATE cases SET updated_at=? WHERE id=?", (ts, case_id))
    return {"ok": True}


def minimal_pdf(text: str) -> bytes:
    # Simple one-page PDF generator. Not pretty. Functional. Like most compliance exports.
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = safe.splitlines()[:55]
    content = "BT /F1 10 Tf 50 780 Td " + " T* ".join(f"({line[:100]})" for line in lines) + " ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        f"<< /Length {len(content.encode())} >>\nstream\n{content}\nendstream".encode(),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


@app.get("/api/cases/{case_id}/export.pdf")
def export_case(case_id: int):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")
        ev = [dict(r) for r in con.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,))]
        notes = [dict(r) for r in con.execute("SELECT * FROM notes WHERE case_id=?", (case_id,))]
    text = f"System Tools Suite Case Report\nCase #{case_id}: {case['title']}\nStatus: {case['status']}\nSummary: {case['summary']}\n\nEvidence:\n" + "\n".join(f"- {e['kind']}: {e['label']} {e['details']}" for e in ev) + "\n\nNotes:\n" + "\n".join(f"- {n['created_at']}: {n['body']}" for n in notes)
    return Response(minimal_pdf(text), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.pdf"})


if DIST_DIR.exists():
    assets = DIST_DIR / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        target = DIST_DIR / full_path
        if full_path and target.exists() and target.is_file():
            return FileResponse(target)
        return FileResponse(DIST_DIR / "index.html")
else:
    @app.get("/")
    def no_dist():
        return JSONResponse({"app": "System Tools Suite", "warning": "frontend dist not found"})
