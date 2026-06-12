# System Tools Suite

System Tools Suite is a fork and extension of IT-Tools for sysadmins, network engineers, security analysts, DevOps engineers, and forensic responders.

It keeps the existing IT-Tools Vue/Vite frontend and adds a FastAPI backend for tools that need controlled server-side execution.

## Tool categories

### Network Tools
- Ping / traceroute from the server
- TCP port scanner with custom ranges
- DNS lookup for A, AAAA, MX, TXT, PTR, CNAME, and NS records
- WHOIS lookup
- SSL certificate checker with expiry, issuer, SANs, and fingerprint
- Enhanced subnet calculator
- VLAN calculator
- BGP ASN lookup with prefix summary
- Network bandwidth calculator

### System Tools
- SMART disk health checker and smartctl parser
- Windows Event ID lookup
- Syslog severity calculator
- AD/LDAP distinguished name builder
- GPO SYSVOL path calculator
- Enhanced cron expression builder
- Service uptime/SLA calculator

### Security Tools
- Password generator with complexity controls
- Certificate decoder
- JWT decoder
- Browser-side RSA SSH key material generator
- Hash generator and verifier: MD5, SHA1, SHA256, SHA512
- CIDR firewall rule builder
- CVE lookup through NVD

### DevOps Tools
- Docker run to Compose converter
- Kubernetes resource calculator
- Terraform variable formatter
- YAML / JSON / TOML converter
- CI/CD pipeline template generator for GitHub Actions and GitLab CI

### Forensic Tools
- File hash verifier
- Metadata extractor
- Binary string finder
- Log analyzer for suspicious entries
- IOC scanner with optional AbuseIPDB and VirusTotal lookups
- Persistent case manager with evidence, notes, timeline, and export

## Screenshots

Screenshots go here after first visual release QA.

- `screenshots/home.png`
- `screenshots/network-tools.png`
- `screenshots/case-manager.png`

## Docker quickstart

```bash
git clone https://github.com/mdziegiel/system-tools-suite.git
cd system-tools-suite
cp .env.example .env
# Optional: add VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY for IOC lookups
docker compose up -d --build
```

Open:

```text
http://localhost:10233
```

MRDTech deployment target:

```text
http://10.10.10.237:10233
```

## Persistence

The case manager stores data in SQLite under `/data/cases.sqlite3`. The Compose file mounts that path through the `system-tools-suite-data` named volume.

## Environment

```text
VIRUSTOTAL_API_KEY=       # optional
ABUSEIPDB_API_KEY=        # optional
DATA_DIR=/data
DIST_DIR=/app/dist
```

## Development

Frontend:

```bash
pnpm install
pnpm dev
pnpm build
```

Backend:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
DATA_DIR=./data DIST_DIR=./dist uvicorn backend.app:app --reload --port 10233
```

## Architecture

- Vue 3 + Vite + Naive UI frontend, preserving IT-Tools component patterns.
- `src/tools/system-suite/` defines new tools and routes.
- FastAPI backend under `backend/` handles server-side operations: ping, traceroute, DNS, WHOIS, SSL, port scan, SMART parsing, CVE lookup, IOC lookup, file forensics, and case persistence.
- Single Docker container serves the built SPA and `/api/*` endpoints on port `10233`.

## License

GPL-3.0, inherited from IT-Tools.
