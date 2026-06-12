# System Tools Suite

An original MRDTech sysadmin toolkit built from scratch with Vue.js, Vite, and FastAPI. It is not a fork and does not ship novelty developer utilities. No toy generators. No novelty converters. No wallet-word tooling.

## Design

- Dark operations-console UI
- Green accent color: `#10b981`
- Background: `#0f172a`
- Cards: `#1e293b`
- Sidebar: `#111827`
- Left category navigation
- Search-driven card grid with larger cards and more breathing room
- Newest tools section
- Favorite/pin heart on each card
- Inline tool workspace; no separate tool pages

## Tool catalog

### Network Tools

- Ping / Traceroute
- Port Scanner
- DNS Lookup
- WHOIS Lookup
- SSL Certificate Checker
- VLAN Calculator
- Subnet Calculator
- BGP ASN Lookup
- Network Bandwidth Calculator
- IP Geolocation
- Wake on LAN

### System Tools

- SMART Disk Health Checker
- Windows Event ID Lookup
- Syslog Severity Calculator
- AD/LDAP Distinguished Name Builder
- GPO Path Calculator
- Cron Expression Builder
- Service Uptime Calculator

### Security Tools

- Password Generator
- Password Strength Analyzer
- SSH Key Generator
- Hash Generator / Verifier
- Certificate Decoder
- JWT Decoder
- CIDR Firewall Rule Builder
- CVE Lookup
- VirusTotal Checker
- Base64 Encoder / Decoder
- IOC Scanner

### DevOps Tools

- Docker Run to Compose Converter
- Kubernetes Resource Calculator
- Terraform Variable Formatter
- YAML / JSON / TOML Converter
- CI/CD Pipeline Template Generator

### UniFi Tools

- UniFi VLAN Builder
- UniFi Port Profile Builder
- UniFi Client Lookup helper

### Forensic Tools

- File Hash Verifier
- Metadata Extractor
- String Finder
- Log Analyzer
- IOC Scanner
- Case Manager with SQLite-backed persistent case storage and PDF export

## Backend tools

FastAPI powers tools that require server-side execution or API access:

- ping / traceroute
- TCP port scan
- DNS lookup
- WHOIS
- SSL certificate inspection
- SMART disk checks
- Wake on LAN
- IP geolocation
- VirusTotal lookup
- IOC extraction/enrichment
- log analysis
- file hashing
- metadata extraction
- string extraction
- case manager persistence and PDF export

## Frontend-only tools

These run in the browser:

- subnet calculator
- VLAN calculator
- bandwidth calculator
- password generator
- password strength analyzer
- JWT decoder
- Base64 encoder/decoder
- hash generator for WebCrypto-supported SHA algorithms
- CIDR firewall rule builder
- Docker run to Compose converter
- Kubernetes resource calculator
- Terraform variable formatter
- YAML/JSON/TOML converter
- UniFi VLAN builder
- UniFi port profile builder
- cron builder
- uptime calculator
- Windows Event ID lookup
- syslog calculator
- AD/LDAP DN builder
- GPO path calculator

## Docker quickstart

```bash
cp .env.example .env
$EDITOR .env

docker compose up -d --build
```

The app listens on port `10233`.

```text
http://localhost:10233
```

## Environment variables

See `.env.example`.

```bash
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
DATA_DIR=/data
DIST_DIR=/app/dist
```

`VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` are optional. IOC and VirusTotal tools degrade cleanly when the keys are absent.

## Persistent data

The Case Manager stores SQLite data under `/data`.

Docker Compose creates a named volume:

```text
system_tools_suite_data:/data
```

## Development

```bash
npm install
npm run build
python3 -m compileall backend
```

Run the backend directly after installing Python dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app:app --host 0.0.0.0 --port 10233
```

Run Vite separately during development:

```bash
npm run dev
```

## Screenshots

Placeholder paths for future live screenshots:

- `screenshots/home.png`
- `screenshots/network-tools.png`
- `screenshots/case-manager.png`

## Security notes

- Server-side command tools validate hostnames/IPs and use argument arrays, not shell strings.
- Port scanning is capped to 2,000 ports per request.
- Command output is truncated.
- API keys stay in environment variables.
- JWT decoding does not verify signatures.
- Generated SSH private keys are shown once and should be handled like credentials.

## License

MIT.
