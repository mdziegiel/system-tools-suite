# System Tools Suite

Original Vue.js + Vite + FastAPI toolkit for sysadmin, network, security, DevOps, UniFi, and forensic workflows. It is not a fork of IT-Tools; it is a purpose-built operational toolbox for MRDTech-style infrastructure work.

## Screenshots

Screenshots will be added after the first live visual capture.

## Docker quickstart

```bash
cp .env.example .env
# optionally set VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY
docker compose up -d --build
open http://localhost:10233
```

Persistent case-manager data is stored in the `system-tools-suite-data` Docker volume at `/data/system_tools.db` inside the container.

## Tool list

### Network Tools
- Ping / Traceroute
- Port Scanner
- DNS Lookup
- Reverse DNS Lookup
- WHOIS Lookup
- SSL Certificate Checker
- VLAN Calculator
- Subnet Calculator
- BGP ASN Lookup
- Network Bandwidth Calculator
- IP Geolocation
- Wake on LAN
- HTTP Header Inspector
- Website Response Time Checker
- Network Address Translator
- Blacklist / RBL Checker

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

### UniFi Tools
- UniFi VLAN Builder
- UniFi Port Profile Builder
- UniFi Client Lookup

### Forensic Tools
- File Hash Verifier
- Metadata Extractor
- String Finder
- Log Analyzer
- Case Manager

## API keys

Server-side threat enrichment tools read these optional environment variables:

- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`

When keys are absent, IOC tools still classify input locally and clearly report skipped enrichments. No fake threat intel, because that would be stupid.
