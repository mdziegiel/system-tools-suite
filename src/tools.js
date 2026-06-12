export const categories = [
  { name: 'Network Tools', tools: [
    ['ping-traceroute','Ping / Traceroute','Run ICMP ping or traceroute from the server and inspect live-style output.','backend','new'],
    ['port-scanner','Port Scanner','Scan a host for open TCP ports across a controlled range.','backend','new'],
    ['dns-lookup','DNS Lookup','Resolve A, AAAA, MX, TXT, PTR, CNAME, and NS records.','backend','new'],
    ['mxtoolbox','MXToolbox','Check MX records, SPF, DMARC, and DNSBL status using DNS lookups.','backend','new'],
    ['dns-propagation','DNS Propagation Checker','Check DNS answers across multiple global public resolvers.','backend','new'],
    ['reverse-dns','Reverse DNS Lookup','Resolve an IP address to hostname using PTR records.','backend',''],
    ['whois','WHOIS Lookup','Review domain registration data, registrar, expiry, and nameservers.','backend',''],
    ['ssl-checker','SSL Certificate Checker','Inspect certificate validity, issuer, SANs, expiry, and SHA256 fingerprint.','backend','new'],
    ['ssl-labs-grade','SSL Labs Grade','Request a Qualys SSL Labs assessment and report TLS endpoint grades.','backend','new'],
    ['vlan-calculator','VLAN Calculator','Reference VLAN ranges and access, trunk, native, and 802.1Q behavior.','frontend',''],
    ['subnet-calculator','Subnet Calculator','Calculate network, broadcast, usable range, netmask, wildcard, and host count.','frontend',''],
    ['bgp-asn','BGP ASN Lookup','Look up ASN registration and announced public prefixes.','backend',''],
    ['bandwidth-calculator','Network Bandwidth Calculator','Estimate transfer time from file size and network bandwidth.','frontend',''],
    ['ip-geolocation','IP Geolocation','Identify country, city, ASN, and ISP for an IP address.','backend',''],
    ['wake-on-lan','Wake on LAN','Send a magic packet to a target MAC address.','backend',''],
    ['http-headers','HTTP Header Inspector','Fetch and display HTTP response headers from a URL.','backend',''],
    ['response-time','Website Response Time Checker','Measure status code and response time from this server.','backend',''],
    ['nat-translator','Network Address Translator','Calculate one-to-one NAT mappings between equal-size private and public ranges.','backend',''],
    ['rbl-checker','Blacklist / RBL Checker','Check common DNSBL/RBL lists for an IP address.','backend','']
  ]},
  { name: 'System Tools', tools: [
    ['smart-checker','SMART Disk Health Checker','Parse smartctl output or query a device path for health and temperature.','backend','new'],
    ['event-id','Windows Event ID Lookup','Map common Windows Event IDs to source, severity, cause, and description.','frontend',''],
    ['syslog-severity','Syslog Severity Calculator','Convert numeric syslog severity to name, meaning, and operational impact.','frontend',''],
    ['ldap-dn','AD/LDAP Distinguished Name Builder','Build valid distinguished names from CN, OU, and DC components.','frontend',''],
    ['gpo-path','GPO Path Calculator','Convert a GPO GUID or name into common SYSVOL policy paths.','frontend',''],
    ['cron-builder','Cron Expression Builder','Build cron expressions with plain-English summary and next run examples.','frontend',''],
    ['uptime-calculator','Service Uptime Calculator','Calculate SLA uptime percentage from downtime and reporting period.','frontend','']
  ]},
  { name: 'Security Tools', tools: [
    ['password-generator','Password Generator','Generate strong single or bulk passwords with complexity controls.','frontend','new'],
    ['password-strength','Password Strength Analyzer','Estimate entropy, crack time, and obvious weakness patterns locally.','frontend',''],
    ['ssh-key-generator','SSH Key Generator','Generate RSA or ED25519 key material in the browser.','frontend',''],
    ['hash-tool','Hash Generator / Verifier','Generate and verify MD5, SHA1, SHA256, and SHA512 hashes.','frontend',''],
    ['cert-decoder','Certificate Decoder','Decode PEM certificate fields and validity hints locally when possible.','frontend',''],
    ['jwt-decoder','JWT Decoder','Decode JWT header and payload locally without sending it anywhere.','frontend',''],
    ['cidr-rule-builder','CIDR Firewall Rule Builder','Generate allow or deny rules for iptables, UFW, Windows Firewall, and pfSense.','frontend',''],
    ['cve-lookup','CVE Lookup','Search NVD CVE records by ID or keyword and inspect CVSS and references.','backend',''],
    ['hibp-check','HaveIBeenPwned','Check an email address against HaveIBeenPwned breaches using API v3.','backend','new'],
    ['urlscan','URLScan.io','Submit a URL to urlscan.io and return verdicts, technologies, IP, and ASN data.','backend','new'],
    ['email-header-analyzer','Email Header Analyzer','Parse raw email headers locally for hops, delays, and SPF/DKIM/DMARC results.','frontend','new'],
    ['virustotal','VirusTotal Checker','Check a URL, IP, domain, or hash against VirusTotal when configured.','backend',''],
    ['base64','Base64 Encoder / Decoder','Encode or decode Base64 safely in the browser.','frontend',''],
    ['ioc-scanner','IOC Scanner','Bulk classify IOCs and enrich with AbuseIPDB and VirusTotal when keys exist.','backend','new']
  ]},
  { name: 'DevOps Tools', tools: [
    ['docker-compose-converter','Docker Run to Compose Converter','Convert common docker run syntax into docker-compose.yml.','frontend',''],
    ['k8s-calculator','Kubernetes Resource Calculator','Estimate CPU and memory requests and limits across replicas.','frontend',''],
    ['terraform-formatter','Terraform Variable Formatter','Generate HCL variable blocks from key/value/type input.','frontend',''],
    ['data-converter','YAML / JSON / TOML Converter','Convert between structured formats with validation.','frontend','']
  ]},
  { name: 'UniFi Tools', tools: [
    ['unifi-vlan','UniFi VLAN Builder','Generate UniFi network JSON for VLAN definitions.','frontend',''],
    ['unifi-port-profile','UniFi Port Profile Builder','Generate access, trunk, and voice switch port profile JSON.','frontend',''],
    ['unifi-client','UniFi Client Lookup','Query a UniFi controller API by MAC or IP using supplied connection details.','backend','']
  ]},
  { name: 'Forensic Tools', tools: [
    ['file-hash','File Hash Verifier','Upload a file and calculate MD5, SHA256, and SHA512 digests.','backend','new'],
    ['metadata-extractor','Metadata Extractor','Upload PDFs, Word files, or images and extract embedded metadata.','backend',''],
    ['string-finder','String Finder','Upload binary content and extract readable ASCII and Unicode strings.','backend',''],
    ['log-analyzer','Log Analyzer','Upload syslog text or EVTX and flag suspicious entries.','backend',''],
    ['case-manager','Case Manager','Create cases, evidence, notes, timeline entries, and export case data.','backend','new']
  ]}
]
export const tools = categories.flatMap(c => c.tools.map(([slug,name,description,mode,badge]) => ({slug,name,description,mode,badge,category:c.name})))
