# CYBR-4950-Cyber-Capstone-Project
## OnyxIoT: A Custom Methodology for Identifying Consumer Device Vulnerabilities

## Overview:
OnyxIoT is a Python-based IoT network scanning tool designed to identify devices, enumerate services, fingerprint embedded software, detect weak or default configurations, and flag potential vulnerabilities using a lightweight CVE-matching engine.

The tool supports both:
  - Interactive mode (`--interactive`)
  - Direct command-line scanning using `--cidr`, `--out`, and other flags.

OnyxIoT is built as a safe, read-only scanner. It performs reconnaissance but does not exploit vulnerabilities.

## Key Features
### Interactive or Traditional CLI Operation
- `--interactive` provides a menu-driven interface
- Command-line flags allow automated scanning & reporting

### Device Discovery
  - ARP sweep
  - Reverse DNS hostname lookup
  - Vendor lookup via oui_map.json
  - MAC, IP, and hostnames collected

### Port Scanning
  - Asynchronous TCP port probing
  - Fast detection of open ports
  - Service guessing based on port + banner

### Device Fingerprinting
  - HTTP/HTTPS banner grabbing
  - TLS certificate extraction
  - UPnP / SSDP metadata
  - SNMP sysDescr (if available)
  - RTSP OPTIONS probing

### Vulnerability Detection
  - Multiple check modules:
      - `common_checks.py`
      - `dns_checks.py`
      - `rtsp_checks.py`
      - `http_checks.py`
      - `tls_checks.py`
      - `auth_checks.py` (weak/default credential check)
   - CVE matching based on service banners using:
      - `cve_lookup.py`
      - `cve_db.json`

### Report Generation
  - Clean HTML report output
  - Includes:
    - Device list
    - Open ports
    - Fingerprints
    - CVE findings
    - Weak/default credential warnings
    - High/Medium/Low severity tagging

## Installation

### 1. Create and activate a Python Virtual Environment

Using a virtual environment keeps dependencies isolated and prevents conflicts with system Python packages.

Windows:
```
python -m venv .venv
.\.venv\Scripts\activate
```

Linux/macOS:
```
python3 -m venv .venv
source .venv /bin/activate
```

### 2. Install Required Packages
`pip install -r requirements.txt`

### 3. Permissions
  - Windows requires Npcap for ARP scanning
      - https://npcap.com/#download
  - Linux/Mac require running with `sudo`:
      - `sudo python onyx_iot.py --interactive`
      - `sudo python onyx_iot.py --cidr 192.168.1.0/24 --out output.html`

## Usage
### Interactive Mode
Launch Interactive Menu:

`python onyx_iot.py --interactive`

Menu options allow you to:

  - Scan your network and return connected devices
  - Run a full vulnerability scan and auto-generate HTML reports
  - Exit the program

### Direct Command-Line Mode
Basic Scan:

`python onyx_iot.py --cidr 192.168.1.0/24`

Save HTML Report:

`pyhon onyx_iot.py --cidr 192.168.1.0/24 --out reports/html_report.html`

## Repository Structure

```
onyx_iot/
├── onyx_iot.py                → main program (CLI + interactive)
├── scanner/
│   ├── discovery.py           → ARP/DNS/OUI device discovery
│   ├── ports.py               → async TCP port scanner
│   ├── fingerprint.py         → HTTP, TLS, SNMP, RTSP, SSDP fingerprinting
│   ├── cve_lookup.py          → lightweight CVE pattern matcher
│   ├── reporting/
│   │     └── html.py          → HTML report generator
│   ├── checks/
│   │     ├── common_checks.py
│   │     ├── http_checks.py
│   │     ├── tls_checks.py
│   │     ├── dns_checks.py
│   │     ├── rtsp_checks.py
│   │     ├── auth_checks.py
│   │     └── rules.py
│   ├── cve_db.json            → list of fingerprint → CVEs
│   └── oui_map.json           → vendor MAC address prefixes
└── requirements.txt
```
## How It Works

1. User starts scan (interactive or CIDR flag)

2. Discovery phase identifies hosts, vendors, hostnames

3. Port scanner enumerates open TCP ports

4. Fingerprint engine collects:

    - HTTP/HTTPS banners

    - TLS certificate info

    - UPnP/SSDP metadata

    - SNMP, RTSP details

5. Check modules look for:

    - Misconfigurations

    - Weak/default credentials

    - Insecure protocols

    - Software patterns mapping to known CVEs

6. Report generator outputs a clean security report in HTML

## Limitations

  - No active exploitations
  - CVE detection relies on banner signatures, not full CVE scraping
  - Some devices may block scanning based on firewall settings

## License

This project is for academic and educational use only.

Unauthorized scanning of others' networks or failing to obtain permission to test on certain networks may violate strict policies or local laws.



