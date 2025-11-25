# CYBR-4950-Cyber-Capstone-Project
## OnyxIoT: A Custom Methodology for Identifying Consumer Device Vulnerabilities

## Overview:
OnyxIoT is a Python-based IoT network scanning tool designed to identify devices, enumerate services, fingerprint embedded software, detect weak or default configurations, and flag potential vulnerabilities using a lightweight CVE-matching engine.
The tool supports both interactive mode (--interactive) and direct command-line scanning using --cidr, --out, and other flags.
OnyxIoT is built as a safe, read-only scanner. It performs reconnaissance but does not exploit vulnerabilities.

## Key Features:
- Interactive or CLI operation
- '--interactive' provides a menu-driven interface
- Command-line flags allow automated scanning & reporting

- Device Discovery:
  - ARP sweep
  - Reverse DNS hostname lookup
  - Vendor lookup via oui_map.json
  - MAC, IP, and hostnames collected

- Port Scanning:
  - Asynchronous TCP port probing
  - Fast detection of open ports
  - Service guessing based on port + banner

- Device Fingerprinting:
  - HTTP/HTTPS banner grabbing
  - TLS certificate extraction
  - UPnP / SSDP metadata
  - SNMP sysDescr (if available)
  - RTSP OPTIONS probing

- Vulnerability Detection:
    - Multiple check modules:
      - common_checks.py
      - dns_checks.py
      - rtsp_checks.py
      - http_checks.py
      - tls_checks.py
      - auth_checks.py (weak/default credential check)
   - CVE matching based on service banners using:
      - cve_lookup.py
      - cve_db.json

- Report Generation:
  - Clean HTML report output
  - Includes:
    - Device list
    - Open ports
    - Fingerprints
    - CVE findings
    - Weak/default credential warnings
    - High/Medium/Low severity tagging

Installation Requirements:
    Python 3.10+ 
    and Npcap (Windows) or root privileges (Linux/macOS).
    Download the OnyxIoT program files from GitHub.
    Install required Python libraries using the
    'pip install -r requirements.txt' command.

Usage:
  Interactive Mode
    Launch interactive menu:
      'python onyx_iot.py --interactive'
    Menu options allow you to:
      Scan your connected network to discover connected devices
      Run a full vulnerability scan for connected devices
      Generate HTML reports automatically
  Direct Command-Line Mode
    Basic Scan:
      python onyx_iot.py --cidr 192.168.1.0/24
    Save HTML Report:
      python onyx_iot.py --cidr 192.168.1.0/24 --out report.html
    Export results as JSON:
      python onyx_iot.py --cidr 192.168.1.0/24 --out report.html --json scan.json




