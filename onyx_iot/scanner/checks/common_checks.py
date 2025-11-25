
from scanner.cve_lookup import lookup_cves_from_text


def telnet_findings(service):
    findings = []
    if service.get("port") == 23:
        findings.append({
            "id": "TELNET_OPEN",
            "title": "Telnet service exposed",
            "severity": "High",
            "description": "Telnet transmits credentials in plaintext and is insecure.",
            "remediation": "Disable Telnet and use SSH (port 22) instead."
        })
    return findings


def smb_findings(service):
    findings = []
    if service.get("port") == 445:
        findings.append({
            "id": "SMB_OPEN",
            "title": "SMB file sharing service exposed",
            "severity": "High",
            "description": "SMB (port 445) can expose file shares or OS vulnerabilities if left open.",
            "remediation": "Disable SMB or restrict access to trusted devices only."
        })
    return findings


def http_findings(service, all_services):
    findings = []
    banner = (service.get("banner") or "").lower()

    # Detect "400 Bad Request" banners that might indicate default admin page
    if "400 bad request" in banner:
        findings.append({
            "id": "HTTP_BAD_REQUEST",
            "title": "Misconfigured HTTP interface detected",
            "severity": "Low",
            "description": "The HTTP service returned a 400 Bad Request response, possibly a default or diagnostic page.",
            "remediation": "Harden or disable unused HTTP interfaces."
        })

    # Flag HTTP with no HTTPS counterpart
    if service.get("port") in (80, 8080, 8000):
        has_https = any(s.get("port") in (443, 8443) for s in all_services)
        if not has_https:
            findings.append({
                "id": "HTTP_NO_HTTPS",
                "title": "Unencrypted HTTP interface detected",
                "severity": "Medium",
                "description": "Device exposes a web interface over HTTP without HTTPS encryption.",
                "remediation": "Enable HTTPS or disable plain HTTP access."
            })
    return findings


def weak_creds_findings(service):
    """
    Detect banners or messages suggesting weak/default credentials.
    """
    findings = []
    banner = (service.get("banner") or "").lower()
    if any(word in banner for word in ["default", "admin", "root:root", "password", "login:"]):
        findings.append({
            "id": "WEAK_CREDS_INDICATOR",
            "title": "Possible default or weak credentials",
            "severity": "High",
            "description": "Service banner or response hints at default login credentials (e.g., admin/admin).",
            "remediation": "Change default passwords and enforce strong credentials."
        })
    return findings


def outdated_software_findings(service):
    findings = []
    # Combine multiple fields for matching
    combined_parts = [
        (service.get("banner") or ""),
        ((service.get("http") or {}).get("server") or ""),
        ((service.get("http") or {}).get("title") or ""),
        (service.get("snmp_sysdescr") or ""),
    ]
    # also include device_info values if present
    device_info = service.get("device_info") or {}
    combined_parts += list(device_info.values()) if device_info else []

    combined = " ".join([p for p in combined_parts if p]).lower()

    # Use the CVE matcher (local DB) first
    matched = lookup_cves_from_text(combined)
    if matched:
        findings.append({
            "id": "OUTDATED_WITH_KNOWN_CVE",
            "title": "Device fingerprint matched known vulnerable software/CVEs",
            "severity": "High",
            "description": f"Evidence matched known CVEs: {', '.join(matched)}",
            "remediation": "Update firmware/software or follow vendor security advisories."
        })
        return findings

    # fallback heuristics (existing checks)
    if any(x in combined for x in ["boa/", "goahead/", "mini_httpd"]):
        findings.append({
            "id": "OUTDATED_FIRMWARE_HTTPD",
            "title": "Outdated web server software detected",
            "severity": "Medium",
            "description": "The device appears to use an outdated embedded HTTP server (e.g., Boa, GoAhead, mini_httpd).",
            "remediation": "Update device firmware or contact the vendor for patches."
        })
    return findings


def excessive_services_findings(host):
    """
    Host-level check: flag devices exposing many services (possible misconfiguration).
    """
    findings = []
    services = host.get("services", [])
    if len(services) > 5:
        findings.append({
            "id": "EXCESSIVE_SERVICES",
            "title": "Device exposing multiple network services",
            "severity": "Medium",
            "description": (
                f"This host exposes {len(services)} services, which may indicate "
                "an unnecessary attack surface. IoT devices typically require only "
                "a few open ports (e.g., HTTP, RTSP, or cloud connection)."
            ),
            "remediation": (
                "Disable or restrict unused network services via device settings, "
                "or isolate this device on an IoT VLAN."
            )
        })
    return findings
