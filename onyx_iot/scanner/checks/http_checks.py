
def http_header_findings(service):
    findings = []
    banner = (service.get("banner") or "").lower()
    if "server:" in banner and "apache" in banner and "2.2" in banner:
        findings.append({
            "id": "HTTP_OLD_APACHE",
            "title": "Outdated Apache version in banner",
            "severity": "Medium",
            "description": "HTTP banner suggests Apache 2.2 which is end-of-life.",
            "remediation": "Upgrade web server or hide version via ServerTokens Prod."
        })
    return findings
