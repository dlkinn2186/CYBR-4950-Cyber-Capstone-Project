
def dns_findings(service):
    """
    Flags open DNS (port 53) services on IoT devices.
    Most IoT devices should not act as DNS servers.
    """
    findings = []
    port = service.get("port")
    banner = (service.get("banner") or "").lower()

    if port == 53 or "dns" in banner:
        findings.append({
            "id": "DNS_OPEN",
            "title": "DNS service exposed",
            "severity": "Medium",
            "description": (
                "This device appears to be running a DNS service (port 53). "
                "Most IoT devices should not provide DNS responses directly, "
                "as this can expose configuration data or allow misuse."
            ),
            "remediation": (
                "Disable or restrict DNS services to trusted internal resolvers. "
                "Ensure only designated DNS servers handle name resolution."
            ),
        })
    return findings
