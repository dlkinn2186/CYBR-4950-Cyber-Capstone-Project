
# scanner/checks/auth_checks.py
def weak_auth_findings(service):
    """
    Detects devices that use Basic or Digest authentication,
    which may indicate weak or default credentials.
    """
    findings = []

    # look for http auth indicators
    http_info = service.get("http", {})
    banner = (service.get("banner") or "").lower()
    server_header = (http_info.get("server") or "").lower()

    # if banner or headers show auth required
    if "www-authenticate" in banner or "401 unauthorized" in banner:
        findings.append({
            "id": "HTTP_WEAK_AUTH",
            "title": "HTTP authentication required (possible weak credentials)",
            "severity": "Medium",
            "description": (
                "The web service requires authentication (e.g., Basic/Digest). "
                "These methods often use default or weak credentials on IoT devices."
            ),
            "remediation": (
                "Change default credentials immediately and use stronger "
                "authentication where possible."
            )
        })

    # flag known insecure admin pages (optional)
    if "admin" in banner or "login" in banner or "setup" in banner:
        findings.append({
            "id": "HTTP_ADMIN_INTERFACE",
            "title": "Possible admin interface detected",
            "severity": "Low",
            "description": (
                "An administrative interface was detected in the HTTP response. "
                "Ensure this interface is protected by strong authentication and "
                "not exposed to untrusted networks."
            ),
            "remediation": (
                "Restrict management interfaces to trusted subnets or use HTTPS with strong credentials."
            )
        })

    return findings
