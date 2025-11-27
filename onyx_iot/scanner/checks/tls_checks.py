
# scanner/checks/tls_checks.py
import datetime

def tls_findings(service):
    findings = []
    t = service.get("tls")
    if not t:
        return findings

    # ----------------------------------------------------
    # 1. Weak TLS protocol detection
    # ----------------------------------------------------
    if t.get("protocol") in ("TLSv1", "TLSv1.1"):
        findings.append({
            "id": "TLS_WEAK_VERSION",
            "title": "Weak TLS version negotiated",
            "severity": "High",
            "description": f"Negotiated {t['protocol']}. Modern devices should use TLS 1.2 or higher.",
            "remediation": "Disable legacy TLS versions and enable TLS 1.2 or TLS 1.3."
        })

    # ----------------------------------------------------
    # 2. Certificate expiration checks
    # ----------------------------------------------------
    exp = t.get("notAfter")
    if exp:
        try:
            expiry_date = datetime.datetime.strptime(exp, "%Y-%m-%d")
            now = datetime.datetime.utcnow()

            # Expired cert
            if expiry_date < now:
                findings.append({
                    "id": "TLS_EXPIRED_CERT",
                    "title": "Expired TLS certificate",
                    "severity": "Medium",
                    "description": f"The TLS certificate expired on {exp}.",
                    "remediation": "Renew or replace the expired certificate."
                })

            # Cert expiring soon (<30 days)
            elif (expiry_date - now).days <= 30:
                findings.append({
                    "id": "TLS_CERT_EXPIRING_SOON",
                    "title": "TLS certificate expiring soon",
                    "severity": "Low",
                    "description": f"The TLS certificate expires on {exp}.",
                    "remediation": "Renew the certificate to avoid service interruption."
                })

        except Exception:
            # Silent fail if parsing fails
            pass

    return findings


