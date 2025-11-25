
def tls_findings(service):
    f = []
    t = service.get("tls")
    if not t: return f
    if t.get("protocol") in ("TLSv1", "TLSv1.1"):
        f.append({
            "id":"TLS_WEAK_VERSION",
            "title":"Weak TLS version negotiated",
            "severity":"High",
            "description":f"Negotiated {t['protocol']}. Modern devices should use TLS 1.2+.",
            "remediation":"Disable legacy TLS and ciphers; require TLS 1.2 or 1.3."
        })
    return f
