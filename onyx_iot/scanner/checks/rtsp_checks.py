
def rtsp_findings(service):
    """
    Flags RTSP (Real-Time Streaming Protocol) endpoints that might expose
    live video feeds or configuration data.
    """
    findings = []
    port = service.get("port")
    banner = (service.get("banner") or "").lower()

    # Identify RTSP by port or banner text
    if port == 554 or "rtsp" in banner:
        # Default assumption: Medium severity unless response looks open/unauthenticated
        severity = "Medium"

        # If the banner looks like an HTTP-style "200 OK" or lists RTSP "Public" methods,
        # it might be responding anonymously.
        if "200 ok" in banner and "public" in banner:
            severity = "High"

        findings.append({
            "id": "RTSP_OPEN",
            "title": "RTSP streaming service exposed",
            "severity": severity,
            "description": (
                "This device is advertising an RTSP (Real-Time Streaming Protocol) "
                "endpoint commonly used for live video streaming. "
                "If unauthenticated, this could allow anyone on the network to "
                "view camera feeds or send control commands."
            ),
            "remediation": (
                "Require authentication for RTSP streams, update firmware, "
                "and restrict access via firewall or IoT VLAN."
            ),
        })

    return findings
