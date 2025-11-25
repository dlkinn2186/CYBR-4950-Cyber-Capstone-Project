
from .http_checks import http_header_findings
from .tls_checks import tls_findings
from .auth_checks import weak_auth_findings
from .common_checks import (
    telnet_findings,
    smb_findings,
    http_findings,
    weak_creds_findings,
    outdated_software_findings,
    excessive_services_findings
)
from .rtsp_checks import rtsp_findings
from .dns_checks import dns_findings


def run_checks(host):
    """
    Aggregate all service-level and host-level checks into a unified findings list.
    """
    all_services = host.get("services", [])
    all_findings = []

    # Service-level checks
    for s in all_services:
        findings = []
        findings += http_header_findings(s)
        findings += tls_findings(s)
        findings += telnet_findings(s)
        findings += smb_findings(s)
        findings += http_findings(s, all_services)
        findings += rtsp_findings(s)
        findings += dns_findings(s)
        findings += weak_creds_findings(s)
        findings += outdated_software_findings(s)
        findings += weak_auth_findings(s)
        all_findings.extend(findings)

    # Host-level check
    all_findings.extend(excessive_services_findings(host))

    host["findings"].extend(all_findings)





