
# scanner/fingerprint.py
import asyncio
import ssl
import socket
import aiohttp
from bs4 import BeautifulSoup

# pysnmp is optional
try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd
    )
    PYSNMP_AVAILABLE = True
except Exception:
    PYSNMP_AVAILABLE = False


def _guess_service_from_banner(port, banner):
    banner = (banner or "").lower()
    if "http" in banner or port in (80, 8080, 8000):
        return "http"
    if "https" in banner or port in (443, 8443):
        return "https"
    if "ssh" in banner or port == 22:
        return "ssh"
    if "rtsp" in banner or port == 554:
        return "rtsp"
    if "telnet" in banner or port == 23:
        return "telnet"
    if "smb" in banner or port == 445:
        return "smb"
    if "dns" in banner or port == 53:
        return "dns"
    return None


async def fingerprint_host(host):
    """
    Assigns service names and performs lightweight TLS fingerprinting.
    Populates:
      - service['name']
      - service['banner'] (augmented)
      - service['http'] = {'server', 'title'}
      - service['tls'] = cert info for HTTPS
      - service['snmp_sysdescr'] (if available)
      - host['device_info'] (from UPnP/SSDP)
    """
    ip = host.get("ip")
    for s in host.get("services", []):
        s["name"] = _guess_service_from_banner(s.get("port"), s.get("banner"))

        # default banners for clarity
        if not s.get("banner"):
            if s["name"] == "https":
                s["banner"] = "HTTPS service (TLS/SSL encrypted)"
            elif s["name"] == "dns":
                s["banner"] = "DNS service (UDP/TCP 53)"

        # HTTP/HTTPS probing (async, read-only)
        if s["name"] in ("http", "https"):
            use_https = s["name"] == "https"
            http_info = await _probe_http(ip, s.get("port"), use_https=use_https)
            if http_info:
                s["http"] = http_info
                parts = []
                if http_info.get("server"):
                    parts.append(f"server:{http_info['server']}")
                if http_info.get("title"):
                    parts.append(f"title:{http_info['title']}")
                if parts:
                    s["banner"] = (s.get("banner") or "") + (" | " if s.get("banner") else "") + " ".join(parts)

        # HTTPS TLS cert info (async wrapper)
        if s["name"] == "https":
            cert = await _get_tls_info(ip, s["port"])
            if cert:
                s["tls"] = cert

        # RTSP probing
        if s["name"] == "rtsp":
            response = _probe_rtsp(ip, s.get("port"))
            if response:
                s["banner"] = response

        # SNMP sysDescr (optional)
        if PYSNMP_AVAILABLE and s.get("port") in (161,):
            loop = asyncio.get_event_loop()
            sysdesc = await loop.run_in_executor(None, _snmp_sysdescr, ip)
            if sysdesc:
                s["snmp_sysdescr"] = sysdesc
                host.setdefault("snmp_sysdescrs", []).append(sysdesc)

    # SSDP/UPnP probe
    upnp = _ssdp_probe(ip)
    if upnp:
        host.setdefault("device_info", {}).update(upnp)
        for s in host.get("services", []):
            s.setdefault("device_info", {}).update(upnp)


# TLS blocking helper executed in executor
def _get_tls_info_blocking(ip, port, timeout=2.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                try:
                    subject = dict(x[0] for x in cert.get("subject", []))
                except Exception:
                    subject = {}
                try:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                except Exception:
                    issuer = {}
                return {"protocol": proto, "subject": subject, "issuer": issuer}
    except Exception:
        return None

async def _get_tls_info(ip, port):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_tls_info_blocking, ip, port)


# Async HTTP probe with auth detection
async def _probe_http(ip, port, use_https=False):
    proto = "https" if use_https else "http"
    url = f"{proto}://{ip}:{port}/"
    timeout = aiohttp.ClientTimeout(total=4)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(url, ssl=False) as resp:
                headers = dict(resp.headers)
                text = await resp.text()
                title = None
                # Detect auth requirement
                auth_required = resp.status == 401 or "www-authenticate" in headers

                if text:
                    try:
                        soup = BeautifulSoup(text, "html.parser")
                        if soup and soup.title and soup.title.string:
                            title = soup.title.string.strip()
                    except Exception:
                        title = None

                return {
                    "server": headers.get("Server"),
                    "title": title,
                    "path": "/",
                    "auth_required": auth_required
                }
    except Exception:
        return None



# RTSP probe
def _probe_rtsp(ip, port=554, timeout=2.0):
    request = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: OnyxIoTScanner/1.0\r\n"
        "\r\n"
    ).encode("utf-8")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(request)
            data = s.recv(512)
            if data:
                return data.decode(errors="ignore")
    except Exception:
        pass
    return None


# SSDP / UPnP probe (lightweight)
def _ssdp_probe(host_ip, timeout=1.0):
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST:239.255.255.250:1900\r\n"
        "MAN:\"ssdp:discover\"\r\n"
        "MX:1\r\n"
        "ST:ssdp:all\r\n"
        "\r\n"
    ).encode("utf-8")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (host_ip, 1900))
        try:
            data, addr = s.recvfrom(4096)
            text = data.decode(errors="ignore").lower()
            for line in text.splitlines():
                if line.startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    try:
                        body = _fetch_url_blocking(loc, timeout=2.0)
                        if body:
                            model = _xml_find_tag(body, "modelName")
                            modelnum = _xml_find_tag(body, "modelNumber")
                            manufacturer = _xml_find_tag(body, "manufacturer") or _xml_find_tag(body, "manufacturerURL")
                            out = {}
                            if model:
                                out["modelName"] = model
                            if modelnum:
                                out["modelNumber"] = modelnum
                            if manufacturer:
                                out["manufacturer"] = manufacturer
                            if out:
                                return out
                    except Exception:
                        continue
        except socket.timeout:
            pass
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return None


def _fetch_url_blocking(url, timeout=2.0):
    try:
        if not url.startswith("http://"):
            return None
        url_no_proto = url[len("http://"):]
        host_port, path = (url_no_proto.split("/", 1) + [""])[:2]
        if ":" in host_port:
            host, port = host_port.split(":", 1)
            port = int(port)
        else:
            host = host_port
            port = 80
        path = "/" + path
        with socket.create_connection((host, port), timeout=timeout) as sock:
            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("utf-8")
            sock.sendall(req)
            data = b""
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
            text = data.decode(errors="ignore")
            parts = text.split("\r\n\r\n", 1)
            if len(parts) == 2:
                return parts[1]
    except Exception:
        pass
    return None


def _xml_find_tag(xml_text, tag):
    try:
        low = xml_text.lower()
        opentag = f"<{tag.lower()}>"
        closetag = f"</{tag.lower()}>"
        if opentag in low and closetag in low:
            start = low.index(opentag) + len(opentag)
            end = low.index(closetag, start)
            return xml_text[start:end].strip()
    except Exception:
        pass
    return None


# SNMP sysDescr (blocking)
def _snmp_sysdescr(ip, community='public', timeout=1):
    if not PYSNMP_AVAILABLE:
        return None
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return None


