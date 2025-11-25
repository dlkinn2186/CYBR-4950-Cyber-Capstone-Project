
# scanner/ports.py

import asyncio
import socket

# Focused set of common IoT ports
TOP_PORTS = [22, 23, 53, 80, 443, 445, 554, 8000, 8080, 8443, 8883, 161]


async def _tcp_probe(ip: str, port: int, timeout: float = 1.5):
    """
    Try connecting to a TCP port and optionally read a banner.
    Returns (port, banner) or None if closed/unresponsive.
    """
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        try:
            writer.write(b"\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=0.6)
            except asyncio.TimeoutError:
                data = b""
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        try:
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
        except Exception:
            pass
        return port, banner
    except Exception:
        return None


async def scan_top_ports(host: dict, use_nmap: bool = False):
    """
    Scan a host for open TCP ports using async connections only.
    (use_nmap is ignored but left in place for CLI compatibility.)
    """
    ip = host.get("ip")
    if not ip:
        print("[!] scan_top_ports: host missing 'ip'")
        return host

    print(f"[*] Scanning {ip} for common ports...")
    sem = asyncio.Semaphore(40)

    async def task(p):
        async with sem:
            return await _tcp_probe(ip, p)

    results = await asyncio.gather(*(task(p) for p in TOP_PORTS))

    host["services"] = []
    for r in results:
        if r:
            port, banner = r
            host["services"].append({
                "port": port,
                "proto": "tcp",
                "name": None,
                "banner": banner
            })

    print(f"[+] {ip}: found {len(host['services'])} open ports")
    return host




