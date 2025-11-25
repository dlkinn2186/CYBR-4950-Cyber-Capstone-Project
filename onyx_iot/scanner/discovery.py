
import asyncio
import ipaddress
import platform
import socket
import json
import pathlib
from scapy.all import ARP, Ether, srp, conf   # requires admin + Npcap

# ------------------------------------------------------------
# Load OUI Vendor Map (JSON if available, otherwise defaults)
# ------------------------------------------------------------
DEFAULT_OUI_MAP = {
    "00:1E:58": "Netgear (Arlo)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "FC:FB:FB": "Nintendo",
    "F0:18:98": "Microsoft (Xbox)",
    "D8:BB:2C": "Amazon Technologies",
    "00:24:E4": "Canon",
    "3C:5A:B4": "Google Nest",
    "9C:DA:3E": "TP-Link",
    "C0:25:E9": "Ring",
    "44:65:0D": "LG Electronics"
}

OUI_PATH = pathlib.Path(__file__).parent / "oui_map.json"
try:
    if OUI_PATH.exists():
        OUI_MAP = json.loads(OUI_PATH.read_text())
    else:
        OUI_MAP = DEFAULT_OUI_MAP
except Exception:
    OUI_MAP = DEFAULT_OUI_MAP


def get_vendor(mac: str):
    """Look up vendor name from MAC prefix."""
    if not mac:
        return None
    prefix = mac.upper()[0:8]
    return OUI_MAP.get(prefix, "Unknown")


# ------------------------------------------------------------
# Host Discovery (ARP Sweep + Reverse DNS + Vendor Lookup)
# ------------------------------------------------------------
async def discover_hosts(cidr: str):
    """
    Perform an ARP sweep of the given CIDR and collect
    IP, MAC, hostname, and vendor information.
    """
    print(f"[*] Discovering hosts on {cidr} ...")
    net = ipaddress.ip_network(cidr, strict=False)
    conf.verb = 0

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered = srp(pkt, timeout=2, retry=1)[0]

    hosts = []
    known_vendors = 0

    for _, recv in answered:
        ip_addr = recv.psrc
        mac = recv.hwsrc.upper()
        prefix = mac[0:8]  # first 3 bytes (OUI)
        vendor = OUI_MAP.get(prefix, "Unknown")
        if vendor != "Unknown":
            known_vendors += 1

        # Try reverse DNS for hostname
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except Exception:
            hostname = None

        host = {
            "ip": ip_addr,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "services": [],
            "findings": []
        }

        print(f"[+] Found device: {ip_addr:15}  MAC: {mac:17}  "
              f"Host: {hostname or '-'}  Vendor: {vendor}")
        hosts.append(host)

    print(f"\n[*] Discovery complete: {len(hosts)} hosts found "
          f"({known_vendors} recognized vendors).\n")
    return hosts



