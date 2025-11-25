
import argparse
import asyncio
import webbrowser
import pathlib
import sys

from scanner.discovery import discover_hosts
from scanner.ports import scan_top_ports
from scanner.fingerprint import fingerprint_host
from scanner.checks.rules import run_checks
from scanner.reporting.html import write_html_report


# -------------------------------------------------------
# CLEAN PROFESSIONAL BANNER
# -------------------------------------------------------
def print_banner():
    print("\n---------------------------------------")
    print("           OnyxIoT Scanner v1.0")
    print("      (CYBR 4950: Cyber Capstone)")
    print("---------------------------------------\n")


# -------------------------------------------------------
# INTERACTIVE MENU
# -------------------------------------------------------
def interactive_menu():
    print("Choose an option:")
    print("1) Discover devices on this network")
    print("2) Full scan (discover + ports + fingerprints + checks)")
    print("3) Exit")

    choice = input("\nEnter choice (1–3): ").strip()
    return choice


# -------------------------------------------------------
# FULL SCAN FUNCTION
# -------------------------------------------------------
async def run_full_scan(cidr: str, out_file: str):
    hosts = await discover_hosts(cidr)

    print("[*] Beginning port scanning, fingerprinting, and rule checks...\n")
    for host in hosts:
        await scan_top_ports(host)
        await fingerprint_host(host)
        run_checks(host)

    out = pathlib.Path(out_file)
    out.parent.mkdir(exist_ok=True, parents=True)
    write_html_report(hosts, out)

    print(f"\n[+] Report written to: {out}")
    try:
        webbrowser.open(out.as_uri())
    except Exception:
        print("[!] Could not auto-open report. You can open it manually.")
    return hosts


# -------------------------------------------------------
# DISCOVERY-ONLY
# -------------------------------------------------------
async def run_discovery_only(cidr: str):
    hosts = await discover_hosts(cidr)
    print("\nDiscovered Devices:")
    for h in hosts:
        print(f"  {h['ip']}  |  {h.get('vendor')}  |  {h.get('hostname')}")
    print("")
    return hosts


# -------------------------------------------------------
# MAIN ENTRY POINT
# -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="OnyxIoT Scanner CLI")
    parser.add_argument("--cidr", help="Target network (default auto-detect)", default=None)
    parser.add_argument("--out", help="Report path", default="reports/onyx_report.html")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive mode")

    args = parser.parse_args()

    # Auto-detect subnet if none supplied
    if args.cidr is None:
        # Simple default: assume /24 on current local LAN
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        base = ".".join(local_ip.split(".")[:3])
        args.cidr = f"{base}.0/24"
        print(f"[*] Auto-selected network: {args.cidr}")

    print_banner()

    if args.interactive:
        while True:
            choice = interactive_menu()
            if choice == "1":
                asyncio.run(run_discovery_only(args.cidr))
            elif choice == "2":
                asyncio.run(run_full_scan(args.cidr, args.out))
            elif choice == "3":
                print("\nExiting OnyxIoT Scanner.\n")
                sys.exit(0)
            else:
                print("Invalid choice. Try again.\n")
    else:
        # Non-interactive default = full scan
        asyncio.run(run_full_scan(args.cidr, args.out))


if __name__ == "__main__":
    main()







