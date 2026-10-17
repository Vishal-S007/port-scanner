#!/usr/bin/env python3
"""
Port Scanner
A multithreaded TCP port scanner using only Python's standard library.

Usage:
    python3 scanner.py -t 127.0.0.1 -p 1-1024
    python3 scanner.py -t scanme.nmap.org -p 22,80,443 -o results.txt

Only scan systems you own or have permission to test.
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Common ports and their usual services.
# Used first; socket.getservbyport() is the fallback.
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


def parse_ports(port_arg):
    """
    Turn a port string into a sorted list of ints.
    Accepts: "80", "1-1024", "22,80,443", or mixes like "22,80-90".
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    # Valid TCP ports are 1-65535
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    if not valid:
        raise ValueError("No valid ports in range 1-65535")
    return valid


def resolve_target(target):
    """Convert a hostname to an IP address. Exit if it fails."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def get_service(port):
    """Return a service name for a port, or 'unknown'."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock):
    """
    Try to read the first bytes a service sends after connecting.
    Many services (SSH, FTP, SMTP) announce themselves. HTTP does not.
    """
    try:
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.splitlines()[0][:80] if banner else ""
    except (socket.timeout, OSError):
        return ""


def scan_port(ip, port, timeout, want_banner):
    """
    Try one TCP connection.
    Returns (port, service, banner) if open, otherwise None.
    """
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on success instead of raising an error
        if sock.connect_ex((ip, port)) == 0:
            banner = grab_banner(sock) if want_banner else ""
            return (port, get_service(port), banner)
    return None


def run_scan(ip, ports, timeout, threads, want_banner):
    """Scan all ports in parallel. Return a sorted list of open results."""
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [
            pool.submit(scan_port, ip, port, timeout, want_banner)
            for port in ports
        ]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
                port, service, banner = result
                line = f"[+] {port:<6} OPEN   {service}"
                if banner:
                    line += f"   | {banner}"
                print(line)
    return sorted(results)


def save_results(path, target, ip, results, elapsed):
    """Write results to a text file."""
    with open(path, "w") as f:
        f.write(f"Scan target : {target} ({ip})\n")
        f.write(f"Scan time   : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Duration    : {elapsed:.2f}s\n")
        f.write(f"Open ports  : {len(results)}\n\n")
        for port, service, banner in results:
            f.write(f"{port}\t{service}\t{banner}\n")
    print(f"[*] Results saved to {path}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner (authorized use only)."
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports: 80, 1-1024, or 22,80,443 (default 1-1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Seconds to wait per port (default 0.5)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Parallel threads (default 100)")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="Try to grab service banners")
    parser.add_argument("-o", "--output",
                        help="Save results to this file")
    return parser


def main():
    args = build_parser().parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid port input: {e}")
        sys.exit(1)

    ip = resolve_target(args.target)

    print("-" * 50)
    print(f"[*] Target  : {args.target} ({ip})")
    print(f"[*] Ports   : {len(ports)} ({ports[0]}-{ports[-1]})")
    print(f"[*] Threads : {args.threads}   Timeout: {args.timeout}s")
    print("-" * 50)

    start = datetime.now()
    try:
        results = run_scan(ip, ports, args.timeout, args.threads, args.banner)
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user")
        sys.exit(1)
    elapsed = (datetime.now() - start).total_seconds()

    print("-" * 50)
    print(f"[*] Done in {elapsed:.2f}s. {len(results)} open port(s).")

    if args.output:
        save_results(args.output, args.target, ip, results, elapsed)


if __name__ == "__main__":
    main()
