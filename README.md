# Port Scanner

A multithreaded TCP port scanner written in pure Python. Checks a target for open ports and identifies common services.

## Features
- Scan single ports, ranges, or lists (`80`, `1-1024`, `22,80,443`)
- Service detection for common ports
- Optional banner grabbing (`-b`)
- Multithreaded for speed
- Configurable timeout and thread count
- Save results to a file
- No external libraries — standard library only

## How It Works
The scanner attempts a TCP connection (`connect_ex`) to each port.
- Returns `0` → port is **open**
- Anything else or timeout → **closed or filtered**

Ports are scanned in parallel using `ThreadPoolExecutor`.

## Usage
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024
python3 scanner.py -t scanme.nmap.org -p 22,80,443 -b
python3 scanner.py -t 127.0.0.1 -p 1-65535 --threads 300 -o results.txt
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-t` | Target IP or hostname | required |
| `-p` | Ports to scan | `1-1024` |
| `--timeout` | Seconds per port | `0.5` |
| `--threads` | Parallel threads | `100` |
| `-b` | Grab banners | off |
| `-o` | Output file | none |

## Example Output
```
--------------------------------------------------
[*] Target  : 127.0.0.1 (127.0.0.1)
[*] Ports   : 1024 (1-1024)
[*] Threads : 100   Timeout: 0.5s
--------------------------------------------------
[+] 22     OPEN   SSH   | SSH-2.0-OpenSSH_9.6
[+] 80     OPEN   HTTP
--------------------------------------------------
[*] Done in 5.21s. 2 open port(s).
```

## Limitations
- TCP connect scan only — no UDP, no SYN (stealth) scan
- Cannot tell "closed" from "filtered"
- Full connections are easy for firewalls/IDS to log
- IPv4 only
- Banner grabbing only works for services that speak first (SSH, FTP, SMTP)

## Future Improvements
- UDP scanning
- IPv6 support
- JSON/CSV output
- Scan multiple hosts / CIDR ranges

## Legal Notice
Only scan systems you own or have explicit permission to test. `scanme.nmap.org` permits scanning for practice.
