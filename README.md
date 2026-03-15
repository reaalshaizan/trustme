# TrustMe v2.4 — Automated Web Reconnaissance Tool

```
  ████████╗██████╗ ██╗   ██╗███████╗████████╗███╗   ███╗███████╗
     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗ ████║██╔════╝
     ██║   ██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║█████╗
     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══╝
     ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║███████╗
     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝

```

Linux-based automated web reconnaissance tool. No external Python libraries required — uses stdlib only. Optional integration with `nmap`, `whois`, and `dig`.

---

## Quick Start

```bash
# 1. Make executable
chmod +x trustme.sh trustme.py

# 2. Install dependencies (optional but recommended)
./trustme.sh --install

# 3. Run a scan
./trustme.sh example.com
```

---

## Usage

```
./trustme.sh <domain> [options]

Options:
  -o, --output DIR       Output directory for reports (default: ./reports)
  -p, --ports LIST       Comma-separated ports (default: 28 common ports)
  --no-subdomains        Skip subdomain brute-force
  --no-dns               Skip DNS enumeration
  --no-vuln              Skip vulnerability checks
  --no-color             Disable colors (useful for piping to file)
  --full                 Full scan (nmap if available + extended mode)
  --json                 Save JSON report to output dir
  --quiet                Minimal output
  --install              Install system dependencies
  --check                Check tool availability
  -h, --help             Show help

Examples:
  ./trustme.sh example.com
  ./trustme.sh example.com --full --json
  ./trustme.sh example.com -o /tmp/reports -p 80,443,8080,3306
  ./trustme.sh example.com --no-color > report.txt
  python3 trustme.py example.com --json -o ./reports
```

---

## What It Scans

| Module                | Details                                                         |
|-----------------------|-----------------------------------------------------------------|
| **DNS Resolution**    | Resolves target to IP, reverse DNS                             |
| **GeoIP**             | Country, city, ISP, ASN, timezone via ipapi.co                 |
| **Port Scanning**     | Parallel TCP scan of 28+ common ports + banner grabbing        |
| **Service Detection** | Banner grabbing for service/version info                        |
| **nmap Integration**  | Full -sV -sC scan if nmap installed + --full flag              |
| **DNS Enumeration**   | A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA records       |
| **WHOIS**             | Registrar, dates, nameservers, email extraction                 |
| **Subdomain Enum**    | Brute-force 60+ common subdomains concurrently                  |
| **HTTP Analysis**     | Status code, server, page title, response headers              |
| **Tech Detection**    | CMS, frameworks, CDN, analytics from headers + body            |
| **SSL/TLS**           | Certificate validity, issuer, expiry, protocol, grade          |
| **Security Headers**  | Checks 7 key security headers for presence                     |
| **Vulnerability Scan**| Port-based CVEs, anonymous FTP, exposed paths (.env, .git etc) |
| **Reports**           | JSON + terminal output, saved to ./reports/                    |

---

## Requirements

**Required:**
- Python 3.6+ (uses stdlib only — no pip install needed)
- Internet connection

**Recommended (enhances results):**
- `dig` / `bind-utils` — DNS enumeration
- `whois` — WHOIS lookups
- `nmap` — Deep service/version detection (for --full mode)

**Install all at once:**
```bash
# Debian/Ubuntu
sudo apt install python3 whois dnsutils nmap

# RHEL/CentOS/Fedora
sudo dnf install python3 whois bind-utils nmap

# Arch Linux
sudo pacman -S python whois bind-tools nmap

# macOS
brew install python3 whois nmap
```

---

## Output

Reports are saved to `./reports/` by default:

- `trustme_example.com_20250315_143022.json` — Full structured JSON report

---

## Legal Notice

> ⚠️ **Use only on systems you own or have explicit written authorization to test.**
> Unauthorized scanning may violate computer fraud laws (CFAA, Computer Misuse Act, etc.).
> The authors accept no liability for misuse.

---

## File Structure

```
trustme/
├── trustme.sh       ← Bash launcher (run this)
├── trustme.py       ← Python scanner engine
├── README.md       ← This file
└── reports/        ← Generated reports (auto-created)
```
