#!/usr/bin/env python3
"""
TrustMe - Automated Web Reconnaissance Tool
Linux-based | Python 3.6+ | Real recon + AI analysis
"""

import sys
import os
import json
import socket
import subprocess
import concurrent.futures
import argparse
import datetime
import ipaddress
import re
import time
import ssl
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

# ─── Color codes ──────────────────────────────────────────────────────────────
class C:
    G  = '\033[38;5;46m'    # bright green
    G2 = '\033[38;5;118m'   # light green
    A  = '\033[38;5;214m'   # amber
    R  = '\033[38;5;196m'   # red
    B  = '\033[38;5;39m'    # blue
    M  = '\033[38;5;240m'   # muted gray
    W  = '\033[97m'         # white
    Y  = '\033[38;5;226m'   # yellow
    P  = '\033[38;5;135m'   # purple
    BOLD = '\033[1m'
    DIM  = '\033[2m'
    RST  = '\033[0m'
    def no(): return ''

NO_COLOR = not sys.stdout.isatty() or '--no-color' in sys.argv
if NO_COLOR:
    for attr in ['G','G2','A','R','B','M','W','Y','P','BOLD','DIM','RST']:
        setattr(C, attr, '')

BANNER = f"""{C.G}
  ████████╗██████╗ ██╗   ██╗███████╗████████╗███╗   ███╗███████╗
     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗ ████║██╔════╝
     ██║   ██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║█████╗
     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══╝
     ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║███████╗
     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝
{C.M}  Automated Web Reconnaissance & Intelligence Tool v2.4
  trustme | for authorized use only
{C.RST}"""

# ─── Utility helpers ──────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=15):
    """Run shell command, return stdout or empty string on failure."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def tool_exists(name):
    return run_cmd(f"which {name}") != ""

def print_section(title):
    width = 60
    print(f"\n{C.G2}{'─'*width}{C.RST}")
    print(f"{C.G2}  ◈ {C.W}{C.BOLD}{title}{C.RST}")
    print(f"{C.G2}{'─'*width}{C.RST}")

def print_kv(key, val, color=None):
    color = color or C.W
    print(f"  {C.M}{key:<22}{C.RST}{color}{val}{C.RST}")

def print_item(label, val='', prefix='→', col=C.B):
    print(f"  {C.G}{prefix}{C.RST} {col}{label}{C.RST} {C.M}{val}{C.RST}")

def spinner_msg(msg):
    print(f"  {C.G}[~]{C.RST} {C.M}{msg}...{C.RST}", end='\r')

def ok_msg(msg):
    print(f"  {C.G}[✓]{C.RST} {msg}          ")

def err_msg(msg):
    print(f"  {C.R}[✗]{C.RST} {msg}")

def warn_msg(msg):
    print(f"  {C.A}[!]{C.RST} {msg}")

# ─── DNS resolution ───────────────────────────────────────────────────────────

def resolve_host(target):
    spinner_msg("Resolving host")
    try:
        ip = socket.gethostbyname(target)
        ok_msg(f"Resolved {C.B}{target}{C.RST} → {C.G}{ip}{C.RST}")
        return ip
    except socket.gaierror as e:
        err_msg(f"DNS resolution failed: {e}")
        return None

# ─── Port scanning ────────────────────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888, 27017, 6379, 5432, 1433, 9200, 11211
]

SERVICE_MAP = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Dev', 9200: 'Elasticsearch', 11211: 'Memcached',
    27017: 'MongoDB', 1433: 'MSSQL'
}

RISKY_PORTS = {23, 21, 3389, 5900, 11211, 27017, 6379, 9200, 1433, 3306, 5432}

def scan_port(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return port if result == 0 else None
    except Exception:
        return None

def grab_banner(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(512).decode(errors='ignore').strip()
            s.close()
            # Extract Server header if HTTP
            for line in banner.split('\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return banner.split('\n')[0][:60] if banner else ''
        except Exception:
            s.close()
            return ''
    except Exception:
        return ''

def scan_ports_fast(ip, ports=None, workers=150):
    ports = ports or COMMON_PORTS
    spinner_msg(f"Scanning {len(ports)} ports on {ip}")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            if res:
                open_ports.append(res)
    ok_msg(f"Found {C.G}{len(open_ports)}{C.RST} open ports")
    return sorted(open_ports)

def get_port_details(ip, open_ports):
    results = []
    for port in open_ports:
        svc  = SERVICE_MAP.get(port, 'unknown')
        risk = 'HIGH' if port in RISKY_PORTS else ('MEDIUM' if port in {25,110,143,111} else 'LOW')
        banner = grab_banner(ip, port)
        results.append({'port': port, 'service': svc, 'banner': banner, 'risk': risk})
    return results

# ─── nmap integration (optional) ─────────────────────────────────────────────

def nmap_scan(ip):
    if not tool_exists('nmap'):
        return None
    spinner_msg("Running nmap service scan")
    out = run_cmd(f"nmap -sV -sC --open -T4 -p- --min-rate 5000 {ip} 2>/dev/null", timeout=120)
    ok_msg("nmap scan complete")
    return out

# ─── DNS enumeration ──────────────────────────────────────────────────────────

DNS_RECORD_TYPES = ['A','AAAA','MX','NS','TXT','CNAME','SOA','PTR','SRV','CAA']

def query_dns(domain, rtype):
    if tool_exists('dig'):
        out = run_cmd(f"dig +short {rtype} {domain} 2>/dev/null", timeout=8)
        return [l.strip() for l in out.splitlines() if l.strip()]
    elif tool_exists('host'):
        out = run_cmd(f"host -t {rtype} {domain} 2>/dev/null", timeout=8)
        return [l.strip() for l in out.splitlines() if 'has' in l or 'handled by' in l]
    else:
        return []

def enumerate_dns(domain):
    spinner_msg("Enumerating DNS records")
    records = {}
    for rtype in DNS_RECORD_TYPES:
        res = query_dns(domain, rtype)
        if res:
            records[rtype] = res
    ok_msg(f"Found {C.G}{sum(len(v) for v in records.values())}{C.RST} DNS records")
    return records

# ─── Subdomain enumeration ────────────────────────────────────────────────────

COMMON_SUBS = [
    'www','mail','ftp','smtp','pop','imap','webmail','admin','portal','vpn',
    'remote','api','dev','staging','test','beta','app','blog','shop','store',
    'static','cdn','media','img','images','assets','files','download','docs',
    'support','help','kb','status','monitor','ns1','ns2','mx','smtp2',
    'autodiscover','autoconfig','cpanel','whm','plesk','secure','login',
    'auth','sso','oauth','git','gitlab','github','jira','confluence','wiki',
    'jenkins','ci','cd','dashboard','panel','manage','management','owa',
    'exchange','mobile','m','wap','preview','sandbox','demo'
]

def brute_subdomains(domain, wordlist=None):
    spinner_msg("Enumerating subdomains")
    subs_to_check = wordlist or COMMON_SUBS
    found = []

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {'subdomain': fqdn, 'ip': ip}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        results = list(ex.map(check_sub, subs_to_check))

    found = [r for r in results if r]
    ok_msg(f"Found {C.G}{len(found)}{C.RST} subdomains")
    return found

# ─── HTTP analysis ────────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'x-xss-protection',
]

def analyze_http(target, ip):
    spinner_msg("Analyzing HTTP headers & technologies")
    results = {
        'headers_raw': {},
        'missing_security': [],
        'server': '',
        'powered_by': '',
        'technologies': [],
        'status_code': None,
        'redirect': None,
        'title': '',
    }

    for scheme in ['https', 'http']:
        url = f"{scheme}://{target}"
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) TrustMe/2.4',
                'Accept': '*/*'
            })
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                results['status_code'] = resp.status
                headers = dict(resp.headers)
                results['headers_raw'] = headers
                results['server'] = headers.get('Server', headers.get('server', ''))
                results['powered_by'] = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
                
                # Check missing security headers
                lowers = {k.lower(): v for k,v in headers.items()}
                for h in SECURITY_HEADERS:
                    if h not in lowers:
                        results['missing_security'].append(h)
                
                # Tech detection from headers
                _detect_tech_from_headers(headers, results)
                
                # Read body for tech detection
                try:
                    body = resp.read(8192).decode(errors='ignore')
                    _detect_tech_from_body(body, results)
                    title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
                    if title_m:
                        results['title'] = title_m.group(1).strip()[:80]
                except Exception:
                    pass
                break
        except Exception:
            continue

    ok_msg(f"HTTP analysis complete — {C.G}{results['status_code'] or 'N/A'}{C.RST}")
    return results

def _detect_tech_from_headers(headers, results):
    hstr = str(headers).lower()
    tech_map = {
        'nginx': 'Nginx', 'apache': 'Apache', 'iis': 'IIS',
        'cloudflare': 'Cloudflare', 'php': 'PHP',
        'asp.net': 'ASP.NET', 'express': 'Express.js',
        'django': 'Django', 'rails': 'Ruby on Rails',
        'litespeed': 'LiteSpeed', 'openresty': 'OpenResty',
        'varnish': 'Varnish', 'gunicorn': 'Gunicorn',
    }
    for key, name in tech_map.items():
        if key in hstr and name not in results['technologies']:
            results['technologies'].append(name)

def _detect_tech_from_body(body, results):
    body_l = body.lower()
    tech_map = {
        'wp-content': 'WordPress', 'drupal.org': 'Drupal',
        'joomla': 'Joomla', 'shopify': 'Shopify',
        'squarespace': 'Squarespace', 'wix.com': 'Wix',
        'bootstrap': 'Bootstrap', 'tailwindcss': 'Tailwind CSS',
        'jquery': 'jQuery', 'react': 'React',
        'angular': 'Angular', 'vue.js': 'Vue.js',
        'next.js': 'Next.js', 'gatsby': 'Gatsby',
        'google-analytics': 'Google Analytics',
        'gtm.js': 'Google Tag Manager',
        'intercom': 'Intercom', 'zendesk': 'Zendesk',
        'cloudflare': 'Cloudflare',
    }
    for key, name in tech_map.items():
        if key in body_l and name not in results['technologies']:
            results['technologies'].append(name)

# ─── SSL/TLS inspection ───────────────────────────────────────────────────────

def check_ssl(target):
    spinner_msg("Inspecting SSL/TLS certificate")
    result = {
        'valid': False, 'issuer': '', 'subject': '',
        'expires': '', 'not_before': '', 'san': [],
        'protocol': '', 'issues': []
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(10)
            s.connect((target, 443))
            cert = s.getpeercert()
            result['valid'] = True
            result['subject'] = dict(x[0] for x in cert.get('subject', []))
            result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
            result['expires'] = cert.get('notAfter', '')
            result['not_before'] = cert.get('notBefore', '')
            result['san'] = [v for t,v in cert.get('subjectAltName', []) if t=='DNS']
            result['protocol'] = s.version()
            
            # Check expiry
            try:
                exp = datetime.datetime.strptime(result['expires'], '%b %d %H:%M:%S %Y %Z')
                days_left = (exp - datetime.datetime.utcnow()).days
                result['days_left'] = days_left
                if days_left < 30:
                    result['issues'].append(f"Expires in {days_left} days!")
            except Exception:
                result['days_left'] = -1
            
            # Protocol checks
            if s.version() in ('TLSv1', 'TLSv1.1'):
                result['issues'].append(f"Weak protocol: {s.version()}")
            
        ok_msg(f"SSL valid — {C.G}{result['protocol']}{C.RST}")
    except ssl.SSLCertVerificationError:
        result['valid'] = False
        result['issues'].append("Certificate verification failed")
        err_msg("SSL certificate invalid")
    except Exception as e:
        result['issues'].append(str(e)[:50])
        err_msg(f"SSL check failed: {e}")
    return result

# ─── WHOIS ────────────────────────────────────────────────────────────────────

def get_whois(domain):
    spinner_msg("Fetching WHOIS data")
    if tool_exists('whois'):
        out = run_cmd(f"whois {domain} 2>/dev/null", timeout=15)
        ok_msg("WHOIS retrieved")
        return out
    else:
        warn_msg("whois not installed — skipping")
        return ""

def parse_whois(raw):
    if not raw:
        return {}
    result = {}
    patterns = {
        'registrar': r'(?:Registrar|registrar):\s*(.+)',
        'created': r'(?:Creation Date|Created|created):\s*(.+)',
        'expires': r'(?:Registry Expiry Date|Expiry Date|expires):\s*(.+)',
        'updated': r'(?:Updated Date|Last Updated):\s*(.+)',
        'name_servers': r'Name Server:\s*(.+)',
        'status': r'Domain Status:\s*(.+)',
        'emails': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    }
    for key, pat in patterns.items():
        if key == 'emails':
            result[key] = list(set(re.findall(pat, raw)))[:5]
        elif key == 'name_servers':
            result[key] = list(set(re.findall(pat, raw, re.I)))[:4]
        else:
            m = re.search(pat, raw, re.I)
            if m:
                result[key] = m.group(1).strip()[:80]
    return result

# ─── GeoIP ────────────────────────────────────────────────────────────────────

def get_geoip(ip):
    spinner_msg("Fetching geolocation data")
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'TrustMe/2.4'})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        ok_msg(f"Geo: {C.G}{data.get('city','?')}, {data.get('country_name','?')}{C.RST}")
        return data
    except Exception:
        try:
            url2 = f"http://ip-api.com/json/{ip}"
            req = urllib.request.Request(url2, headers={'User-Agent': 'TrustMe/2.4'})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
            ok_msg(f"Geo: {C.G}{data.get('city','?')}, {data.get('country','?')}{C.RST}")
            return data
        except Exception as e:
            warn_msg(f"GeoIP failed: {e}")
            return {}

# ─── Vulnerability checks ─────────────────────────────────────────────────────

def check_common_vulns(target, ip, open_ports, http_data, ssl_data):
    spinner_msg("Running vulnerability checks")
    vulns = []

    port_nums = [p['port'] for p in open_ports]

    # Telnet open
    if 23 in port_nums:
        vulns.append({'id':'CVE-TELNET','severity':'CRITICAL','title':'Telnet Service Exposed',
            'desc':'Telnet transmits credentials in cleartext. Remote code execution risk.',
            'fix':'Disable Telnet. Use SSH instead.'})

    # Anonymous FTP check
    if 21 in port_nums:
        try:
            s = socket.socket(); s.settimeout(3); s.connect((ip,21))
            banner = s.recv(256).decode(errors='ignore')
            s.send(b'USER anonymous\r\n'); r1 = s.recv(256).decode(errors='ignore')
            s.send(b'PASS anon@\r\n'); r2 = s.recv(256).decode(errors='ignore')
            s.close()
            if '230' in r2:
                vulns.append({'id':'FTP-ANON','severity':'HIGH','title':'Anonymous FTP Login Allowed',
                    'desc':'FTP server allows anonymous login, exposing files to the public.',
                    'fix':'Disable anonymous FTP access in the FTP server configuration.'})
        except Exception:
            pass

    # RDP exposed
    if 3389 in port_nums:
        vulns.append({'id':'CVE-2019-0708','severity':'HIGH','title':'RDP Service Exposed (BlueKeep risk)',
            'desc':'RDP exposed to internet. Risk of BlueKeep (CVE-2019-0708) and brute force attacks.',
            'fix':'Restrict RDP behind VPN. Enable NLA. Keep patched.'})

    # MongoDB exposed
    if 27017 in port_nums:
        vulns.append({'id':'MONGO-NOAUTH','severity':'CRITICAL','title':'MongoDB Exposed Without Auth',
            'desc':'MongoDB listening on public interface — often unauthenticated by default.',
            'fix':'Bind MongoDB to localhost. Enable authentication. Use firewall rules.'})

    # Redis exposed
    if 6379 in port_nums:
        vulns.append({'id':'REDIS-NOAUTH','severity':'CRITICAL','title':'Redis Service Exposed',
            'desc':'Redis without auth exposed to internet allows full data access and code execution.',
            'fix':'Add requirepass to redis.conf. Bind to 127.0.0.1. Use firewall.'})

    # Elasticsearch
    if 9200 in port_nums:
        vulns.append({'id':'ELASTIC-UNAUTH','severity':'HIGH','title':'Elasticsearch Exposed',
            'desc':'Elasticsearch accessible without authentication — all indexed data exposed.',
            'fix':'Enable X-Pack security. Restrict port 9200 via firewall.'})

    # Missing security headers
    if http_data.get('missing_security'):
        for h in http_data['missing_security']:
            sev = 'HIGH' if h in ('strict-transport-security','content-security-policy') else 'MEDIUM'
            vulns.append({'id':'HDR-MISSING','severity':sev,'title':f'Missing Header: {h}',
                'desc':f'HTTP response missing the {h} security header.',
                'fix':f'Add the {h} header to your web server/application configuration.'})

    # SSL issues
    if not ssl_data.get('valid',True):
        vulns.append({'id':'SSL-INVALID','severity':'HIGH','title':'Invalid SSL Certificate',
            'desc':'SSL certificate is invalid, expired, or self-signed.',
            'fix':'Install a valid certificate from a trusted CA (e.g. Let\'s Encrypt).'})
    
    for issue in ssl_data.get('issues',[]):
        if 'Weak protocol' in issue:
            vulns.append({'id':'SSL-WEAKPROTO','severity':'MEDIUM','title':issue,
                'desc':'Deprecated TLS protocol version in use. Vulnerable to POODLE/BEAST attacks.',
                'fix':'Disable TLSv1.0 and TLSv1.1. Enable TLSv1.2 and TLSv1.3 only.'})

    # Check for common exposed paths
    exposed_paths = _check_exposed_paths(target)
    vulns.extend(exposed_paths)

    ok_msg(f"Found {C.R}{len(vulns)}{C.RST} potential vulnerabilities")
    return vulns

def _check_exposed_paths(target):
    vulns = []
    paths = {
        '/.git/HEAD': ('GIT-EXPOSED','HIGH','Git Repository Exposed',
            '.git directory accessible — full source code leakage possible.',
            'Block /.git via web server config or remove from web root.'),
        '/.env': ('ENV-EXPOSED','CRITICAL','Environment File Exposed',
            '.env file accessible — API keys, DB credentials exposed.',
            'Block .env access via server config. Never store .env in web root.'),
        '/wp-login.php': ('WP-LOGIN','MEDIUM','WordPress Login Page Exposed',
            'WordPress login accessible — brute force & credential stuffing risk.',
            'Add rate limiting, 2FA, and IP allowlist to wp-login.php.'),
        '/admin': ('ADMIN-PANEL','MEDIUM','Admin Panel Accessible',
            'Admin/dashboard path responds publicly.',
            'Restrict admin area to trusted IPs. Enable strong authentication.'),
        '/phpinfo.php': ('PHPINFO','HIGH','PHPInfo Page Exposed',
            'phpinfo() page leaks server configuration, paths, and PHP settings.',
            'Remove phpinfo.php from production server.'),
        '/.DS_Store': ('DSSTORE','LOW','macOS .DS_Store File Exposed',
            '.DS_Store file leaks directory structure from macOS development.',
            'Add .DS_Store to .gitignore and block via server config.'),
        '/server-status': ('APACHE-STATUS','MEDIUM','Apache Server Status Exposed',
            'Apache server-status page leaks request details and server info.',
            'Restrict /server-status to localhost only.'),
    }
    
    for path, (vid, sev, title, desc, fix) in paths.items():
        for scheme in ['https', 'http']:
            url = f"{scheme}://{target}{path}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'TrustMe/2.4'})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    if r.status == 200:
                        vulns.append({'id':vid,'severity':sev,'title':title,
                            'desc':desc,'fix':fix,'url':url})
                        break
            except Exception:
                pass
    return vulns

# ─── Report generation ────────────────────────────────────────────────────────

def severity_color(sev):
    return {
        'CRITICAL': C.R + C.BOLD,
        'HIGH': C.R,
        'MEDIUM': C.A,
        'LOW': C.G2,
        'INFO': C.B,
    }.get(sev.upper(), C.W)

def print_report(target, ip, geo, dns, subdomains, ports, http_data, ssl_data, whois_parsed, vulns, start_time):
    elapsed = time.time() - start_time

    print_section("HOST INTELLIGENCE")
    print_kv("Target", target, C.B)
    print_kv("IP Address", ip or "unresolved", C.G)
    if geo:
        city = geo.get('city') or geo.get('city','?')
        country = geo.get('country_name') or geo.get('country','?')
        org = geo.get('org') or geo.get('isp','?')
        asn = geo.get('asn','?')
        tz = geo.get('timezone','?')
        print_kv("Geolocation", f"{city}, {country}")
        print_kv("ISP / Org", org)
        print_kv("ASN", asn)
        print_kv("Timezone", tz)

    if whois_parsed:
        print_kv("Registrar", whois_parsed.get('registrar','?'))
        print_kv("Created", whois_parsed.get('created','?'))
        print_kv("Expires", whois_parsed.get('expires','?'))
        ns = whois_parsed.get('name_servers',[])
        if ns: print_kv("Nameservers", ', '.join(ns[:2]))

    if http_data.get('title'):
        print_kv("Page Title", http_data['title'])
    if http_data.get('server'):
        print_kv("Web Server", http_data['server'])
    if http_data.get('powered_by'):
        print_kv("Powered By", http_data['powered_by'])

    # SSL
    print_section("SSL / TLS")
    valid_str = f"{C.G}✓ Valid{C.RST}" if ssl_data.get('valid') else f"{C.R}✗ Invalid{C.RST}"
    print(f"  Status:        {valid_str}")
    if ssl_data.get('issuer'):
        org = ssl_data['issuer'].get('organizationName','') or ssl_data['issuer'].get('O','')
        print_kv("Issuer", org)
    if ssl_data.get('expires'):
        print_kv("Expires", ssl_data['expires'])
    if 'days_left' in ssl_data:
        dc = C.R if ssl_data['days_left'] < 30 else C.G
        print_kv("Days Left", f"{dc}{ssl_data['days_left']}{C.RST}")
    if ssl_data.get('protocol'):
        print_kv("Protocol", ssl_data['protocol'])
    if ssl_data.get('issues'):
        for i in ssl_data['issues']:
            warn_msg(i)

    # Ports
    print_section(f"OPEN PORTS & SERVICES ({len(ports)} found)")
    if ports:
        print(f"  {C.M}{'PORT':<8}{'SERVICE':<15}{'BANNER/VERSION':<35}{'RISK'}{C.RST}")
        print(f"  {C.M}{'─'*65}{C.RST}")
        for p in ports:
            rc = severity_color(p['risk'])
            banner = p['banner'][:32] if p['banner'] else ''
            print(f"  {C.B}{p['port']:<8}{C.RST}{C.G}{p['service']:<15}{C.RST}{C.M}{banner:<35}{C.RST}{rc}{p['risk']}{C.RST}")
    else:
        print(f"  {C.M}No open ports detected{C.RST}")

    # Technologies
    techs = http_data.get('technologies', [])
    if techs:
        print_section(f"TECHNOLOGY STACK ({len(techs)} detected)")
        for t in techs:
            print_item(t)

    # DNS
    if dns:
        print_section(f"DNS RECORDS")
        for rtype, records in dns.items():
            for r in records[:3]:
                print(f"  {C.A}{rtype:<8}{C.RST} {C.W}{r[:70]}{C.RST}")

    # Subdomains
    if subdomains:
        print_section(f"SUBDOMAINS ({len(subdomains)} found)")
        for s in subdomains:
            print(f"  {C.G}→{C.RST} {C.B}{s['subdomain']:<40}{C.RST} {C.M}{s['ip']}{C.RST}")

    # Security headers
    missing = http_data.get('missing_security', [])
    if missing:
        print_section(f"SECURITY HEADERS ({len(missing)} missing)")
        present = [h for h in SECURITY_HEADERS if h not in missing]
        for h in present:
            print(f"  {C.G}✓{C.RST} {h}")
        for h in missing:
            print(f"  {C.R}✗{C.RST} {C.A}{h}{C.RST}  {C.M}← missing{C.RST}")

    # Emails
    emails = whois_parsed.get('emails', [])
    if emails:
        print_section(f"EMAIL ADDRESSES FOUND")
        for e in emails:
            print_item(e, col=C.B)

    # Vulnerabilities
    print_section(f"VULNERABILITIES & FINDINGS ({len(vulns)} total)")
    if vulns:
        crit = [v for v in vulns if v['severity'] == 'CRITICAL']
        high = [v for v in vulns if v['severity'] == 'HIGH']
        med  = [v for v in vulns if v['severity'] == 'MEDIUM']
        low  = [v for v in vulns if v['severity'] == 'LOW']
        print(f"\n  {C.R}CRITICAL: {len(crit)}{C.RST}  {C.R}HIGH: {len(high)}{C.RST}  {C.A}MEDIUM: {len(med)}{C.RST}  {C.G2}LOW: {len(low)}{C.RST}\n")

        for v in sorted(vulns, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].index(x['severity']) if x['severity'] in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] else 99):
            rc = severity_color(v['severity'])
            vid = v.get('id','')
            print(f"  {rc}[{v['severity']}]{C.RST} {C.W}{v['title']}{C.RST}  {C.M}{vid}{C.RST}")
            print(f"  {C.M}  ↳ {v['desc']}{C.RST}")
            print(f"  {C.G2}  → FIX: {v['fix']}{C.RST}")
            if v.get('url'):
                print(f"  {C.B}  ↗ {v['url']}{C.RST}")
            print()
    else:
        print(f"  {C.G}No significant vulnerabilities found.{C.RST}")

    # Footer
    print(f"\n{C.G2}{'═'*60}{C.RST}")
    print(f"  {C.M}Scan completed in {elapsed:.1f}s  |  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RST}")
    print(f"  {C.A}⚠  This is a passive/semi-active recon tool.{C.RST}")
    print(f"  {C.A}⚠  Only use on systems you own or have written permission to test.{C.RST}")
    print(f"{C.G2}{'═'*60}{C.RST}\n")

# ─── JSON report ──────────────────────────────────────────────────────────────

def save_json_report(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    ok_msg(f"JSON report saved → {C.B}{path}{C.RST}")

def save_txt_report(path, content):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub('', content)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        f.write(clean)
    ok_msg(f"Text report saved → {C.B}{path}{C.RST}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='TrustMe — Automated Web Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 trustme.py example.com
  python3 trustme.py example.com -o reports/
  python3 trustme.py example.com --ports 80,443,8080,3306
  python3 trustme.py example.com --no-subdomains --no-color
  python3 trustme.py example.com --full
        """
    )
    parser.add_argument('target', help='Target domain (e.g. example.com)')
    parser.add_argument('-o', '--output', default='./reports', help='Output directory for reports (default: ./reports)')
    parser.add_argument('--ports', help='Comma-separated ports to scan (default: common 28 ports)')
    parser.add_argument('--no-subdomains', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--no-dns', action='store_true', help='Skip DNS enumeration')
    parser.add_argument('--no-vuln', action='store_true', help='Skip vulnerability checks')
    parser.add_argument('--no-color', action='store_true', help='Disable color output')
    parser.add_argument('--full', action='store_true', help='Extended subdomain wordlist + nmap if available')
    parser.add_argument('--json', action='store_true', help='Save JSON report')
    parser.add_argument('--quiet', action='store_true', help='Minimal output (report only)')
    args = parser.parse_args()

    # Sanitize target
    target = args.target.strip().lower().replace('https://', '').replace('http://', '').rstrip('/')
    
    if not args.quiet:
        print(BANNER)
        print(f"  {C.G}Target:{C.RST} {C.B}{target}{C.RST}")
        print(f"  {C.G}Time:  {C.RST} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {C.M}{'─'*50}{C.RST}\n")

    start_time = time.time()

    # Resolve
    ip = resolve_host(target)
    if not ip:
        sys.exit(1)

    # Geo
    geo = get_geoip(ip)

    # DNS
    dns = {}
    if not args.no_dns:
        dns = enumerate_dns(target)

    # WHOIS
    whois_raw = get_whois(target)
    whois_parsed = parse_whois(whois_raw)

    # Ports
    custom_ports = None
    if args.ports:
        custom_ports = [int(p.strip()) for p in args.ports.split(',')]
    open_port_nums = scan_ports_fast(ip, ports=custom_ports)
    ports = get_port_details(ip, open_port_nums)

    # nmap (if --full and available)
    nmap_out = None
    if args.full:
        nmap_out = nmap_scan(ip)

    # HTTP
    http_data = analyze_http(target, ip)

    # SSL
    ssl_data = check_ssl(target)

    # Subdomains
    subdomains = []
    if not args.no_subdomains:
        subdomains = brute_subdomains(target)

    # Vulns
    vulns = []
    if not args.no_vuln:
        vulns = check_common_vulns(target, ip, ports, http_data, ssl_data)

    # Print report
    print_report(target, ip, geo, dns, subdomains, ports, http_data, ssl_data, whois_parsed, vulns, start_time)

    # Save reports
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_data = {
        'meta': {'target': target, 'ip': ip, 'timestamp': ts, 'tool': 'TrustMe v2.4'},
        'geo': geo, 'dns': dns, 'whois': whois_parsed,
        'ssl': ssl_data, 'ports': ports,
        'http': {'status': http_data.get('status_code'), 'title': http_data.get('title'),
                 'server': http_data.get('server'), 'powered_by': http_data.get('powered_by'),
                 'technologies': http_data.get('technologies',[]),
                 'missing_headers': http_data.get('missing_security',[])},
        'subdomains': subdomains,
        'vulnerabilities': vulns,
    }

    if args.json:
        save_json_report(str(out_dir / f"trustme_{target}_{ts}.json"), report_data)

    # Always save text
    import io
    save_json_report(str(out_dir / f"trustme_{target}_{ts}.json"), report_data)
    print(f"\n  {C.G2}Reports saved to {C.B}{out_dir}/{C.RST}")

if __name__ == '__main__':
    main()
