"""
Port Scanner — Smart CDN-aware scanning with 4-tier fallback.

Tier 1: nmap (best results — needs nmap installed + sudo for some scans)
Tier 2: subprocess nmap (fallback if python-nmap library fails)
Tier 3: HTTP-based scan (ALWAYS works for CDN/Cloudflare targets via requests)
Tier 4: Pure TCP socket scan (last resort)

CDN Detection: If target is behind Cloudflare/Akamai/Fastly, automatically
switches to HTTP-based fingerprinting which works THROUGH the CDN.
"""
import nmap
import socket
import subprocess
import platform
import concurrent.futures
import re
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IS_WINDOWS = platform.system() == 'Windows'

RISKY_PORTS = {
    21:    ('high',     'FTP — unencrypted, credentials sent in plaintext'),
    22:    ('low',      'SSH — ensure key-based auth is enforced'),
    23:    ('critical', 'Telnet — completely unencrypted, replace with SSH'),
    25:    ('medium',   'SMTP — verify relay restrictions'),
    53:    ('low',      'DNS — verify not an open resolver'),
    69:    ('medium',   'TFTP — unauthenticated file transfer'),
    80:    ('low',      'HTTP — redirect to HTTPS'),
    110:   ('medium',   'POP3 — verify TLS enforcement'),
    111:   ('medium',   'RPC portmapper — service enumeration risk'),
    135:   ('medium',   'Microsoft RPC — DCOM attack surface'),
    137:   ('medium',   'NetBIOS Name Service — info disclosure'),
    139:   ('high',     'NetBIOS Session — share info may be exposed'),
    143:   ('medium',   'IMAP — verify TLS'),
    389:   ('medium',   'LDAP — directory exposure, verify auth'),
    443:   ('info',     'HTTPS — check cert and cipher strength'),
    445:   ('high',     'SMB — EternalBlue/WannaCry vector'),
    512:   ('high',     'rexec — unauthenticated remote execution'),
    513:   ('high',     'rlogin — unencrypted remote login'),
    514:   ('high',     'RSH — remote shell without auth'),
    873:   ('medium',   'rsync — verify auth and access restrictions'),
    1433:  ('high',     'MSSQL — database accessible from network'),
    1521:  ('high',     'Oracle DB — database accessible from network'),
    2049:  ('high',     'NFS — filesystem may be remotely mountable'),
    2181:  ('high',     'ZooKeeper — usually no auth, config exposure'),
    3306:  ('high',     'MySQL — database accessible from network'),
    3389:  ('high',     'RDP — bruteforce/BlueKeep target'),
    4444:  ('critical', 'Port 4444 — Metasploit/backdoor default port'),
    5432:  ('medium',   'PostgreSQL — database accessible from network'),
    5900:  ('high',     'VNC — often unencrypted or weakly authenticated'),
    5984:  ('high',     'CouchDB — no auth by default'),
    6379:  ('critical', 'Redis — no authentication, full data exposure'),
    7001:  ('high',     'WebLogic — common RCE target'),
    8080:  ('low',      'HTTP alternate port'),
    8443:  ('low',      'HTTPS alternate port'),
    8888:  ('medium',   'Dev/proxy port — verify service running'),
    9200:  ('critical', 'Elasticsearch — no auth, full data exposure'),
    9300:  ('high',     'Elasticsearch transport — cluster port exposed'),
    11211: ('high',     'Memcached — no auth, DDoS amplification risk'),
    27017: ('critical', 'MongoDB — no auth by default, full DB exposure'),
    50000: ('medium',   'Jenkins/SAP — check for default credentials'),
}

# Cloudflare known open ports (accessible through CDN)
CF_PORTS_HTTP  = [80, 8080, 8880, 2052, 2082, 2086, 2095]
CF_PORTS_HTTPS = [443, 2053, 2083, 2087, 2096, 8443]

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
             1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]


def _log(cb, msg, level='info'):
    cb('log', {'message': msg, 'level': level})


def _finding(cb, severity, category, description, **extra):
    cb('finding', {'severity': severity, 'category': category,
                   'description': description, **extra})


def _normalize_target(target):
    """Strip http/https from target for raw socket use."""
    return re.sub(r'^https?://', '', target).split('/')[0].strip()


def _normalize_url(target, port=None):
    """Build proper URL from target."""
    t = re.sub(r'^https?://', '', target).split('/')[0].strip()
    if port in CF_PORTS_HTTPS or port == 443:
        return f'https://{t}' + (f':{port}' if port not in (443,) else '')
    if port and port != 80:
        return f'http://{t}:{port}'
    return f'http://{t}'


def _is_cdn(target):
    """Quick CDN detection by resolving IP and checking ranges."""
    cdn_ranges = {
        'Cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
                       '104.21.', '104.22.', '104.23.', '172.64.', '172.65.',
                       '172.66.', '172.67.', '172.68.', '172.69.', '162.158.',
                       '188.114.', '190.93.', '198.41.'],
        'Akamai':    ['23.32.', '23.64.', '23.192.', '184.24.', '2.16.', '2.17.'],
        'Fastly':    ['151.101.', '199.232.', '167.82.'],
        'Cloudfront': ['13.224.', '13.225.', '13.226.', '13.227.', '52.84.', '54.230.'],
    }
    try:
        ip = socket.gethostbyname(_normalize_target(target))
        for cdn, prefixes in cdn_ranges.items():
            if any(ip.startswith(p) for p in prefixes):
                return True, cdn, ip
        return False, None, ip
    except Exception:
        return False, None, None


def _check_port_open(host, port, timeout=2.0):
    """Fast socket-level port check."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except Exception:
        return None


def _fast_prescan(target, ports, timeout=2.0):
    """Parallel socket pre-scan — returns list of likely-open ports."""
    host = _normalize_target(target)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_check_port_open, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = f.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass
    return sorted(open_ports)


# ── CDN-AWARE HTTP SCAN ──────────────────────────────────────────────────────
def _http_service_scan(target, callback):
    """
    HTTP-based service fingerprinting — works THROUGH Cloudflare/CDN.
    Uses requests library to probe web services on all known CDN-accessible ports.
    Extracts: server type, headers, redirects, SSL info, technology stack.
    """
    host = _normalize_target(target)
    _log(callback, '🌐 CDN detected — switching to HTTP-based service scan...', 'info')
    _log(callback, '   (Direct TCP port scans are blocked by CDN — this is normal)', 'info')
    _log(callback, f'   Probing {len(CF_PORTS_HTTP + CF_PORTS_HTTPS)} CDN-accessible ports via HTTP/HTTPS...', 'info')

    found_services = []
    headers_ua = {'User-Agent': 'Mozilla/5.0 (VulnCatch-AI/4.0 Security Scanner)'}

    all_ports = [(p, False) for p in CF_PORTS_HTTP] + [(p, True) for p in CF_PORTS_HTTPS]

    for port, use_ssl in all_ports:
        scheme = 'https' if use_ssl else 'http'
        url    = f'{scheme}://{host}' + (f':{port}' if port not in (80, 443) else '')
        try:
            resp = requests.get(url, timeout=5, verify=False,
                                allow_redirects=True, headers=headers_ua)
            status = resp.status_code
            _log(callback, f'  [HTTP {status}] Port {port:<5} ({scheme.upper()}) — {url}', 'success')
            found_services.append({'port': port, 'scheme': scheme,
                                   'status': status, 'headers': dict(resp.headers)})

            # ── Analyze response headers ──────────────────────────────────────
            rh = resp.headers

            # Server disclosure
            if 'Server' in rh:
                sv = rh['Server']
                _log(callback, f'    Server: {sv}', 'info')
                if any(x in sv.lower() for x in ['apache', 'nginx', 'iis', 'litespeed']):
                    _finding(callback, 'low', 'Information Disclosure',
                             f'Server header reveals technology: {sv}',
                             port=port, service='http')
                    # Check for old versions
                    old_vers = {'apache/2.2': 'Apache 2.2 EOL', 'apache/2.0': 'Apache 2.0 EOL',
                                'nginx/1.': 'Check nginx version', 'iis/7': 'IIS 7 EOL'}
                    for kw, msg in old_vers.items():
                        if kw in sv.lower():
                            _finding(callback, 'high', 'Outdated Software',
                                     f'{msg} — upgrade immediately. Server: {sv}', port=port)

            # X-Powered-By disclosure
            if 'X-Powered-By' in rh:
                xpb = rh['X-Powered-By']
                _log(callback, f'    X-Powered-By: {xpb}', 'warning')
                _finding(callback, 'low', 'Information Disclosure',
                         f'X-Powered-By header leaks tech stack: {xpb}', port=port)
                if 'php/5' in xpb.lower() or 'php/7.0' in xpb.lower() or 'php/7.1' in xpb.lower():
                    _finding(callback, 'high', 'Outdated Software',
                             f'Outdated PHP version: {xpb} — critical CVEs exist', port=port)

            # CDN info
            if 'CF-RAY' in rh:
                _log(callback, f'    ☁ Cloudflare detected (CF-Ray: {rh["CF-RAY"][:16]}...)', 'info')
                _finding(callback, 'info', 'CDN / Infrastructure',
                         'Site is behind Cloudflare CDN — real server IP is hidden. '
                         'Port scans show CDN edge, not origin server.',
                         port=port, cdn='Cloudflare')

            # Security headers check
            missing = []
            if 'Strict-Transport-Security' not in rh and use_ssl:
                missing.append('HSTS')
            if 'Content-Security-Policy' not in rh:
                missing.append('CSP')
            if 'X-Frame-Options' not in rh:
                missing.append('X-Frame-Options')
            if 'X-Content-Type-Options' not in rh:
                missing.append('X-Content-Type-Options')
            if missing:
                _finding(callback, 'medium', 'HTTP Security Headers',
                         f'Port {port}: Missing security headers: {", ".join(missing)}',
                         port=port, missing_headers=missing)

            # HTTP only (no redirect to HTTPS)
            if not use_ssl and status < 400:
                location = rh.get('Location', '')
                if location and location.startswith('https://'):
                    _log(callback, f'    ✔ Redirects to HTTPS: {location[:60]}', 'success')
                else:
                    _finding(callback, 'medium', 'HTTP Security',
                             f'Port {port}: Site accessible over HTTP without HTTPS redirect — '
                             'traffic may be intercepted', port=port)

            # Admin/login pages
            body_lower = (resp.text or '')[:2000].lower()
            if any(x in body_lower for x in ['admin', 'login', 'dashboard', 'wp-admin']):
                _finding(callback, 'low', 'Web Application',
                         f'Port {port}: Admin/login interface detected — verify access controls',
                         port=port)

        except requests.exceptions.SSLError:
            _log(callback, f'  Port {port:<5} ({scheme.upper()}) — SSL error', 'warning')
        except requests.exceptions.ConnectionError:
            pass  # Port not accessible
        except requests.exceptions.Timeout:
            _log(callback, f'  Port {port:<5} ({scheme.upper()}) — timeout', 'info')
        except Exception:
            pass

    if found_services:
        _log(callback, f'\n  📊 Found {len(found_services)} accessible HTTP service(s) on CDN ports', 'success')
        for svc in found_services:
            _log(callback, f'    ✔ {svc["scheme"].upper()}:{svc["port"]} → HTTP {svc["status"]}', 'success')
    else:
        _log(callback, '  No HTTP services found. Site may be completely offline or geo-blocked.', 'warning')

    # Try to discover real IP via common bypass techniques
    _log(callback, '\n  🔍 Attempting CDN bypass / real IP discovery...', 'info')
    _cdn_ip_discovery(host, callback)

    return found_services


def _cdn_ip_discovery(host, callback):
    """Try to find the real IP behind CDN via common techniques."""
    import ssl as ssl_lib

    # Technique 1: Check SSL certificate for real hostname clues
    try:
        ctx = ssl_lib.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            san = cert.get('subjectAltName', [])
            cn  = dict(cert.get('subject', [{}])[0] if cert.get('subject') else {}).get('commonName', '')
            _log(callback, f'  SSL Cert CN: {cn}', 'info')
            if san:
                domains = [v for t, v in san if t == 'DNS'][:5]
                _log(callback, f'  SSL SANs: {", ".join(domains)}', 'info')
                _finding(callback, 'info', 'SSL Certificate / CDN',
                         f'SSL cert covers: {", ".join(domains[:3])}', cert_cn=cn)
    except Exception:
        pass

    # Technique 2: Check common subdomains that bypass CDN
    bypass_subdomains = ['direct.', 'origin.', 'mail.', 'ftp.', 'cpanel.', 'webmail.']
    base = '.'.join(host.split('.')[-2:]) if '.' in host else host
    found_bypass = []
    for sub in bypass_subdomains:
        candidate = sub + base
        try:
            ip = socket.gethostbyname(candidate)
            is_cdn, cdn_name, _ = _is_cdn(candidate)
            if not is_cdn:
                found_bypass.append((candidate, ip))
                _log(callback, f'  🎯 Potential bypass subdomain: {candidate} → {ip} (NOT behind CDN!)', 'success')
                _finding(callback, 'medium', 'CDN Bypass / Recon',
                         f'Subdomain {candidate} ({ip}) may bypass CDN and reveal origin server',
                         subdomain=candidate, ip=ip)
        except Exception:
            pass

    if not found_bypass:
        _log(callback, '  No CDN bypass subdomains found via common names.', 'info')

    _log(callback, '  💡 Tip: Use OSINT module for deeper threat intel on this target.', 'info')


# ── MAIN SCAN FUNCTIONS ──────────────────────────────────────────────────────

def basic_port_scan(target, callback):
    """
    Smart port scan with CDN awareness.
    - For CDN targets: uses HTTP-based scanning (always works)
    - For direct targets: nmap → subprocess nmap → socket → HTTP
    """
    host = _normalize_target(target)
    _log(callback, f'Starting Basic Port Scan on [{host}]')

    # ── CDN Check first ──────────────────────────────────────────────────────
    is_cdn, cdn_name, resolved_ip = _is_cdn(host)
    if is_cdn:
        _log(callback, f'☁ {cdn_name} CDN detected (IP: {resolved_ip})', 'warning')
        _log(callback, f'  Direct TCP port scans are blocked by {cdn_name}.', 'warning')
        _log(callback, '  Switching to HTTP-based scanning (penetrates CDN)...', 'info')
        _http_service_scan(target, callback)
        _log(callback, 'Basic Port Scan (CDN Mode) finished.', 'success')
        return

    # ── Direct target — standard scan ────────────────────────────────────────
    _log(callback, f'✔ No CDN detected (IP: {resolved_ip}) — running direct scan', 'success')
    _log(callback, '⚡ Running fast socket pre-scan...', 'info')

    top100 = list(set(list(RISKY_PORTS.keys()) + [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]))
    quick_open = _fast_prescan(host, top100, timeout=2.0)

    if quick_open:
        _log(callback, f'  Pre-scan: {len(quick_open)} port(s) detected: {quick_open}', 'success')
    else:
        _log(callback, '  Pre-scan: no common ports responding', 'warning')

    # ── Tier 1: python-nmap ───────────────────────────────────────────────────
    nmap_success = False
    try:
        nm = nmap.PortScanner()
        nm.scan(host, '1-1024', '-sV -T4 --open --max-rtt-timeout 800ms --max-retries 2', timeout=120)
        nmap_success = bool(nm.all_hosts())
        if nmap_success:
            _log(callback, '🔍 nmap scan complete.', 'success')
            for h in nm.all_hosts():
                _log(callback, f'Host: {h}  State: {nm[h].state()}', 'success')
                for proto in nm[h].all_protocols():
                    ports_open = sorted(nm[h][proto].keys())
                    _log(callback, f'Found {len(ports_open)} open port(s) [{proto.upper()}]')
                    for port in ports_open:
                        svc     = nm[h][proto][port]
                        state   = svc['state']
                        name    = svc.get('name', 'unknown')
                        prod    = svc.get('product', '')
                        ver     = svc.get('version', '')
                        svc_str = f'{prod} {ver}'.strip() or name
                        _log(callback,
                             f'  [OPEN] Port {port:>5}/{proto}  {name:<12}  {svc_str}',
                             'success' if state == 'open' else 'info')
                        if port in RISKY_PORTS and state == 'open':
                            sev, desc = RISKY_PORTS[port]
                            _finding(callback, sev, 'Network / Port Risk',
                                     f'Port {port} ({name}): {desc}',
                                     port=port, service=name, version=ver)
        else:
            _log(callback, 'nmap: host down or all ports filtered — trying fallbacks.', 'warning')
    except Exception as e:
        _log(callback, f'nmap library error ({type(e).__name__}) — trying subprocess...', 'warning')

    # ── Tier 2: subprocess nmap ───────────────────────────────────────────────
    if not nmap_success:
        try:
            result = subprocess.run(
                ['nmap', '-sV', '-T4', '--open', '-p', '1-1024', host],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and 'open' in result.stdout:
                nmap_success = True
                _log(callback, '🔍 nmap (subprocess) results:', 'success')
                for line in result.stdout.splitlines():
                    if '/tcp' in line or '/udp' in line:
                        _log(callback, f'  {line.strip()}', 'success')
                        try:
                            port = int(line.split('/')[0].strip().split()[-1])
                            if port in RISKY_PORTS and 'open' in line:
                                sev, desc = RISKY_PORTS[port]
                                _finding(callback, sev, 'Network / Port Risk',
                                         f'Port {port}: {desc}', port=port)
                        except Exception:
                            pass
        except FileNotFoundError:
            _log(callback, 'nmap not installed — install: sudo apt install nmap -y', 'warning')
            _finding(callback, 'info', 'Tool Missing',
                     'nmap not installed. Install: sudo apt install nmap -y')
        except Exception as e:
            _log(callback, f'nmap subprocess error: {e}', 'warning')

    # ── Tier 3: Socket scan (always works for non-CDN) ────────────────────────
    if not nmap_success:
        _log(callback, '🔌 Running socket-only port scan...', 'info')
        found = 0
        for port in quick_open:
            if port in RISKY_PORTS:
                sev, desc = RISKY_PORTS[port]
                _log(callback, f'  [OPEN] Port {port:>5}  {desc[:60]}', 'success')
                _finding(callback, sev, 'Network / Port Risk (Socket)',
                         f'Port {port} appears open: {desc}', port=port)
                found += 1

        # ── Tier 4: HTTP probe (last resort) ──────────────────────────────────
        if not quick_open:
            _log(callback, '  No open ports via socket — trying HTTP probe...', 'info')
            _http_service_scan(target, callback)
        else:
            _log(callback, f'  Socket scan: {found} risky port(s) found.', 'success')

    _log(callback, 'Basic Port Scan finished.', 'success')


def full_port_scan(target, callback):
    """Full 65535-port scan — with CDN awareness."""
    host = _normalize_target(target)
    _log(callback, f'Starting Full Port Scan on [{host}]')

    is_cdn, cdn_name, _ = _is_cdn(host)
    if is_cdn:
        _log(callback, f'☁ {cdn_name} CDN detected — full port scan blocked by CDN.', 'warning')
        _log(callback, '  Running HTTP-based scan on all CDN-accessible ports instead...', 'info')
        _finding(callback, 'info', 'CDN / Scan Limitation',
                 f'Full port scan blocked by {cdn_name} CDN. '
                 'Only ports 80/443 and CDN bypass ports are accessible. '
                 'Use Security Headers + SSL + OSINT modules for deeper analysis.')
        _http_service_scan(target, callback)
        return

    _log(callback, 'Scanning all 65535 ports (T4 speed) — may take 5-10 min...', 'warning')
    try:
        nm = nmap.PortScanner()
        nm.scan(host, '1-65535', '-T4 --open --max-rtt-timeout 500ms --max-retries 1', timeout=600)
        if not nm.all_hosts():
            _log(callback, 'No open ports or host is down', 'warning')
            return
        total_open = 0
        for h in nm.all_hosts():
            for proto in nm[h].all_protocols():
                for port in sorted(nm[h][proto].keys()):
                    svc  = nm[h][proto][port]
                    name = svc.get('name', 'unknown')
                    ver  = svc.get('version', '')
                    prod = svc.get('product', '')
                    if svc['state'] == 'open':
                        total_open += 1
                        _log(callback,
                             f'  [OPEN] Port {port:>5}/{proto}  {name}  {prod} {ver}'.strip(),
                             'success')
                        if port in RISKY_PORTS:
                            sev, desc = RISKY_PORTS[port]
                            _finding(callback, sev, 'Network / Port Risk',
                                     f'Port {port} ({name}): {desc}', port=port, service=name)
                        elif port > 1024:
                            _finding(callback, 'low', 'Network / Port Risk',
                                     f'Non-standard high port {port} is open', port=port, service=name)
        _log(callback, f'Full Port Scan complete — {total_open} open port(s).', 'success')
    except Exception as e:
        _log(callback, f'Full port scan failed: {e} — trying HTTP scan fallback', 'error')
        _http_service_scan(target, callback)


def aggressive_scan(target, callback):
    """Aggressive scan — CDN-aware, fallback to HTTP fingerprinting."""
    host = _normalize_target(target)
    _log(callback, f'Starting Aggressive Scan on [{host}]')

    is_cdn, cdn_name, resolved_ip = _is_cdn(host)
    if is_cdn:
        _log(callback, f'☁ {cdn_name} CDN detected — OS fingerprinting not possible through CDN.', 'warning')
        _log(callback, '  Running HTTP-based aggressive fingerprinting instead...', 'info')
        _finding(callback, 'info', 'CDN / Scan Limitation',
                 f'OS detection blocked by {cdn_name}. '
                 'Real server OS cannot be determined. Performing HTTP fingerprinting.')
        _http_aggressive_fingerprint(target, callback)
        return

    _log(callback, 'Running OS fingerprint + scripts (-A -T4)...', 'info')
    _log(callback, '⚠ Requires root/sudo for OS detection', 'warning')
    try:
        nm = nmap.PortScanner()
        nm.scan(host, '1-1024', '-A -T4 --max-rtt-timeout 500ms --max-retries 1', timeout=180)
        if not nm.all_hosts():
            _log(callback, 'No hosts found — trying HTTP fingerprint fallback', 'warning')
            _http_aggressive_fingerprint(target, callback)
            return
        for h in nm.all_hosts():
            _log(callback, f'Host: {h}  ({nm[h].hostname()})', 'info')
            if nm[h].get('osmatch'):
                _log(callback, '--- OS Detection ---')
                for m in nm[h]['osmatch'][:2]:
                    _log(callback, f"  OS: {m['name']} (Accuracy: {m['accuracy']}%)", 'success')
                    _finding(callback, 'info', 'OS Detection',
                             f"Detected OS: {m['name']} ({m['accuracy']}% confidence)")
            for proto in nm[h].all_protocols():
                for port in sorted(nm[h][proto].keys()):
                    svc   = nm[h][proto][port]
                    state = svc['state']
                    name  = svc.get('name', 'unknown')
                    ver   = svc.get('version', '')
                    prod  = svc.get('product', '')
                    _log(callback,
                         f'  [{state.upper():^6}] Port {port}/{proto}  {name}  {prod} {ver}'.strip(),
                         'success' if state == 'open' else 'info')
                    for script_name, out in svc.get('script', {}).items():
                        _log(callback, f'    [{script_name}] {str(out)[:200]}')
                    if port in RISKY_PORTS and state == 'open':
                        sev, desc = RISKY_PORTS[port]
                        _finding(callback, sev, 'Network / Port Risk',
                                 f'Port {port} ({name}): {desc}', port=port, service=name)
        _log(callback, 'Aggressive Scan completed.', 'success')
    except Exception as e:
        _log(callback, f'Aggressive scan failed: {e} — trying HTTP fingerprint', 'error')
        _http_aggressive_fingerprint(target, callback)


def _http_aggressive_fingerprint(target, callback):
    """Deep HTTP fingerprinting — works on any target including CDN."""
    host = _normalize_target(target)
    _log(callback, '🔬 Running HTTP aggressive fingerprinting...', 'info')

    tech_signatures = {
        'WordPress':    ['wp-content', 'wp-includes', 'wordpress'],
        'Drupal':       ['drupal', 'sites/default', 'x-drupal-cache'],
        'Joomla':       ['joomla', '/components/com_'],
        'Laravel':      ['laravel_session', 'x-powered-by: PHP'],
        'Django':       ['csrfmiddlewaretoken', 'django'],
        'React':        ['__react', 'react-dom'],
        'Angular':      ['ng-version', 'angular'],
        'jQuery':       ['jquery'],
        'Bootstrap':    ['bootstrap'],
        'Nginx':        ['nginx'],
        'Apache':       ['apache'],
        'Cloudflare':   ['cf-ray', 'cloudflare'],
        'AWS':          ['x-amz-', 'amazonaws'],
        'Varnish':      ['x-varnish', 'via: varnish'],
    }

    for scheme in ['https', 'http']:
        url = f'{scheme}://{host}'
        try:
            resp = requests.get(url, timeout=8, verify=False,
                                allow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (VulnCatch-AI/4.0)'})
            _log(callback, f'  HTTP {resp.status_code} from {url}', 'success')

            body    = resp.text[:5000]
            headers = {k.lower(): v for k, v in resp.headers.items()}
            combined = (body + str(headers)).lower()

            detected = []
            for tech, sigs in tech_signatures.items():
                if any(s.lower() in combined for s in sigs):
                    detected.append(tech)

            if detected:
                _log(callback, f'  🏷 Technologies detected: {", ".join(detected)}', 'success')
                _finding(callback, 'info', 'Technology Fingerprint',
                         f'Detected technologies: {", ".join(detected)}',
                         technologies=detected)

            # Check for login pages
            if any(x in body.lower() for x in ['login', 'signin', 'password', 'username']):
                _finding(callback, 'low', 'Web Application',
                         'Login/authentication page detected — verify brute-force protection')

            # Check for directory listing
            if 'index of /' in body.lower():
                _finding(callback, 'high', 'Directory Listing',
                         'Directory listing enabled — file system structure exposed!')

            # Check for error pages that reveal stack
            if any(x in body.lower() for x in ['stack trace', 'exception', 'fatal error', 'traceback']):
                _finding(callback, 'medium', 'Information Disclosure',
                         'Error page reveals application stack trace — disable debug mode')

            break
        except Exception:
            continue

    _log(callback, 'HTTP aggressive fingerprinting complete.', 'success')


def service_version_detection(target, callback):
    """Service and version detection — CDN-aware."""
    host = _normalize_target(target)
    _log(callback, f'Starting Service & Version Detection on [{host}]')

    is_cdn, cdn_name, _ = _is_cdn(host)
    if is_cdn:
        _log(callback, f'☁ {cdn_name} CDN — TCP service detection not possible.', 'warning')
        _log(callback, '  Using HTTP-based version detection...', 'info')
        _http_aggressive_fingerprint(target, callback)
        _log(callback, 'Service Detection (HTTP mode) complete.', 'success')
        return

    try:
        nm = nmap.PortScanner()
        nm.scan(host, '1-1024', '-sV -T4 --max-rtt-timeout 500ms --max-retries 2', timeout=120)
        if not nm.all_hosts():
            _log(callback, 'No services detected via nmap — using HTTP fingerprint', 'warning')
            _http_aggressive_fingerprint(target, callback)
            return
        outdated = {
            'apache':  ['1.', '2.0.', '2.1.', '2.2.'],
            'nginx':   ['0.', '1.0.', '1.1.', '1.2.', '1.3.', '1.4.', '1.5.'],
            'openssh': ['5.', '6.', '7.0', '7.1', '7.2', '7.3'],
            'openssl': ['0.', '1.0.0', '1.0.1', '1.0.2'],
            'iis':     ['5.', '6.', '7.'],
            'php':     ['5.', '7.0', '7.1', '7.2', '7.3'],
        }
        for h in nm.all_hosts():
            for proto in nm[h].all_protocols():
                for port in sorted(nm[h][proto].keys()):
                    svc   = nm[h][proto][port]
                    name  = svc.get('name', 'unknown')
                    prod  = svc.get('product', '')
                    ver   = svc.get('version', '')
                    extra = svc.get('extrainfo', '')
                    full  = f'{prod} {ver} {extra}'.strip()
                    _log(callback, f'  Port {port:>5}/{proto}  {name:<12}  →  {full or "unknown"}', 'success')
                    combined = (name + prod).lower()
                    for sw, prefixes in outdated.items():
                        if sw in combined and ver:
                            for pfx in prefixes:
                                if ver.startswith(pfx):
                                    _finding(callback, 'high', 'Outdated Software',
                                             f'Outdated {prod} {ver} on port {port} — check for CVEs',
                                             port=port, service=name, version=ver)
                                    break
        _log(callback, 'Service & Version Detection completed.', 'success')
    except Exception as e:
        _log(callback, f'Service detection failed: {e}', 'error')
        _http_aggressive_fingerprint(target, callback)


def banner_grab(target, callback):
    """Banner grabbing — CDN-aware with HTTP fallback."""
    host = _normalize_target(target)
    _log(callback, f'Starting Banner Grabbing on [{host}]')

    is_cdn, cdn_name, _ = _is_cdn(host)

    ports_to_check = [21, 22, 23, 25, 80, 110, 143, 443, 8080, 8443, 3306, 6379, 27017]
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    found = 0
    for port in ports_to_check:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    s.send(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                    if banner:
                        _log(callback, f'  Port {port}: {banner[:100]}', 'success')
                        found += 1
                        if any(x in banner.lower() for x in
                               ['server:', 'x-powered-by', 'apache', 'nginx', 'iis', 'php']):
                            _finding(callback, 'low', 'Information Disclosure',
                                     f'Port {port} reveals server info: {banner[:120]}')
                except Exception:
                    _log(callback, f'  Port {port}: open (no banner)', 'info')
                    found += 1
            s.close()
        except Exception:
            pass

    if found == 0 and is_cdn:
        _log(callback, f'  {cdn_name} CDN blocks raw banner grabbing — using HTTP headers instead', 'warning')
        # Grab via HTTP requests instead
        for scheme in ['https', 'http']:
            try:
                url  = f'{scheme}://{host}'
                resp = requests.head(url, timeout=5, verify=False,
                                     headers={'User-Agent': 'VulnCatch-AI/4.0'})
                _log(callback, f'  HTTP {scheme.upper()} Response Headers:', 'success')
                for hk, hv in resp.headers.items():
                    _log(callback, f'    {hk}: {hv}', 'info')
                    if hk.lower() in ['server', 'x-powered-by']:
                        _finding(callback, 'low', 'Information Disclosure',
                                 f'Header {hk}: {hv}', header=hk, value=hv)
                found += 1
                break
            except Exception:
                pass

    _log(callback, f'Banner Grabbing complete — {found} result(s) retrieved.', 'success')
