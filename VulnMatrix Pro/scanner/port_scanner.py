"""Port Scanner — 3-tier fallback: python-nmap → subprocess nmap → pure socket."""
import nmap
import socket
import subprocess
import platform
import concurrent.futures
import threading

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

# Top ports for fast pre-scan
TOP_PORTS = [21,22,23,25,53,80,110,135,139,143,389,443,445,
             1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017]


def _log(cb, msg, level='info'):
    cb('log', {'message': msg, 'level': level})


def _finding(cb, severity, category, description, **extra):
    cb('finding', {'severity': severity, 'category': category,
                   'description': description, **extra})


def _check_port_open(host, port, timeout=1.5):
    """Fast socket-level port check."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except Exception:
        return None


def _fast_prescan(target, ports, timeout=1.5):
    """Parallel socket pre-scan — returns list of likely-open ports."""
    open_ports = []
    # Resolve hostname to IP first
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_check_port_open, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures, timeout=10):
            try:
                result = f.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass
    return sorted(open_ports)


def basic_port_scan(target, callback):
    """Fast basic port scan — 3-tier fallback: nmap → subprocess nmap → pure socket."""
    _log(callback, f'Starting Basic Port Scan on [{target}]')
    _log(callback, '⚡ Running fast socket pre-scan on top ports...', 'info')

    top100 = list(set(list(RISKY_PORTS.keys()) + [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]))
    quick_open = _fast_prescan(target, top100)

    if quick_open:
        _log(callback, f'  Pre-scan found {len(quick_open)} potentially open port(s): {quick_open}', 'success')
    else:
        _log(callback, '  Pre-scan: no common ports open (may be behind firewall/CDN)', 'warning')

    # ── Tier 1: python-nmap library ──────────────────────────────────────────
    nmap_success = False
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '1-1024', '-sV -T4 --open --max-rtt-timeout 500ms --max-retries 1', timeout=90)
        nmap_success = bool(nm.all_hosts())
        if nmap_success:
            _log(callback, '🔍 nmap scan complete.', 'success')
            for host in nm.all_hosts():
                _log(callback, f'Host: {host}  State: {nm[host].state()}', 'success')
                for proto in nm[host].all_protocols():
                    ports = sorted(nm[host][proto].keys())
                    _log(callback, f'Found {len(ports)} open port(s) [{proto.upper()}]')
                    for port in ports:
                        svc   = nm[host][proto][port]
                        state = svc['state']
                        name  = svc.get('name', 'unknown')
                        prod  = svc.get('product', '')
                        ver   = svc.get('version', '')
                        svc_str = f'{prod} {ver}'.strip() or name
                        _log(callback, f'  [OPEN] Port {port:>5}/{proto}  {name:<12}  {svc_str}',
                             'success' if state == 'open' else 'info')
                        if port in RISKY_PORTS and state == 'open':
                            sev, desc = RISKY_PORTS[port]
                            _finding(callback, sev, 'Network / Port Risk',
                                     f'Port {port} ({name}): {desc}',
                                     port=port, service=name, version=ver)
        else:
            _log(callback, 'nmap: host appears down or ports filtered — trying socket fallback.', 'warning')
    except Exception as e:
        _log(callback, f'nmap library error ({type(e).__name__}) — trying subprocess fallback...', 'warning')

    # ── Tier 2: subprocess nmap (if library failed) ──────────────────────────
    if not nmap_success:
        try:
            result = subprocess.run(
                ['nmap', '-sV', '-T4', '--open', '-p', '1-1024', target],
                capture_output=True, text=True, timeout=90
            )
            if result.returncode == 0 and 'open' in result.stdout:
                nmap_success = True
                _log(callback, '🔍 nmap (subprocess) results:', 'success')
                for line in result.stdout.splitlines():
                    if '/tcp' in line or '/udp' in line:
                        _log(callback, f'  {line.strip()}', 'success')
                        parts = line.split()
                        if len(parts) >= 1:
                            try:
                                port = int(parts[0].split('/')[0])
                                if port in RISKY_PORTS and 'open' in line:
                                    sev, desc = RISKY_PORTS[port]
                                    _finding(callback, sev, 'Network / Port Risk',
                                             f'Port {port}: {desc}', port=port)
                            except Exception:
                                pass
        except FileNotFoundError:
            _log(callback, 'nmap not installed — using socket-only scan.', 'warning')
            _finding(callback, 'info', 'Tool Missing',
                     'nmap not installed. Install: sudo apt install nmap -y')
        except Exception as e:
            _log(callback, f'nmap subprocess error: {e}', 'warning')

    # ── Tier 3: pure socket scan (always works) ───────────────────────────────
    if not nmap_success:
        _log(callback, '🔌 Running socket-only port scan (no nmap)...', 'info')
        _log(callback, f'  Checking {len(top100)} ports via TCP socket...', 'info')
        found = 0
        for port in quick_open:
            if port in RISKY_PORTS:
                sev, desc = RISKY_PORTS[port]
                _log(callback, f'  [OPEN] Port {port:>5}  {desc[:60]}', 'success')
                _finding(callback, sev, 'Network / Port Risk (Socket)',
                         f'Port {port} appears open: {desc}', port=port)
                found += 1
        if found == 0:
            _log(callback, '  No risky ports found via socket scan.', 'info')
        _log(callback, f'Socket scan complete — {found} risky port(s) found.', 'success')

    _log(callback, 'Basic Port Scan finished.', 'success')


def full_port_scan(target, callback):
    """Full 65535-port scan — optimized with T5."""
    _log(callback, f'Starting Full Port Scan on [{target}]')
    _log(callback, 'Scanning all 65535 ports (T5 speed) — may take 3-8 min...', 'warning')
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '1-65535', '-T5 --open --max-rtt-timeout 250ms --max-retries 1', timeout=600)
        if not nm.all_hosts():
            _log(callback, 'No open ports or host is down', 'warning')
            return
        total_open = 0
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc = nm[host][proto][port]
                    name = svc.get('name', 'unknown')
                    ver  = svc.get('version', '')
                    prod = svc.get('product', '')
                    if svc['state'] == 'open':
                        total_open += 1
                        _log(callback, f'  [OPEN] Port {port:>5}/{proto}  {name}  {prod} {ver}'.strip(), 'success')
                        if port in RISKY_PORTS:
                            sev, desc = RISKY_PORTS[port]
                            _finding(callback, sev, 'Network / Port Risk',
                                     f'Port {port} ({name}): {desc}', port=port, service=name)
                        elif port > 1024:
                            _finding(callback, 'low', 'Network / Port Risk',
                                     f'Non-standard high port {port} is open', port=port, service=name)
        _log(callback, f'Full Port Scan complete — {total_open} open port(s).', 'success')
    except Exception as e:
        _log(callback, f'Full port scan failed: {e}', 'error')


def aggressive_scan(target, callback):
    """Aggressive scan with OS + scripts — optimized."""
    _log(callback, f'Starting Aggressive Scan on [{target}]')
    _log(callback, 'Running OS fingerprint + scripts (-A -T5)...', 'info')
    _log(callback, '⚠ Requires root/sudo for OS detection', 'warning')
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '1-1024', '-A -T5 --max-rtt-timeout 300ms --max-retries 1', timeout=180)
        if not nm.all_hosts():
            _log(callback, 'No hosts found', 'warning')
            return
        for host in nm.all_hosts():
            _log(callback, f'Host: {host}  ({nm[host].hostname()})', 'info')
            if nm[host].get('osmatch'):
                _log(callback, '--- OS Detection ---')
                for m in nm[host]['osmatch'][:2]:
                    _log(callback, f"  OS: {m['name']} (Accuracy: {m['accuracy']}%)", 'success')
                    _finding(callback, 'info', 'OS Detection',
                             f"Detected OS: {m['name']} ({m['accuracy']}% confidence)")
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc   = nm[host][proto][port]
                    state = svc['state']
                    name  = svc.get('name', 'unknown')
                    ver   = svc.get('version', '')
                    prod  = svc.get('product', '')
                    _log(callback, f'  [{state.upper():^6}] Port {port}/{proto}  {name}  {prod} {ver}'.strip(),
                         'success' if state == 'open' else 'info')
                    for script_name, out in svc.get('script', {}).items():
                        _log(callback, f'    [{script_name}] {str(out)[:200]}')
                    if port in RISKY_PORTS and state == 'open':
                        sev, desc = RISKY_PORTS[port]
                        _finding(callback, sev, 'Network / Port Risk',
                                 f'Port {port} ({name}): {desc}', port=port, service=name)
        _log(callback, 'Aggressive Scan completed.', 'success')
    except Exception as e:
        _log(callback, f'Aggressive scan failed: {e}', 'error')


def service_version_detection(target, callback):
    """Service and version detection."""
    _log(callback, f'Starting Service & Version Detection on [{target}]')
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '1-1024', '-sV -T5 --max-rtt-timeout 300ms --max-retries 1', timeout=120)
        if not nm.all_hosts():
            _log(callback, 'No services detected', 'warning')
            return
        outdated = {
            'apache':  ['1.', '2.0.', '2.1.', '2.2.'],
            'nginx':   ['0.', '1.0.', '1.1.', '1.2.', '1.3.', '1.4.', '1.5.'],
            'openssh': ['5.', '6.', '7.0', '7.1', '7.2', '7.3'],
            'openssl': ['0.', '1.0.0', '1.0.1', '1.0.2'],
            'iis':     ['5.', '6.', '7.'],
            'php':     ['5.', '7.0', '7.1', '7.2', '7.3'],
        }
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc   = nm[host][proto][port]
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


def banner_grab(target, callback):
    """Fast parallel banner grabbing."""
    _log(callback, f'Starting Banner Grabbing on [{target}]')
    ports_to_check = [21, 22, 23, 25, 80, 110, 143, 443, 8080, 8443, 3306, 6379, 27017]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    found = 0
    for port in ports_to_check:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                    if banner:
                        _log(callback, f'  Port {port}: {banner[:100]}', 'success')
                        found += 1
                        # Check for server version disclosure
                        if any(x in banner.lower() for x in ['server:', 'x-powered-by', 'apache', 'nginx', 'iis', 'php']):
                            _finding(callback, 'low', 'Information Disclosure',
                                     f'Port {port} reveals server info: {banner[:120]}')
                except Exception:
                    _log(callback, f'  Port {port}: open (no banner)', 'info')
                    found += 1
            s.close()
        except Exception:
            pass
    _log(callback, f'Banner Grabbing complete — {found} banner(s) retrieved.', 'success')
