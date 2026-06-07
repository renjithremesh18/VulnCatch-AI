"""Web Scanner — HTTP headers, banner grabbing, HTTP methods, Nikto, Nuclei."""
import socket
import subprocess
import platform
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IS_WINDOWS = platform.system() == 'Windows'

# Security headers that should be present
REQUIRED_HEADERS = {
    'Strict-Transport-Security': {
        'severity': 'high',
        'description': 'Missing HSTS — forces browsers to use HTTPS, prevents protocol downgrade attacks',
    },
    'Content-Security-Policy': {
        'severity': 'high',
        'description': 'Missing CSP — no protection against XSS and data injection attacks',
    },
    'X-Frame-Options': {
        'severity': 'medium',
        'description': 'Missing X-Frame-Options — site may be vulnerable to clickjacking attacks',
    },
    'X-Content-Type-Options': {
        'severity': 'medium',
        'description': 'Missing X-Content-Type-Options — browsers may MIME-sniff responses',
    },
    'Referrer-Policy': {
        'severity': 'low',
        'description': 'Missing Referrer-Policy — sensitive URL data may leak to third parties',
    },
    'Permissions-Policy': {
        'severity': 'low',
        'description': 'Missing Permissions-Policy — browser features not restricted',
    },
    'X-XSS-Protection': {
        'severity': 'low',
        'description': 'Missing X-XSS-Protection — older browsers lack basic XSS filter activation',
    },
}

# Response headers that disclose server information
INFO_LEAK_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                     'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via']

BANNER_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 3306, 3389, 5432, 6379, 8080, 8443]


def _log(cb, message, level='info'):
    cb('log', {'message': message, 'level': level})


def _finding(cb, severity, category, description, **extra):
    cb('finding', {'severity': severity, 'category': category,
                   'description': description, **extra})


def _normalize_url(target):
    if not target.startswith(('http://', 'https://')):
        return 'http://' + target
    return target


def check_security_headers(target, callback):
    """Analyse HTTP security headers and flag missing or misconfigured ones."""
    url = _normalize_url(target)
    _log(callback, f'Checking security headers on {url}', 'info')

    try:
        resp = requests.get(url, timeout=15, verify=False,
                            headers={'User-Agent': 'VulnCatch-AI/3.0'})
        _log(callback, f'HTTP Response: {resp.status_code} {resp.reason}', 'info')
        _log(callback, '--- Response Headers ---', 'info')

        for h, v in resp.headers.items():
            _log(callback, f'  {h}: {v}', 'info')

        _log(callback, '--- Security Header Analysis ---', 'info')

        # Check for missing security headers
        present = 0
        for header, info in REQUIRED_HEADERS.items():
            if header in resp.headers:
                _log(callback, f'  ✔ {header}: {resp.headers[header][:80]}', 'success')
                present += 1
            else:
                _log(callback, f'  ✘ MISSING: {header}', 'warning')
                _finding(callback, info['severity'], 'HTTP Security Headers',
                         info['description'], header=header)

        _log(callback, f'Security headers present: {present}/{len(REQUIRED_HEADERS)}',
             'success' if present >= 5 else 'warning')

        # Information disclosure via response headers
        for leak_header in INFO_LEAK_HEADERS:
            if leak_header in resp.headers:
                val = resp.headers[leak_header]
                _log(callback, f'  ⚠ Info Disclosure [{leak_header}]: {val}', 'warning')
                _finding(callback, 'low', 'Information Disclosure',
                         f'Header "{leak_header}: {val}" discloses server technology',
                         header=leak_header, value=val)

        # HTTP vs HTTPS
        if url.startswith('http://'):
            _finding(callback, 'medium', 'HTTP Security Headers',
                     'Site serves content over plain HTTP — all traffic is unencrypted')

    except requests.exceptions.SSLError as e:
        _log(callback, f'SSL error accessing {url}: {e}', 'error')
        _finding(callback, 'high', 'SSL/TLS', f'SSL certificate error: {str(e)[:200]}')
    except requests.exceptions.ConnectionError:
        _log(callback, f'Could not connect to {url} — host may be down', 'error')
    except Exception as e:
        _log(callback, f'Header check failed: {e}', 'error')

    _log(callback, 'Security Headers Check completed.', 'success')


def banner_grab(target, callback):
    """Grab banners from common ports using raw TCP."""
    _log(callback, f'Starting Banner Grabbing on [{target}]', 'info')
    _log(callback, f'Probing {len(BANNER_PORTS)} common ports...', 'info')

    probes = {
        80:   b'HEAD / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\nConnection: close\r\n\r\n',
        8080: b'HEAD / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\nConnection: close\r\n\r\n',
        8443: b'HEAD / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\nConnection: close\r\n\r\n',
        21:   b'',
        22:   b'',
        23:   b'',
        25:   b'EHLO vulnmatrix.probe\r\n',
        110:  b'',
        143:  b'',
        443:  b'',
        465:  b'',
        587:  b'',
        3306: b'',
        3389: b'',
        5432: b'',
        6379: b'PING\r\n',
    }

    found = 0
    for port in BANNER_PORTS:
        try:
            with socket.create_connection((target, port), timeout=3) as s:
                probe = probes.get(port, b'')
                if probe:
                    s.send(probe)
                s.settimeout(3)
                try:
                    banner = s.recv(1024)
                    banner_text = banner.decode('utf-8', errors='ignore').strip()[:200]
                    if banner_text:
                        found += 1
                        _log(callback,
                             f'  Port {port:>5}: {banner_text[:100]}',
                             'success')

                        # Flag interesting banners
                        lower = banner_text.lower()
                        if any(x in lower for x in ['ssh-1.', 'ssh-2.0-openssh_5', 'ssh-2.0-openssh_6']):
                            _finding(callback, 'high', 'Banner Grabbing',
                                     f'Outdated SSH version detected on port {port}: {banner_text[:80]}',
                                     port=port)
                        elif 'telnet' in lower or port == 23:
                            _finding(callback, 'critical', 'Banner Grabbing',
                                     f'Telnet service confirmed on port {port} — unencrypted protocol',
                                     port=port)
                        elif 'ftp' in lower and port == 21:
                            _finding(callback, 'high', 'Banner Grabbing',
                                     f'FTP service on port 21 — {banner_text[:60]}',
                                     port=port)
                        elif port == 6379 and '+PONG' in banner_text:
                            _finding(callback, 'critical', 'Banner Grabbing',
                                     'Redis is unauthenticated — responded to PING without credentials',
                                     port=port)
                    else:
                        _log(callback, f'  Port {port:>5}: open (no banner)', 'info')
                except socket.timeout:
                    _log(callback, f'  Port {port:>5}: open (read timeout)', 'info')
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # Port closed or filtered

    _log(callback, f'Banner Grabbing complete — {found} banner(s) retrieved.', 'success')


def http_methods_probe(target, callback):
    """Check which HTTP methods the server allows."""
    url = _normalize_url(target)
    _log(callback, f'Probing HTTP methods on {url}', 'info')

    methods_to_check = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS',
                        'HEAD', 'TRACE', 'CONNECT']
    dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']

    try:
        # First try OPTIONS to get Allow header
        resp = requests.options(url, timeout=10, verify=False,
                                headers={'User-Agent': 'VulnCatch-AI/3.0'})
        allow_header = resp.headers.get('Allow', '')
        if allow_header:
            _log(callback, f'Allow header: {allow_header}', 'info')

        # Check each method
        for method in methods_to_check:
            try:
                r = requests.request(method, url, timeout=8, verify=False,
                                     headers={'User-Agent': 'VulnCatch-AI/3.0'})
                status = r.status_code
                level = 'success'
                if status < 400:
                    level = 'warning' if method in dangerous else 'success'
                    _log(callback,
                         f'  {method:<8}: HTTP {status} — {"⚠ ALLOWED" if status < 400 else "blocked"}',
                         level)

                    if method in dangerous and status < 400:
                        sev = 'high' if method in ['PUT', 'DELETE'] else 'medium'
                        _finding(callback, sev, 'HTTP Methods',
                                 f'Dangerous HTTP method {method} is allowed (HTTP {status})',
                                 method=method, status=status)
                else:
                    _log(callback, f'  {method:<8}: HTTP {status}', 'info')
            except Exception:
                pass

    except Exception as e:
        _log(callback, f'HTTP methods probe failed: {e}', 'error')

    _log(callback, 'HTTP Methods Probe completed.', 'success')


def nikto_scan(target, callback):
    """Run Nikto web server scanner."""
    _log(callback, f'Starting Nikto Scan on [{target}]', 'info')
    _log(callback, 'Nikto performs comprehensive web server vulnerability testing...', 'info')
    _log(callback, 'This may take 2–5 minutes depending on the target.', 'warning')

    args = ['-h', target, '-Tuning', 'x 6', '-nointeractive',
            '-timeout', '5', '-maxtime', '180s', '-no404', '-Format', 'txt']

    cmd = None
    if IS_WINDOWS:
        # Try WSL first
        try:
            test = subprocess.run(['wsl', 'which', 'nikto'], capture_output=True, timeout=5)
            if test.returncode == 0:
                cmd = ['wsl', 'nikto'] + args
        except Exception:
            pass

        if not cmd:
            _log(callback, 'Nikto not found via WSL. Install: wsl --install, then sudo apt install nikto', 'error')
            _finding(callback, 'info', 'Tool Missing',
                     'Nikto not installed in WSL. Install with: wsl sudo apt install nikto')
            return
    else:
        cmd = ['nikto'] + args

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            _log(callback, f'  {line}', 'info')

            # Flag Nikto findings
            lower = line.lower()
            if '+ osvdb' in lower or 'vulnerability' in lower or 'vulnerable' in lower:
                _finding(callback, 'high', 'Nikto / Web Vulnerability',
                         line[:300])
            elif 'missing' in lower and ('header' in lower or 'hsts' in lower):
                _finding(callback, 'medium', 'Nikto / HTTP Headers', line[:300])

        proc.wait(timeout=200)
        _log(callback, 'Nikto Scan completed.', 'success')

    except subprocess.TimeoutExpired:
        _log(callback, 'Nikto scan timed out — partial results above', 'warning')
    except FileNotFoundError:
        _log(callback, 'Nikto not found. On Linux: sudo apt install nikto', 'error')
        _finding(callback, 'info', 'Tool Missing',
                 'Nikto is not installed. Install with: sudo apt install nikto')
    except Exception as e:
        _log(callback, f'Nikto error: {e}', 'error')


def nuclei_scan(target, callback):
    """Run Nuclei vulnerability scanner."""
    url = _normalize_url(target)
    _log(callback, f'Starting Nuclei Scan on [{url}]', 'info')
    _log(callback, 'Nuclei scans for known CVEs, misconfigurations, and exposures...', 'info')
    _log(callback, 'This may take 3–10 minutes on first run (template download).', 'warning')

    cmd = ['nuclei', '-u', url, '-silent', '-no-color', '-timeout', '10']
    if IS_WINDOWS:
        cmd = ['wsl'] + cmd

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)

        sev_map = {'[critical]': 'critical', '[high]': 'high',
                   '[medium]': 'medium', '[low]': 'low', '[info]': 'info'}

        for line in proc.stdout:
            line = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
            if not line:
                continue
            _log(callback, f'  {line}', 'info')

            # Parse nuclei severity tags
            lower = line.lower()
            detected_sev = 'info'
            for tag, sev in sev_map.items():
                if tag in lower:
                    detected_sev = sev
                    break

            if any(tag in lower for tag in ['[critical]', '[high]', '[medium]', '[low]']):
                _finding(callback, detected_sev, 'Nuclei / Vulnerability',
                         line[:400])

        proc.wait(timeout=600)
        _log(callback, 'Nuclei Scan completed.', 'success')

    except FileNotFoundError:
        _log(callback, 'Nuclei not found. Install from https://github.com/projectdiscovery/nuclei', 'error')
        _finding(callback, 'info', 'Tool Missing',
                 'Nuclei is not installed. Download from: https://github.com/projectdiscovery/nuclei/releases')
    except subprocess.TimeoutExpired:
        _log(callback, 'Nuclei scan timed out — partial results above', 'warning')
    except Exception as e:
        _log(callback, f'Nuclei error: {e}', 'error')
