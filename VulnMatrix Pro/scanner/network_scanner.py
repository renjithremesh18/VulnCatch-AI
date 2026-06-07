"""Network Scanner — DNS enumeration, WHOIS lookup, SSL/TLS analysis.
Fixed: SSL uses requests for CDN/DNS compatibility, DNS checks root domain for SPF/DMARC.
"""
import ssl
import socket
import datetime
import re
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def _log(cb, message, level='info'):
    cb('log', {'message': message, 'level': level})


def _finding(cb, severity, category, description, **extra):
    cb('finding', {'severity': severity, 'category': category,
                   'description': description, **extra})


def _clean_target(target):
    """Strip http:// https:// and trailing slashes."""
    t = re.sub(r'^https?://', '', target).split('/')[0].strip()
    return t


def _get_root_domain(domain):
    """Extract root domain: sub.example.com → example.com"""
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    # Handle country-code SLDs like .co.uk, .com.au
    if len(parts) >= 3 and parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu',
                                          'ac', 'nom', 'in', 'ad'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


# ---------------------------------------------------------------------------
# DNS Enumeration
# ---------------------------------------------------------------------------

def dns_enumeration(target, callback):
    """Enumerate DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA.
    Checks BOTH the given domain AND root domain for SPF/DMARC.
    """
    domain = _clean_target(target)
    root   = _get_root_domain(domain)
    _log(callback, f'Starting DNS Enumeration for [{domain}]', 'info')
    if root != domain:
        _log(callback, f'  (Will also check root domain [{root}] for email security records)', 'info')

    if not DNS_AVAILABLE:
        _log(callback, 'dnspython not installed. Run: pip install dnspython', 'error')
        _finding(callback, 'info', 'Tool Missing',
                 'dnspython library not found. Install with: pip install dnspython')
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 8
    resolver.lifetime = 10

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    found_records = 0

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            _log(callback, f'  [{rtype:<5}] Records:', 'info')
            for rdata in answers:
                val = str(rdata)
                _log(callback, f'    → {val[:120]}', 'success')
                found_records += 1
                if rtype == 'TXT':
                    val_lower = val.lower()
                    if 'v=spf1' in val_lower:
                        _log(callback, '    ✔ SPF record found', 'success')
                    if 'v=dmarc1' in val_lower:
                        _log(callback, '    ✔ DMARC record found', 'success')
                # Flag Cloudflare NS
                if rtype == 'NS' and 'cloudflare' in val.lower():
                    _finding(callback, 'info', 'CDN / Infrastructure',
                             f'Domain uses Cloudflare nameservers ({val}) — site is CDN-protected')
        except dns.resolver.NXDOMAIN:
            _log(callback, f'  [{rtype:<5}] Domain does not exist', 'warning')
            break
        except dns.resolver.NoAnswer:
            _log(callback, f'  [{rtype:<5}] No records found', 'info')
        except dns.exception.Timeout:
            _log(callback, f'  [{rtype:<5}] Timeout', 'warning')
        except Exception as e:
            _log(callback, f'  [{rtype:<5}] Error: {e}', 'warning')

    # ── Email Security — check BOTH www subdomain AND root domain ────────────
    _log(callback, '--- Email Security Records ---', 'info')
    spf_found   = False
    dmarc_found = False
    spf_val     = ''
    dmarc_val   = ''

    # Check all relevant domains for SPF/DMARC
    domains_to_check = list({domain, root})  # unique set

    for check_domain in domains_to_check:
        # SPF in TXT
        try:
            for rdata in resolver.resolve(check_domain, 'TXT'):
                val = str(rdata)
                if 'v=spf1' in val.lower():
                    spf_found = True
                    spf_val   = val[:120]
                    _log(callback, f'  ✔ SPF record on [{check_domain}]: {spf_val[:80]}', 'success')
        except Exception:
            pass

        # DMARC at _dmarc.<domain>
        try:
            for rdata in resolver.resolve(f'_dmarc.{check_domain}', 'TXT'):
                val = str(rdata)
                if 'v=dmarc1' in val.lower():
                    dmarc_found = True
                    dmarc_val   = val[:120]
                    _log(callback, f'  ✔ DMARC record on [_dmarc.{check_domain}]: {dmarc_val[:80]}', 'success')
                    # Analyse policy
                    if 'p=none' in val.lower():
                        _finding(callback, 'medium', 'DNS / Email Security',
                                 f'DMARC policy is p=none (monitor only) — emails are NOT rejected. '
                                 f'Upgrade to p=quarantine or p=reject')
                    elif 'p=quarantine' in val.lower():
                        _log(callback, '  ℹ DMARC p=quarantine — moderate protection', 'info')
                    elif 'p=reject' in val.lower():
                        _log(callback, '  ✔ DMARC p=reject — maximum email protection', 'success')
        except Exception:
            pass

    # Report missing
    if not spf_found:
        _log(callback, f'  ✘ No SPF record found on [{domain}] or [{root}]', 'warning')
        _finding(callback, 'medium', 'DNS / Email Security',
                 f'No SPF record found for {root} — emails can be spoofed from this domain. '
                 f'Add: v=spf1 include:_spf.google.com ~all')
    if not dmarc_found:
        _log(callback, f'  ✘ No DMARC record found for [{root}]', 'warning')
        _finding(callback, 'medium', 'DNS / Email Security',
                 f'No DMARC record for {root} — phishing emails will not be blocked. '
                 f'Add TXT at _dmarc.{root}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{root}')

    # ── MX check ─────────────────────────────────────────────────────────────
    mx_found = False
    for check_domain in domains_to_check:
        try:
            mx_records = resolver.resolve(check_domain, 'MX')
            for mx in mx_records:
                mx_found = True
                mx_str = str(mx.exchange).lower()
                if 'outlook' in mx_str or 'microsoft' in mx_str:
                    _log(callback, f'  ℹ Mail: Microsoft 365 / Exchange Online', 'info')
                elif 'google' in mx_str or 'googlemail' in mx_str:
                    _log(callback, f'  ℹ Mail: Google Workspace (Gmail)', 'info')
                elif 'zoho' in mx_str:
                    _log(callback, f'  ℹ Mail: Zoho Mail', 'info')
        except Exception:
            pass

    _log(callback, f'DNS Enumeration complete — {found_records} record(s) found.', 'success')


# ---------------------------------------------------------------------------
# WHOIS Lookup
# ---------------------------------------------------------------------------

def whois_lookup(target, callback):
    """Perform WHOIS lookup and flag domain age/expiry issues."""
    domain = _clean_target(target)
    _log(callback, f'Starting WHOIS Lookup for [{domain}]', 'info')

    try:
        socket.inet_aton(domain)
        is_ip = True
    except socket.error:
        is_ip = False

    if not WHOIS_AVAILABLE:
        _log(callback, 'python-whois not installed. Run: pip install python-whois', 'error')
        _finding(callback, 'info', 'Tool Missing',
                 'python-whois library not found. Install with: pip install python-whois')
        return

    try:
        try:
            w = whois_lib.whois(domain)
            if not w or not getattr(w, 'domain_name', None):
                raise Exception("No WHOIS records found for domain")
        except Exception:
            root = _get_root_domain(domain)
            if root != domain:
                _log(callback, f'  WHOIS: retrying with root domain [{root}]...', 'info')
                w = whois_lib.whois(root)
                if not w or not getattr(w, 'domain_name', None):
                    raise Exception("No WHOIS data found")
                domain = root

        fields = {
            'Domain':       getattr(w, 'domain_name', None),
            'Registrar':    getattr(w, 'registrar', None),
            'Created':      getattr(w, 'creation_date', None),
            'Expires':      getattr(w, 'expiration_date', None),
            'Updated':      getattr(w, 'updated_date', None),
            'Status':       getattr(w, 'status', None),
            'Name Servers': getattr(w, 'name_servers', None),
            'Emails':       getattr(w, 'emails', None),
        }

        for field, value in fields.items():
            if value is None:
                continue
            if isinstance(value, list):
                value = value[0] if len(value) == 1 else str(value[:3])
            _log(callback, f'  {field:<15}: {str(value)[:100]}', 'info')

        def to_utc(dt):
            if dt is None:
                return None
            if isinstance(dt, list):
                dt = dt[0]
            if not isinstance(dt, datetime.datetime):
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)

        now_utc = datetime.datetime.now(datetime.timezone.utc)

        try:
            expiry = to_utc(getattr(w, 'expiration_date', None))
            if expiry:
                days_left = (expiry - now_utc).days
                if days_left < 0:
                    _log(callback, f'  ⚠ Domain EXPIRED {abs(days_left)} day(s) ago!', 'error')
                    _finding(callback, 'critical', 'WHOIS / Domain',
                             f'Domain {domain} has EXPIRED — may be hijackable')
                elif days_left < 30:
                    _log(callback, f'  ⚠ Domain expires in {days_left} day(s)!', 'warning')
                    _finding(callback, 'high', 'WHOIS / Domain',
                             f'Domain {domain} expires in {days_left} days — at risk of expiry hijacking')
                elif days_left < 90:
                    _log(callback, f'  ℹ Domain expires in {days_left} day(s)', 'warning')
                    _finding(callback, 'low', 'WHOIS / Domain',
                             f'Domain {domain} expires in {days_left} days — renew soon')
                else:
                    _log(callback, f'  ✔ Domain valid for {days_left} more day(s)', 'success')
        except Exception as e:
            _log(callback, f'  Could not parse expiry date: {e}', 'warning')

        try:
            created = to_utc(getattr(w, 'creation_date', None))
            if created:
                age_days = (now_utc - created).days
                if age_days < 30:
                    _finding(callback, 'high', 'WHOIS / Domain',
                             f'Domain is very new ({age_days} days old) — common with phishing domains')
                else:
                    _log(callback, f'  ✔ Domain age: {age_days} days ({age_days // 365} year(s))', 'success')
        except Exception as e:
            _log(callback, f'  Could not parse creation date: {e}', 'warning')

        _log(callback, 'WHOIS Lookup completed.', 'success')

    except Exception as e:
        _log(callback, f'WHOIS lookup failed: {e}', 'error')


# ---------------------------------------------------------------------------
# SSL/TLS Analysis — uses requests + raw socket fallback (CDN-safe)
# ---------------------------------------------------------------------------

def ssl_analysis(target, callback):
    """
    Analyse SSL/TLS certificate validity, expiry, and cipher strength.
    Fixed: Uses requests library first (CDN-safe, no DNS issues),
    falls back to raw SSL socket for cipher/protocol detail.
    """
    domain = _clean_target(target)
    _log(callback, f'Starting SSL/TLS Analysis for [{domain}]', 'info')

    # ── Step 1: Basic HTTPS connectivity via requests (always works) ─────────
    https_url = f'https://{domain}'
    cert_info = {}
    connected = False

    try:
        resp = requests.get(https_url, timeout=10, verify=True,
                            headers={'User-Agent': 'VulnCatch-AI/4.0'})
        connected = True
        _log(callback, f'  ✔ HTTPS connection: HTTP {resp.status_code}', 'success')

        # Check HSTS in response
        if 'Strict-Transport-Security' in resp.headers:
            hsts = resp.headers['Strict-Transport-Security']
            _log(callback, f'  ✔ HSTS: {hsts}', 'success')
            if 'max-age=0' in hsts:
                _finding(callback, 'medium', 'SSL/TLS',
                         'HSTS max-age=0 effectively disables HSTS protection')
        else:
            _finding(callback, 'medium', 'SSL/TLS / HSTS',
                     'HSTS header missing — browsers not forced to use HTTPS')

        # Check redirect from HTTP → HTTPS
        try:
            http_resp = requests.get(f'http://{domain}', timeout=5,
                                     allow_redirects=False, verify=False,
                                     headers={'User-Agent': 'VulnCatch-AI/4.0'})
            if http_resp.status_code in (301, 302, 307, 308):
                loc = http_resp.headers.get('Location', '')
                if loc.startswith('https://'):
                    _log(callback, f'  ✔ HTTP→HTTPS redirect: {http_resp.status_code} → {loc[:60]}', 'success')
                else:
                    _finding(callback, 'medium', 'SSL/TLS',
                             f'HTTP redirects to non-HTTPS: {loc[:80]}')
            else:
                _finding(callback, 'medium', 'SSL/TLS',
                         f'No HTTP→HTTPS redirect (HTTP {http_resp.status_code}) — plaintext access possible')
        except Exception:
            pass

    except requests.exceptions.SSLError as e:
        err = str(e)
        _log(callback, f'  ✘ SSL Certificate Error: {err[:120]}', 'error')
        _finding(callback, 'critical', 'SSL/TLS',
                 f'SSL certificate error: {err[:200]} — users will see browser security warnings')
        connected = False
    except requests.exceptions.ConnectionError as e:
        _log(callback, f'  HTTPS not reachable via requests: {str(e)[:80]}', 'warning')
    except Exception as e:
        _log(callback, f'  HTTPS check error: {str(e)[:80]}', 'warning')

    # ── Step 2: Raw SSL socket for cert details + cipher info ────────────────
    _log(callback, '--- Certificate Details ---', 'info')
    ssl_detail_ok = False

    # Try resolving manually to avoid DNS failures
    try:
        ip = socket.getaddrinfo(domain, 443, socket.AF_INET)[0][4][0]
    except Exception:
        ip = domain

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE  # Still get cert even if expired
        with socket.create_connection((ip, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()
        ssl_detail_ok = True

        # Subject
        subject    = dict(x[0] for x in cert.get('subject', []))
        cn         = subject.get('commonName', 'N/A')
        org        = subject.get('organizationName', 'N/A')
        _log(callback, f'  Common Name  : {cn}', 'info')
        _log(callback, f'  Organization : {org}', 'info')

        # Issuer
        issuer     = dict(x[0] for x in cert.get('issuer', []))
        issuer_cn  = issuer.get('commonName', 'N/A')
        issuer_org = issuer.get('organizationName', 'N/A')
        _log(callback, f'  Issuer       : {issuer_org} ({issuer_cn})', 'info')

        # Self-signed check
        if cn == issuer_cn:
            _finding(callback, 'high', 'SSL/TLS',
                     f'Self-signed certificate detected — not trusted by browsers')

        # Expiry
        not_after_str = cert.get('notAfter', '')
        fmt = '%b %d %H:%M:%S %Y %Z'
        try:
            not_after = datetime.datetime.strptime(not_after_str, fmt).replace(
                tzinfo=datetime.timezone.utc)
            days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
            _log(callback, f'  Valid Until  : {not_after_str}  ({days_left} days remaining)', 'info')
            if days_left < 0:
                _log(callback, '  ✘ Certificate EXPIRED!', 'error')
                _finding(callback, 'critical', 'SSL/TLS',
                         f'SSL certificate for {domain} has EXPIRED — browsers show red warning screen')
            elif days_left < 14:
                _finding(callback, 'high', 'SSL/TLS',
                         f'SSL certificate expires in {days_left} days — renew IMMEDIATELY')
            elif days_left < 30:
                _finding(callback, 'medium', 'SSL/TLS',
                         f'SSL certificate expires in {days_left} days — schedule renewal soon')
            else:
                _log(callback, f'  ✔ Certificate valid for {days_left} more days', 'success')
        except ValueError:
            _log(callback, '  Could not parse certificate dates', 'warning')

        # SANs
        sans = cert.get('subjectAltName', [])
        if sans:
            san_list = [v for t, v in sans if t == 'DNS']
            _log(callback, f'  SANs ({len(san_list)}): {", ".join(san_list[:6])}{"..." if len(san_list) > 6 else ""}', 'info')

        # TLS Protocol
        _log(callback, f'  TLS Version  : {proto}', 'info')
        if proto in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'):
            _finding(callback, 'high', 'SSL/TLS',
                     f'Weak TLS protocol in use: {proto} — must upgrade to TLS 1.2+')
        elif proto == 'TLSv1.2':
            _log(callback, '  ℹ TLS 1.2 — acceptable but TLS 1.3 preferred', 'info')
        elif proto == 'TLSv1.3':
            _log(callback, '  ✔ TLS 1.3 — excellent (latest standard)', 'success')

        # Cipher suite
        if cipher:
            cipher_name, _, bits = cipher
            _log(callback, f'  Cipher Suite : {cipher_name} ({bits}-bit)', 'info')
            if bits and bits < 128:
                _finding(callback, 'high', 'SSL/TLS',
                         f'Weak cipher with only {bits}-bit key: {cipher_name}')
            elif any(x in (cipher_name or '') for x in ['RC4', 'DES', 'NULL', 'EXPORT', 'MD5']):
                _finding(callback, 'critical', 'SSL/TLS',
                         f'Broken cipher suite detected: {cipher_name} — disable immediately')
            else:
                _log(callback, f'  ✔ Cipher strength: {bits}-bit — OK', 'success')

    except ConnectionRefusedError:
        if not connected:
            _log(callback, f'  Port 443 refused on {domain} — HTTPS not running', 'warning')
            _finding(callback, 'medium', 'SSL/TLS',
                     f'HTTPS (port 443) is not open on {domain} — site may not support SSL')
    except ssl.SSLCertVerificationError as e:
        _log(callback, f'  Certificate verification failed: {e}', 'error')
        _finding(callback, 'high', 'SSL/TLS', f'Cert verification error: {str(e)[:200]}')
    except Exception as e:
        err_msg = str(e)
        if not ssl_detail_ok:
            if 'timed out' in err_msg.lower():
                _log(callback, f'  SSL socket timed out — CDN may be rate-limiting', 'warning')
            elif 'name or service not known' in err_msg.lower():
                _log(callback, '  DNS resolution failed for raw socket — CDN-safe mode only', 'warning')
                if connected:
                    _log(callback, '  ✔ HTTPS confirmed reachable via HTTP client (CDN mode)', 'success')
            else:
                _log(callback, f'  SSL detail error: {err_msg[:100]}', 'warning')

    _log(callback, 'SSL/TLS Analysis completed.', 'success')
