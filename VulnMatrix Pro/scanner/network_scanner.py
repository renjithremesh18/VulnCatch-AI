"""Network Scanner — DNS enumeration, WHOIS lookup, SSL/TLS analysis."""
import ssl
import socket
import datetime
import json

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
    for prefix in ('https://', 'http://'):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split('/')[0].strip()


# ---------------------------------------------------------------------------
# DNS Enumeration
# ---------------------------------------------------------------------------

def dns_enumeration(target, callback):
    """Enumerate DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    domain = _clean_target(target)
    _log(callback, f'Starting DNS Enumeration for [{domain}]', 'info')

    if not DNS_AVAILABLE:
        _log(callback, 'dnspython not installed. Run: pip install dnspython', 'error')
        _finding(callback, 'info', 'Tool Missing',
                 'dnspython library not found. Install with: pip install dnspython')
        return

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 8
    resolver.lifetime = 10

    found_records = 0
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            _log(callback, f'  [{rtype:<5}] Records:', 'info')
            for rdata in answers:
                val = str(rdata)
                _log(callback, f'    → {val[:120]}', 'success')
                found_records += 1

                # Check for interesting TXT records
                if rtype == 'TXT':
                    val_lower = val.lower()
                    if 'spf' not in val_lower and rtype == 'TXT':
                        pass  # Not alarming
                    if 'v=spf1' in val_lower:
                        _log(callback, '    ✔ SPF record found', 'success')
                    if 'v=dmarc1' in val_lower:
                        _log(callback, '    ✔ DMARC record found', 'success')

        except dns.resolver.NXDOMAIN:
            _log(callback, f'  [{rtype:<5}] Domain does not exist', 'warning')
            break
        except dns.resolver.NoAnswer:
            _log(callback, f'  [{rtype:<5}] No records found', 'info')
        except dns.exception.Timeout:
            _log(callback, f'  [{rtype:<5}] Timeout', 'warning')
        except Exception as e:
            _log(callback, f'  [{rtype:<5}] Error: {e}', 'warning')

    # SPF / DMARC checks
    _log(callback, '--- Email Security Records ---', 'info')
    spf_found = False
    dmarc_found = False

    try:
        txt_answers = resolver.resolve(domain, 'TXT')
        for rdata in txt_answers:
            val = str(rdata).lower()
            if 'v=spf1' in val:
                spf_found = True
            if 'v=dmarc1' in val:
                dmarc_found = True
    except Exception:
        pass

    try:
        dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in dmarc_answers:
            if 'v=dmarc1' in str(rdata).lower():
                dmarc_found = True
    except Exception:
        pass

    if not spf_found:
        _log(callback, '  ✘ No SPF record — domain may be spoofed for phishing', 'warning')
        _finding(callback, 'medium', 'DNS / Email Security',
                 f'No SPF record found for {domain} — emails can be spoofed from this domain')
    else:
        _log(callback, '  ✔ SPF record present', 'success')

    if not dmarc_found:
        _log(callback, '  ✘ No DMARC record — phishing emails will not be rejected', 'warning')
        _finding(callback, 'medium', 'DNS / Email Security',
                 f'No DMARC record found for {domain} — no policy to reject spoofed emails')
    else:
        _log(callback, '  ✔ DMARC record present', 'success')

    _log(callback, f'DNS Enumeration complete — {found_records} record(s) found.', 'success')


# ---------------------------------------------------------------------------
# WHOIS Lookup
# ---------------------------------------------------------------------------

def _get_base_domain(domain):
    """Extract root/registered domain from a subdomain (e.g. sub.example.com -> example.com)."""
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    # If the second to last part is a common second-level domain suffix
    if len(parts) >= 3 and parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'nom', 'in', 'ad', 'net'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def whois_lookup(target, callback):
    """Perform WHOIS lookup and flag domain age/expiry issues."""
    domain = _clean_target(target)
    _log(callback, f'Starting WHOIS Lookup for [{domain}]', 'info')

    # Try to detect if it's an IP address
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
        except Exception as e:
            base_domain = _get_base_domain(domain)
            if base_domain != domain:
                _log(callback, f'  WHOIS failed for subdomain [{domain}]. Retrying with base domain [{base_domain}]...', 'warning')
                w = whois_lib.whois(base_domain)
                if not w or not getattr(w, 'domain_name', None):
                    raise Exception("No WHOIS records found for base domain")
                domain = base_domain  # Update domain context for logging/dates
            else:
                raise e

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

        # Helper: make any datetime UTC-aware so comparisons never crash
        def to_utc(dt):
            if dt is None:
                return None
            if isinstance(dt, list):
                dt = dt[0]
            if not isinstance(dt, datetime.datetime):
                return None
            if dt.tzinfo is None:
                # naive → assume UTC
                return dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)

        now_utc = datetime.datetime.now(datetime.timezone.utc)

        # Check expiry
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
        except Exception as date_err:
            _log(callback, f'  Could not parse expiry date: {date_err}', 'warning')

        # Check domain age
        try:
            created = to_utc(getattr(w, 'creation_date', None))
            if created:
                age_days = (now_utc - created).days
                if age_days < 30:
                    _finding(callback, 'high', 'WHOIS / Domain',
                             f'Domain is very new ({age_days} days old) — common with phishing/scam domains')
                else:
                    _log(callback, f'  ✔ Domain age: {age_days} days ({age_days // 365} year(s))', 'success')
        except Exception as date_err:
            _log(callback, f'  Could not parse creation date: {date_err}', 'warning')

        _log(callback, 'WHOIS Lookup completed.', 'success')

    except Exception as e:
        _log(callback, f'WHOIS lookup failed: {e}', 'error')


# ---------------------------------------------------------------------------
# SSL/TLS Analysis
# ---------------------------------------------------------------------------

def ssl_analysis(target, callback):
    """Analyse SSL/TLS certificate validity, expiry, and cipher strength."""
    domain = _clean_target(target)
    _log(callback, f'Starting SSL/TLS Analysis for [{domain}]', 'info')

    # Check if port 443 is open
    try:
        sock_test = socket.create_connection((domain, 443), timeout=5)
        sock_test.close()
    except Exception:
        _log(callback, f'Port 443 not reachable on {domain} — skipping SSL analysis', 'warning')
        _finding(callback, 'medium', 'SSL/TLS',
                 f'HTTPS (port 443) is not accessible on {domain}')
        return

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as ssock:
            ssock.settimeout(10)
            ssock.connect((domain, 443))
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            protocol = ssock.version()

        _log(callback, '--- Certificate Details ---', 'info')

        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        cn = subject.get('commonName', 'N/A')
        org = subject.get('organizationName', 'N/A')
        _log(callback, f'  Common Name  : {cn}', 'info')
        _log(callback, f'  Organization : {org}', 'info')

        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        issuer_cn = issuer.get('commonName', 'N/A')
        issuer_org = issuer.get('organizationName', 'N/A')
        _log(callback, f'  Issuer       : {issuer_org} ({issuer_cn})', 'info')

        # Validity
        not_before_str = cert.get('notBefore', '')
        not_after_str  = cert.get('notAfter', '')

        fmt = '%b %d %H:%M:%S %Y %Z'
        try:
            not_after = datetime.datetime.strptime(not_after_str, fmt).replace(
                tzinfo=datetime.timezone.utc)
            days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
            _log(callback, f'  Valid Until  : {not_after_str}  ({days_left} days remaining)', 'info')

            if days_left < 0:
                _log(callback, '  ✘ Certificate has EXPIRED!', 'error')
                _finding(callback, 'critical', 'SSL/TLS',
                         f'SSL certificate for {domain} has expired — browsers will show security warnings')
            elif days_left < 14:
                _log(callback, f'  ⚠ Certificate expires in {days_left} days!', 'warning')
                _finding(callback, 'high', 'SSL/TLS',
                         f'SSL certificate expires in {days_left} days — renew immediately')
            elif days_left < 30:
                _finding(callback, 'medium', 'SSL/TLS',
                         f'SSL certificate expires in {days_left} days — schedule renewal')
            else:
                _log(callback, f'  ✔ Certificate valid for {days_left} more days', 'success')
        except ValueError:
            _log(callback, f'  Could not parse certificate dates', 'warning')

        # SANs
        sans = cert.get('subjectAltName', [])
        if sans:
            san_list = [v for t, v in sans if t == 'DNS']
            _log(callback, f'  SANs ({len(san_list)}): {", ".join(san_list[:5])}{"..." if len(san_list)>5 else ""}', 'info')

        # Protocol version
        _log(callback, f'  TLS Version  : {protocol}', 'info')
        if protocol in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'):
            _finding(callback, 'high', 'SSL/TLS',
                     f'Weak TLS protocol {protocol} negotiated — upgrade to TLS 1.2 or 1.3')
        elif protocol == 'TLSv1.2':
            _log(callback, '  ✔ TLS 1.2 — acceptable, but TLS 1.3 is preferred', 'success')
        elif protocol == 'TLSv1.3':
            _log(callback, '  ✔ TLS 1.3 — excellent', 'success')

        # Cipher suite
        if cipher:
            cipher_name, _, bits = cipher
            _log(callback, f'  Cipher Suite : {cipher_name} ({bits}-bit)', 'info')
            if bits and bits < 128:
                _finding(callback, 'high', 'SSL/TLS',
                         f'Weak cipher {cipher_name} with {bits}-bit key negotiated')
            elif 'RC4' in (cipher_name or '') or 'DES' in (cipher_name or '') or 'NULL' in (cipher_name or ''):
                _finding(callback, 'critical', 'SSL/TLS',
                         f'Insecure cipher {cipher_name} — deprecated and broken')
            else:
                _log(callback, f'  ✔ Cipher strength: {bits}-bit — OK', 'success')

        _log(callback, 'SSL/TLS Analysis completed.', 'success')

    except ssl.SSLCertVerificationError as e:
        _log(callback, f'Certificate verification failed: {e}', 'error')
        _finding(callback, 'high', 'SSL/TLS',
                 f'Certificate verification error: {str(e)[:200]}')
    except ssl.SSLError as e:
        _log(callback, f'SSL error: {e}', 'error')
        _finding(callback, 'high', 'SSL/TLS',
                 f'SSL handshake error: {str(e)[:200]}')
    except Exception as e:
        _log(callback, f'SSL analysis failed: {e}', 'error')
