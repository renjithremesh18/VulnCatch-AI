"""OSINT Scanner — VirusTotal, AbuseIPDB, IP geolocation, MX/DNS reputation checks."""
import socket
import concurrent.futures
import requests
import dns.resolver
import re
import time

TIMEOUT = 12
HEADERS = {'User-Agent': 'VulnCatch-AI/4.0'}


def _log(cb, msg, level='info'):
    cb('log', {'message': msg, 'level': level})


def _finding(cb, severity, category, description, **extra):
    cb('finding', {'severity': severity, 'category': category,
                   'description': description, **extra})


# ---------------------------------------------------------------------------
# IP Geolocation — free, no key needed (ip-api.com)
# ---------------------------------------------------------------------------
def get_ip_info(ip: str) -> dict:
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting',
                         timeout=8, headers=HEADERS)
        data = r.json()
        if data.get('status') == 'success':
            return data
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# AbuseIPDB — free tier: 1000 checks/day
# ---------------------------------------------------------------------------
def check_abuseipdb(ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={**HEADERS, 'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=TIMEOUT
        )
        r.raise_for_status()
        data = r.json().get('data', {})
        return {
            'abuse_score': data.get('abuseConfidenceScore', 0),
            'total_reports': data.get('totalReports', 0),
            'country': data.get('countryCode', '??'),
            'isp': data.get('isp', ''),
            'domain': data.get('domain', ''),
            'is_tor': data.get('isTor', False),
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# VirusTotal — domain + IP reputation
# ---------------------------------------------------------------------------
def check_virustotal_domain(domain: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        # Strip protocol and path
        domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()
        r = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers={**HEADERS, 'x-apikey': api_key},
            timeout=TIMEOUT
        )
        if r.status_code == 404:
            return {'verdict': 'unknown', 'error': 'not in VT database'}
        r.raise_for_status()
        attrs = r.json().get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        reputation = attrs.get('reputation', 0)
        cats = attrs.get('categories', {})
        return {
            'domain': domain,
            'malicious': malicious,
            'suspicious': suspicious,
            'total_engines': total,
            'reputation': reputation,
            'categories': list(cats.values())[:4],
            'verdict': 'malicious' if malicious >= 3 or reputation < -10
                       else ('suspicious' if malicious >= 1 or suspicious >= 2 else 'clean'),
        }
    except Exception as e:
        return {'verdict': 'unknown', 'error': str(e)[:60]}


def check_virustotal_ip(ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={**HEADERS, 'x-apikey': api_key},
            timeout=TIMEOUT
        )
        r.raise_for_status()
        attrs = r.json().get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        total = sum(stats.values())
        return {
            'ip': ip,
            'malicious': malicious,
            'total_engines': total,
            'reputation': attrs.get('reputation', 0),
            'country': attrs.get('country', '??'),
            'asn': attrs.get('asn', ''),
            'as_owner': attrs.get('as_owner', ''),
            'verdict': 'malicious' if malicious >= 3 else ('suspicious' if malicious >= 1 else 'clean'),
        }
    except Exception as e:
        return {'verdict': 'unknown', 'error': str(e)[:60]}


# ---------------------------------------------------------------------------
# MXToolbox-style DNS analysis — no API key needed
# ---------------------------------------------------------------------------
def analyze_dns_reputation(domain: str, callback) -> dict:
    """Check MX records, blacklists, SPF, DMARC via DNS — no API key needed."""
    _log(callback, f'--- MX / DNS Reputation Analysis for [{domain}] ---')
    results = {'spf': False, 'dmarc': False, 'mx': [], 'blacklisted': False}

    # Strip to base domain
    base = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    # Get TLD+1 for DNS checks
    parts = base.split('.')
    if len(parts) >= 2:
        base_domain = '.'.join(parts[-2:])
    else:
        base_domain = base

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    # MX Records
    try:
        mx_records = resolver.resolve(base_domain, 'MX')
        for mx in mx_records:
            results['mx'].append(str(mx.exchange))
            _log(callback, f'  MX: {mx.preference} {mx.exchange}', 'success')
    except Exception:
        _log(callback, f'  No MX records found for {base_domain}', 'warning')
        _finding(callback, 'info', 'DNS / MX',
                 f'No MX records found for {base_domain} — domain may not send/receive email')

    # SPF
    try:
        txt_records = resolver.resolve(base_domain, 'TXT')
        for rdata in txt_records:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                results['spf'] = True
                _log(callback, f'  SPF: {txt[:80]}', 'success')
                if 'all' not in txt and '-all' not in txt:
                    _finding(callback, 'medium', 'Email Security / SPF',
                             f'SPF record found but missing enforcement (-all): {txt[:80]}')
    except Exception:
        pass

    if not results['spf']:
        _log(callback, f'  ⚠ No SPF record found', 'warning')
        _finding(callback, 'high', 'Email Security / SPF',
                 f'No SPF record for {base_domain} — domain can be spoofed to send phishing emails')

    # DMARC
    try:
        dmarc_records = resolver.resolve(f'_dmarc.{base_domain}', 'TXT')
        for rdata in dmarc_records:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                results['dmarc'] = True
                _log(callback, f'  DMARC: {txt[:80]}', 'success')
                if 'p=none' in txt:
                    _finding(callback, 'medium', 'Email Security / DMARC',
                             f'DMARC found but policy is p=none (monitoring only, not enforced): {txt[:80]}')
                elif 'p=reject' in txt:
                    _log(callback, '  DMARC: p=reject (strong protection)', 'success')
                elif 'p=quarantine' in txt:
                    _log(callback, '  DMARC: p=quarantine (moderate protection)', 'success')
    except Exception:
        pass

    if not results['dmarc']:
        _log(callback, '  ⚠ No DMARC record found', 'warning')
        _finding(callback, 'high', 'Email Security / DMARC',
                 f'No DMARC record for {base_domain} — email spoofing is possible')

    # Check popular DNS blacklists (DNSBL)
    ip = None
    try:
        ip = socket.gethostbyname(base_domain)
    except Exception:
        pass

    if ip and not ip.startswith('10.') and not ip.startswith('192.168.'):
        _log(callback, f'  Checking IP {ip} against DNS blacklists...', 'info')
        reversed_ip = '.'.join(reversed(ip.split('.')))
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
        ]
        for bl in blacklists:
            try:
                lookup = f'{reversed_ip}.{bl}'
                resolver.resolve(lookup, 'A')
                _log(callback, f'  ✘ BLACKLISTED on {bl}!', 'error')
                _finding(callback, 'high', 'DNS Blacklist',
                         f'IP {ip} is listed on {bl} — may indicate spam/malware activity')
                results['blacklisted'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                _log(callback, f'  ✔ Clean on {bl}', 'success')
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Main OSINT scan function
# ---------------------------------------------------------------------------
def run_osint_scan(target: str, callback, vt_api_key: str = '', abuseipdb_key: str = ''):
    """Run full OSINT scan: IP info, VT, AbuseIPDB, DNS blacklists in parallel."""
    _log(callback, f'Starting OSINT & Threat Intelligence scan for [{target}]', 'info')

    # Resolve target IP
    try:
        ip = socket.gethostbyname(target.replace('https://', '').replace('http://', '').split('/')[0])
        _log(callback, f'  Resolved IP: {ip}', 'info')
    except Exception:
        ip = None
        _log(callback, '  Could not resolve IP', 'warning')

    domain = re.sub(r'^https?://', '', target).split('/')[0].strip()

    # Parallel execution
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {}

        if ip:
            futures['ipinfo'] = ex.submit(get_ip_info, ip)
            if abuseipdb_key:
                futures['abuseipdb'] = ex.submit(check_abuseipdb, ip, abuseipdb_key)
            if vt_api_key:
                futures['vt_ip'] = ex.submit(check_virustotal_ip, ip, vt_api_key)

        if vt_api_key:
            futures['vt_domain'] = ex.submit(check_virustotal_domain, domain, vt_api_key)

        for key, fut in futures.items():
            try:
                results[key] = fut.result(timeout=20)
            except Exception as e:
                results[key] = {'error': str(e)}

    # --- IP Info ---
    ipinfo = results.get('ipinfo', {})
    if ipinfo:
        _log(callback, '--- IP Geolocation (ip-api.com) ---', 'info')
        _log(callback, f"  Country : {ipinfo.get('country', '?')}", 'info')
        _log(callback, f"  City    : {ipinfo.get('city', '?')}", 'info')
        _log(callback, f"  ISP     : {ipinfo.get('isp', '?')}", 'info')
        _log(callback, f"  Org     : {ipinfo.get('org', '?')}", 'info')
        if ipinfo.get('proxy'):
            _finding(callback, 'medium', 'IP Intelligence',
                     f'IP {ip} is a proxy/VPN/Tor exit node (ip-api.com)')
        if ipinfo.get('hosting'):
            _log(callback, '  ⚠ Hosting/datacenter IP (cloud provider)', 'warning')

    # --- AbuseIPDB ---
    abuse = results.get('abuseipdb', {})
    if abuse and 'abuse_score' in abuse:
        score = abuse['abuse_score']
        reports = abuse['total_reports']
        _log(callback, f'--- AbuseIPDB Results ---', 'info')
        _log(callback, f'  Abuse Score : {score}/100', 'success' if score < 25 else 'error')
        _log(callback, f'  Total Reports: {reports}', 'info')
        _log(callback, f"  ISP         : {abuse.get('isp', '?')}", 'info')
        if abuse.get('is_tor'):
            _log(callback, '  ⚠ This is a TOR exit node!', 'error')
            _finding(callback, 'high', 'IP Reputation / AbuseIPDB',
                     f'IP {ip} is a TOR exit node — anonymized traffic')
        if score >= 75:
            _finding(callback, 'critical', 'IP Reputation / AbuseIPDB',
                     f'IP {ip} has AbuseIPDB score {score}/100 with {reports} reports — known malicious host')
        elif score >= 25:
            _finding(callback, 'high', 'IP Reputation / AbuseIPDB',
                     f'IP {ip} has AbuseIPDB score {score}/100 — suspicious activity reported')
        elif score > 0:
            _finding(callback, 'medium', 'IP Reputation / AbuseIPDB',
                     f'IP {ip} has low abuse score {score}/100 ({reports} reports) — minor concern')
        else:
            _log(callback, f'  ✔ IP is clean (AbuseIPDB score: 0)', 'success')

    # --- VirusTotal IP ---
    vt_ip = results.get('vt_ip', {})
    if vt_ip and 'malicious' in vt_ip:
        mal = vt_ip['malicious']
        total = vt_ip['total_engines']
        _log(callback, f'--- VirusTotal IP Reputation ---', 'info')
        _log(callback, f'  {mal}/{total} engines flagged IP as malicious', 'error' if mal > 0 else 'success')
        _log(callback, f"  Country: {vt_ip.get('country', '?')}  ASN: {vt_ip.get('as_owner', '?')}", 'info')
        if vt_ip['verdict'] == 'malicious':
            _finding(callback, 'critical', 'IP Reputation / VirusTotal',
                     f'IP {ip} flagged by {mal}/{total} VirusTotal engines as malicious')
        elif vt_ip['verdict'] == 'suspicious':
            _finding(callback, 'high', 'IP Reputation / VirusTotal',
                     f'IP {ip} flagged by {mal}/{total} VirusTotal engines as suspicious')
        else:
            _log(callback, f'  ✔ IP clean on VirusTotal', 'success')

    # --- VirusTotal Domain ---
    vt_domain = results.get('vt_domain', {})
    if vt_domain and 'malicious' in vt_domain:
        mal = vt_domain['malicious']
        total = vt_domain['total_engines']
        rep = vt_domain.get('reputation', 0)
        cats = vt_domain.get('categories', [])
        _log(callback, f'--- VirusTotal Domain Reputation ---', 'info')
        _log(callback, f'  {mal}/{total} engines flagged domain', 'error' if mal > 0 else 'success')
        _log(callback, f'  Reputation score: {rep}', 'info')
        if cats:
            _log(callback, f'  Categories: {", ".join(cats)}', 'info')
        if vt_domain['verdict'] == 'malicious':
            _finding(callback, 'critical', 'Domain Reputation / VirusTotal',
                     f'Domain {domain} flagged malicious by {mal}/{total} VT engines (rep: {rep})')
        elif vt_domain['verdict'] == 'suspicious':
            _finding(callback, 'high', 'Domain Reputation / VirusTotal',
                     f'Domain {domain} flagged suspicious by {mal}/{total} VT engines')
        else:
            _log(callback, f'  ✔ Domain clean on VirusTotal', 'success')

    # MX / DNS blacklist check (no key needed)
    analyze_dns_reputation(domain, callback)

    _log(callback, 'OSINT & Threat Intelligence scan completed.', 'success')
