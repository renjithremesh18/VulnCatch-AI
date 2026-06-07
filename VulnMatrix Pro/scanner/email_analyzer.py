"""Email Phishing Analyzer — parses raw email, checks headers, extracts URLs, queries threat intel."""
import re
import email
import email.policy
import socket
import json
from email.header import decode_header, make_header
from urllib.parse import urlparse
from scanner.threat_intel import VirusTotalClient, AbuseIPDBClient, PhishTankClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

URL_RE = re.compile(
    r'https?://[^\s<>\"\'\)\(,;]+',
    re.IGNORECASE
)

SUSPICIOUS_KEYWORDS = [
    'verify your account', 'confirm your identity', 'update your payment',
    'your account has been suspended', 'urgent action required', 'click here immediately',
    'you have won', 'claim your prize', 'limited time offer', 'act now',
    'password expired', 'login attempt', 'unusual activity', 'validate your',
    'account will be closed', 'wire transfer', 'bitcoin', 'cryptocurrency',
    'gift card', 'paypal', 'bank account', 'social security', 'irs',
    'refund pending', 'invoice attached', 'dear customer', 'dear user',
    'dear account holder', 'kindly', 'as soon as possible',
]

TRUSTED_DOMAINS = {
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'yahoo.com',
    'apple.com', 'amazon.com', 'paypal.com', 'ebay.com', 'linkedin.com',
    'twitter.com', 'facebook.com', 'instagram.com', 'github.com',
}


def _decode_header_value(val):
    """Safely decode email header value."""
    try:
        return str(make_header(decode_header(val)))
    except Exception:
        return str(val)


def _extract_ips_from_received(received_headers: list) -> list:
    """Extract sender IPs from Received headers."""
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    for r in received_headers:
        found = ip_re.findall(r)
        for ip in found:
            parts = ip.split('.')
            # Skip private/loopback IPs
            if parts[0] in ('10', '127', '172', '192') and (
                parts[0] == '127' or
                (parts[0] == '10') or
                (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
                (parts[0] == '192' and parts[1] == '168')
            ):
                continue
            if ip not in ips:
                ips.append(ip)
    return ips


def _get_domain(address: str) -> str:
    """Extract domain from email address."""
    match = re.search(r'@([\w.\-]+)', address)
    return match.group(1).lower() if match else ''


# ---------------------------------------------------------------------------
# Main Analyzer
# ---------------------------------------------------------------------------

def analyze_email(raw_email: str, vt_api_key: str = '', abuseipdb_key: str = '',
                  phishtank_key: str = '', callback=None) -> dict:
    """
    Full phishing email analysis pipeline.
    Returns structured results dict with phishing_score (0-100) and verdict.
    """

    def _log(msg, level='info'):
        if callback:
            callback('log', {'message': msg, 'level': level})

    def _finding(severity, category, description, **extra):
        if callback:
            callback('finding', {'severity': severity, 'category': category,
                                 'description': description, **extra})

    results = {
        'headers': {},
        'spf_dkim_dmarc': {},
        'urls': [],
        'sender_ips': [],
        'ip_reputation': [],
        'url_reputation': [],
        'keyword_flags': [],
        'phishing_score': 0,
        'verdict': 'safe',
        'findings': [],
    }
    score = 0

    # ── Parse the email ──────────────────────────────────────────────────────
    _log('Parsing email headers and body...', 'info')
    try:
        msg = email.message_from_string(raw_email, policy=email.policy.default)
    except Exception as e:
        _log(f'Failed to parse email: {e}', 'error')
        results['error'] = str(e)
        return results

    # ── Extract key headers ──────────────────────────────────────────────────
    from_header   = _decode_header_value(msg.get('From', ''))
    reply_to      = _decode_header_value(msg.get('Reply-To', ''))
    subject       = _decode_header_value(msg.get('Subject', '(No Subject)'))
    return_path   = msg.get('Return-Path', '')
    x_mailer      = msg.get('X-Mailer', '')
    received_list = msg.get_all('Received') or []
    auth_results  = msg.get('Authentication-Results', '')

    results['headers'] = {
        'From': from_header,
        'Reply-To': reply_to or '(not set)',
        'Subject': subject,
        'Return-Path': return_path or '(not set)',
        'X-Mailer': x_mailer or '(not set)',
        'Received-Count': len(received_list),
    }

    _log(f'  From       : {from_header}', 'info')
    _log(f'  Subject    : {subject}', 'info')
    _log(f'  Reply-To   : {reply_to or "(not set)"}', 'info')
    _log(f'  Return-Path: {return_path or "(not set)"}', 'info')

    # ── Reply-To mismatch ────────────────────────────────────────────────────
    from_domain = _get_domain(from_header)
    replyto_domain = _get_domain(reply_to)
    if reply_to and from_domain and replyto_domain and from_domain != replyto_domain:
        _log(f'  ⚠ Reply-To domain mismatch: From={from_domain}, Reply-To={replyto_domain}', 'warning')
        _finding('high', 'Email Header', f'Reply-To domain ({replyto_domain}) differs from From domain ({from_domain}) — classic phishing indicator')
        score += 20

    # ── Return-Path mismatch ─────────────────────────────────────────────────
    returnpath_domain = _get_domain(return_path)
    if return_path and from_domain and returnpath_domain and from_domain != returnpath_domain:
        _log(f'  ⚠ Return-Path domain mismatch: {returnpath_domain} vs {from_domain}', 'warning')
        _finding('medium', 'Email Header', f'Return-Path domain ({returnpath_domain}) differs from sender domain — possible spoofing')
        score += 10

    # ── SPF / DKIM / DMARC ──────────────────────────────────────────────────
    _log('--- Checking SPF / DKIM / DMARC ---', 'info')
    spf_pass  = 'spf=pass'  in auth_results.lower()
    dkim_pass = 'dkim=pass' in auth_results.lower()
    dmarc_pass = 'dmarc=pass' in auth_results.lower()
    spf_fail  = 'spf=fail'  in auth_results.lower() or 'spf=softfail' in auth_results.lower()
    dkim_fail = 'dkim=fail' in auth_results.lower()

    results['spf_dkim_dmarc'] = {
        'spf': 'pass' if spf_pass else ('fail' if spf_fail else 'unknown'),
        'dkim': 'pass' if dkim_pass else ('fail' if dkim_fail else 'unknown'),
        'dmarc': 'pass' if dmarc_pass else 'unknown',
        'auth_results_raw': auth_results[:200] if auth_results else '(not present)',
    }

    if not auth_results:
        _log('  ⚠ No Authentication-Results header — email may not have passed through proper mail servers', 'warning')
        _finding('medium', 'Email Authentication', 'No Authentication-Results header found — email may be spoofed or sent directly')
        score += 15
    else:
        if spf_fail:
            _log('  ✘ SPF FAILED — email did not originate from authorized server', 'error')
            _finding('high', 'Email Authentication', 'SPF check FAILED — email did not originate from an authorized mail server')
            score += 20
        elif spf_pass:
            _log('  ✔ SPF PASS', 'success')

        if dkim_fail:
            _log('  ✘ DKIM FAILED — email signature invalid', 'error')
            _finding('high', 'Email Authentication', 'DKIM signature FAILED — email content may have been tampered with')
            score += 20
        elif dkim_pass:
            _log('  ✔ DKIM PASS', 'success')

        if not dmarc_pass and auth_results:
            _log('  ⚠ DMARC not passed — domain policy not enforced', 'warning')
            score += 5

    # ── Sender IP reputation ─────────────────────────────────────────────────
    sender_ips = _extract_ips_from_received(received_list)
    results['sender_ips'] = sender_ips
    _log(f'--- Checking Sender IPs ({len(sender_ips)} found) ---', 'info')

    if abuseipdb_key and sender_ips:
        try:
            abuse_client = AbuseIPDBClient(abuseipdb_key)
            for ip in sender_ips[:3]:  # check first 3
                _log(f'  Checking IP {ip} via AbuseIPDB...', 'info')
                ip_result = abuse_client.check_ip(ip)
                results['ip_reputation'].append(ip_result)
                abuse_score = ip_result.get('abuse_score', 0)
                if ip_result.get('verdict') == 'malicious':
                    _log(f'  ✘ IP {ip} is MALICIOUS (AbuseIPDB score: {abuse_score})', 'error')
                    _finding('critical', 'Sender IP Reputation',
                             f'Sender IP {ip} has AbuseIPDB abuse confidence score of {abuse_score}% — known malicious sender',
                             ip=ip, abuse_score=abuse_score)
                    score += 30
                elif ip_result.get('verdict') == 'suspicious':
                    _log(f'  ⚠ IP {ip} is SUSPICIOUS (AbuseIPDB score: {abuse_score})', 'warning')
                    score += 15
                else:
                    _log(f'  ✔ IP {ip} is clean (score: {abuse_score})', 'success')
        except Exception as e:
            _log(f'  AbuseIPDB check error: {e}', 'warning')

    # ── Extract URLs from body ───────────────────────────────────────────────
    body_text = ''
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ('text/plain', 'text/html'):
                    try:
                        body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except Exception:
                        pass
        else:
            try:
                body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except Exception:
                body_text = str(msg.get_payload())
    except Exception as e:
        _log(f'  Could not extract email body: {e}', 'warning')

    extracted_urls = list(set(URL_RE.findall(body_text)))[:20]  # cap at 20 URLs
    results['urls'] = extracted_urls
    _log(f'--- URL Analysis ({len(extracted_urls)} URLs found) ---', 'info')

    # ── VirusTotal URL checks ─────────────────────────────────────────────────
    if vt_api_key and extracted_urls:
        try:
            vt = VirusTotalClient(vt_api_key)
            for url in extracted_urls[:10]:  # check first 10 to respect rate limits
                _log(f'  Checking: {url[:80]}', 'info')
                vt_result = vt.check_url(url)
                results['url_reputation'].append(vt_result)

                if vt_result.get('verdict') == 'malicious':
                    malicious = vt_result.get('malicious', 0)
                    total = vt_result.get('total_engines', 0)
                    _log(f'  ✘ MALICIOUS URL detected ({malicious}/{total} engines flagged): {url[:70]}', 'error')
                    _finding('critical', 'Malicious URL',
                             f'URL flagged by {malicious}/{total} VirusTotal engines: {url[:150]}',
                             url=url, malicious_engines=malicious)
                    score += 25
                elif vt_result.get('verdict') == 'suspicious':
                    _log(f'  ⚠ Suspicious URL: {url[:70]}', 'warning')
                    score += 10
                elif 'error' not in vt_result:
                    _log(f'  ✔ Clean: {url[:70]}', 'success')
                import time; time.sleep(0.5)  # VT rate limit: free tier ~4 req/s
        except Exception as e:
            _log(f'  VirusTotal check error: {e}', 'warning')
    elif not vt_api_key:
        _log('  VirusTotal API key not set — skipping URL reputation check', 'warning')

    # ── Keyword / linguistic analysis ─────────────────────────────────────────
    _log('--- Phishing Language Analysis ---', 'info')
    body_lower = body_text.lower()
    subject_lower = subject.lower()
    combined_text = body_lower + ' ' + subject_lower
    flagged_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined_text]
    results['keyword_flags'] = flagged_keywords

    if flagged_keywords:
        _log(f'  ⚠ Suspicious language detected: {", ".join(flagged_keywords[:5])}', 'warning')
        kw_score = min(len(flagged_keywords) * 5, 25)
        score += kw_score
        if len(flagged_keywords) >= 3:
            _finding('medium', 'Phishing Language',
                     f'Email contains {len(flagged_keywords)} phishing language indicators: {", ".join(flagged_keywords[:5])}',
                     keywords=flagged_keywords)
    else:
        _log('  ✔ No obvious phishing keywords detected', 'success')

    # ── Impersonation check ──────────────────────────────────────────────────
    display_name = re.match(r'^([^<]+)<', from_header)
    if display_name:
        name_text = display_name.group(1).strip().lower()
        for trusted in TRUSTED_DOMAINS:
            brand = trusted.split('.')[0]
            if brand in name_text and brand not in from_domain:
                _log(f'  ✘ Possible brand impersonation: Display name contains "{brand}" but sender domain is "{from_domain}"', 'error')
                _finding('critical', 'Brand Impersonation',
                         f'Sender display name implies "{brand}" but email comes from "{from_domain}" — likely impersonation')
                score += 35
                break

    # ── Compute final verdict ─────────────────────────────────────────────────
    score = min(score, 100)
    results['phishing_score'] = score
    if score >= 70:
        results['verdict'] = 'confirmed_phishing'
        verdict_log = '🚨 VERDICT: CONFIRMED PHISHING'
        verdict_level = 'error'
    elif score >= 45:
        results['verdict'] = 'likely_phishing'
        verdict_log = '⚠ VERDICT: LIKELY PHISHING'
        verdict_level = 'warning'
    elif score >= 20:
        results['verdict'] = 'suspicious'
        verdict_log = 'ℹ VERDICT: SUSPICIOUS — review carefully'
        verdict_level = 'warning'
    else:
        results['verdict'] = 'safe'
        verdict_log = '✔ VERDICT: LIKELY SAFE'
        verdict_level = 'success'

    _log(f'Phishing Risk Score: {score}/100', 'info')
    _log(verdict_log, verdict_level)

    return results
