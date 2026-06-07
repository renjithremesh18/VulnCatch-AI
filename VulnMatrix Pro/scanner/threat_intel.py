"""Threat Intelligence API clients — VirusTotal, AbuseIPDB, PhishTank, Google Safe Browsing."""
import re
import time
import base64
import hashlib
import json
import urllib.parse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15
HEADERS = {'User-Agent': 'VulnCatch-AI/3.0'}


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class VirusTotalClient:
    BASE = 'https://www.virustotal.com/api/v3'

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {**HEADERS, 'x-apikey': api_key}

    def _get(self, endpoint: str) -> dict:
        r = requests.get(f'{self.BASE}{endpoint}', headers=self.headers, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _post(self, endpoint: str, data=None, json_data=None) -> dict:
        r = requests.post(f'{self.BASE}{endpoint}', headers=self.headers,
                          data=data, json=json_data, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()

    def check_url(self, url: str) -> dict:
        """Submit URL for analysis and return verdict."""
        try:
            # Encode URL for VT ID
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
            try:
                result = self._get(f'/urls/{url_id}')
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    # Not cached — submit for scanning
                    self._post('/urls', data={'url': url})
                    time.sleep(2)
                    result = self._get(f'/urls/{url_id}')
                else:
                    raise

            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            return {
                'url': url,
                'malicious': malicious,
                'suspicious': suspicious,
                'total_engines': total,
                'verdict': 'malicious' if malicious >= 3 else ('suspicious' if suspicious >= 2 or malicious >= 1 else 'clean'),
                'raw': stats,
            }
        except Exception as e:
            return {'url': url, 'error': str(e), 'verdict': 'unknown'}

    def check_domain(self, domain: str) -> dict:
        """Get domain reputation."""
        try:
            result = self._get(f'/domains/{domain}')
            attrs = result.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            rep = attrs.get('reputation', 0)
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            cats = attrs.get('categories', {})
            return {
                'domain': domain,
                'malicious': malicious,
                'total_engines': total,
                'reputation_score': rep,
                'categories': list(cats.values())[:3],
                'verdict': 'malicious' if malicious >= 3 or rep < -10 else ('suspicious' if malicious >= 1 else 'clean'),
            }
        except Exception as e:
            return {'domain': domain, 'error': str(e), 'verdict': 'unknown'}

    def check_ip(self, ip: str) -> dict:
        """Get IP reputation."""
        try:
            result = self._get(f'/ip_addresses/{ip}')
            attrs = result.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            rep = attrs.get('reputation', 0)
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            country = attrs.get('country', 'Unknown')
            asn = attrs.get('asn', '')
            as_owner = attrs.get('as_owner', '')
            return {
                'ip': ip,
                'malicious': malicious,
                'total_engines': total,
                'reputation_score': rep,
                'country': country,
                'asn': asn,
                'as_owner': as_owner,
                'verdict': 'malicious' if malicious >= 3 or rep < -10 else ('suspicious' if malicious >= 1 else 'clean'),
            }
        except Exception as e:
            return {'ip': ip, 'error': str(e), 'verdict': 'unknown'}


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class AbuseIPDBClient:
    BASE = 'https://api.abuseipdb.com/api/v2'

    def __init__(self, api_key: str):
        self.headers = {**HEADERS, 'Key': api_key, 'Accept': 'application/json'}

    def check_ip(self, ip: str) -> dict:
        """Check IP against AbuseIPDB blocklist."""
        try:
            r = requests.get(
                f'{self.BASE}/check',
                headers=self.headers,
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                timeout=TIMEOUT
            )
            r.raise_for_status()
            data = r.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            country = data.get('countryCode', 'Unknown')
            isp = data.get('isp', '')
            total_reports = data.get('totalReports', 0)
            return {
                'ip': ip,
                'abuse_score': score,
                'total_reports': total_reports,
                'country': country,
                'isp': isp,
                'verdict': 'malicious' if score >= 75 else ('suspicious' if score >= 25 else 'clean'),
            }
        except Exception as e:
            return {'ip': ip, 'error': str(e), 'verdict': 'unknown'}


# ---------------------------------------------------------------------------
# PhishTank
# ---------------------------------------------------------------------------

class PhishTankClient:
    URL = 'https://checkurl.phishtank.com/checkurl/'

    def __init__(self, api_key: str = ''):
        self.api_key = api_key

    def check_url(self, url: str) -> dict:
        """Check URL against PhishTank database."""
        try:
            data = {'url': url, 'format': 'json'}
            if self.api_key:
                data['app_key'] = self.api_key
            r = requests.post(self.URL, data=data,
                              headers={**HEADERS, 'Accept': 'application/json'},
                              timeout=TIMEOUT)
            r.raise_for_status()
            result = r.json().get('results', {})
            in_db = result.get('in_database', False)
            is_phish = result.get('valid', False) and result.get('verified', False)
            return {
                'url': url,
                'in_database': in_db,
                'is_phish': is_phish,
                'verdict': 'malicious' if is_phish else ('suspicious' if in_db else 'clean'),
            }
        except Exception as e:
            return {'url': url, 'error': str(e), 'verdict': 'unknown'}


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

class SafeBrowsingClient:
    URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

    def __init__(self, api_key: str):
        self.api_key = api_key

    def check_urls(self, urls: list) -> dict:
        """Batch check URLs against Google Safe Browsing."""
        try:
            payload = {
                'client': {'clientId': 'vulncatch-ai', 'clientVersion': '3.0'},
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': u} for u in urls],
                }
            }
            r = requests.post(f'{self.URL}?key={self.api_key}',
                              json=payload, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            matches = r.json().get('matches', [])
            flagged = {m['threat']['url'] for m in matches}
            return {
                'flagged_urls': list(flagged),
                'total_checked': len(urls),
                'threat_matches': len(matches),
            }
        except Exception as e:
            return {'error': str(e), 'flagged_urls': [], 'total_checked': len(urls)}
