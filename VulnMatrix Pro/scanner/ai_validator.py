"""AI Scan Validator — sends complete scan results to Gemini for accuracy analysis."""
import requests
import json

GEMINI_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent'


def validate_with_ai(target: str, findings: list, score: int,
                     modules_run: list, api_key: str = '') -> dict:
    """
    Send all scan findings to Gemini AI for independent accuracy validation.
    Returns structured validation report with confidence, gaps, and priority fixes.
    """
    if not api_key or not findings:
        return _local_validate(findings, score, modules_run)

    # Build findings summary for AI
    findings_text = []
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'info').upper()
        cat = f.get('category', '')
        desc = f.get('description', '')[:300]
        findings_text.append(f"{i}. [{sev}] {cat}: {desc}")

    prompt = f"""You are a cybersecurity expert reviewing an automated vulnerability scan report.

TARGET: {target}
RISK SCORE: {score}/100
MODULES USED: {', '.join(modules_run)}
TOTAL FINDINGS: {len(findings)}

FINDINGS:
{chr(10).join(findings_text[:25])}

Please analyze this scan and provide:
1. ACCURACY ASSESSMENT: Is the risk score of {score}/100 accurate given these findings? (answer: accurate/underestimated/overestimated and why in 1-2 sentences)
2. CRITICAL GAPS: What important checks may be missing? (max 3 bullet points)
3. TOP 3 PRIORITY FIXES: The 3 most urgent things to fix, with specific commands/steps
4. CONFIDENCE: Give a confidence % (0-100) that this scan captured the real security posture

Format your response as JSON:
{{
  "accuracy_verdict": "accurate|underestimated|overestimated",
  "accuracy_reason": "...",
  "confidence": 85,
  "gaps": ["gap1", "gap2", "gap3"],
  "priority_fixes": [
    {{"rank": 1, "issue": "...", "fix": "specific command or config"}},
    {{"rank": 2, "issue": "...", "fix": "..."}},
    {{"rank": 3, "issue": "...", "fix": "..."}}
  ],
  "summary": "One sentence overall assessment"
}}"""

    payload = {
        'contents': [{'role': 'user', 'parts': [{'text': prompt}]}],
        'generationConfig': {
            'temperature': 0.2,
            'maxOutputTokens': 1024,
            'responseMimeType': 'application/json',
        },
    }

    try:
        r = requests.post(
            f'{GEMINI_URL}?key={api_key}',
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30,
        )
        r.raise_for_status()
        text = r.json()['candidates'][0]['content']['parts'][0]['text']

        # Parse JSON response
        # Strip markdown code fences if present
        text = text.strip().strip('```json').strip('```').strip()
        result = json.loads(text)
        result['source'] = 'gemini'
        # Merge with local validation
        local = _local_validate(findings, score, modules_run)
        result['local_issues'] = local.get('issues', [])
        return result

    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else 0
        local = _local_validate(findings, score, modules_run)
        local['error'] = f'Gemini API error (HTTP {code}) — using local validation'
        return local
    except json.JSONDecodeError:
        local = _local_validate(findings, score, modules_run)
        local['error'] = 'Could not parse Gemini JSON response — using local validation'
        return local
    except Exception as e:
        local = _local_validate(findings, score, modules_run)
        local['error'] = str(e)[:100]
        return local


def _local_validate(findings: list, score: int, modules_run: list) -> dict:
    """Rule-based local accuracy validation (no API key needed)."""
    issues = []
    confidence = 90

    critical = sum(1 for f in findings if f.get('severity') == 'critical')
    high      = sum(1 for f in findings if f.get('severity') == 'high')
    medium    = sum(1 for f in findings if f.get('severity') == 'medium')

    # Score consistency checks
    if score >= 80 and critical > 0:
        issues.append(f'Risk score {score}/100 seems high with {critical} Critical finding(s) — score may be underestimated.')
        confidence -= 25

    if score >= 70 and critical + high >= 4:
        issues.append(f'{critical + high} Critical/High findings but score shows Good — consider running more modules.')
        confidence -= 15

    if len(findings) == 0 and len(modules_run) <= 3:
        issues.append('Very few modules run — results may be incomplete. Try adding Security Headers, SSL, and DNS modules.')
        confidence -= 20

    tool_missing = [f for f in findings if 'Tool Missing' in f.get('category', '')]
    if tool_missing:
        issues.append(f'{len(tool_missing)} scanner tool(s) not installed (Nikto/Nuclei) — web vulnerabilities may be missed.')
        confidence -= 10

    cdn_hints = any('cloudflare' in f.get('description', '').lower() or
                    'cdn' in f.get('description', '').lower()
                    for f in findings)
    if cdn_hints:
        issues.append('Target appears to be behind CDN/WAF — real server IP and ports may be hidden.')
        confidence -= 5

    if 'osint' not in [m.lower() for m in modules_run] and \
       'dns' not in modules_run and 'whois' not in modules_run:
        issues.append('No OSINT modules used — DNS, WHOIS, and reputation checks skipped.')
        confidence -= 10

    confidence = max(0, min(100, confidence))

    # Determine accuracy verdict
    if score >= 80 and critical >= 2:
        verdict = 'underestimated'
        reason = f'Score {score}/100 is inconsistent with {critical} critical findings.'
    elif score < 50 and critical == 0 and high == 0:
        verdict = 'overestimated'
        reason = f'Score {score}/100 seems low with no Critical/High findings.'
    else:
        verdict = 'accurate'
        reason = 'Score appears consistent with the findings severity distribution.'

    return {
        'source': 'local',
        'accuracy_verdict': verdict,
        'accuracy_reason': reason,
        'confidence': confidence,
        'gaps': issues[:3],
        'priority_fixes': _generate_priority_fixes(findings),
        'summary': f'Scan completed with {len(findings)} findings. {reason}',
        'local_issues': issues,
    }


def _generate_priority_fixes(findings: list) -> list:
    """Generate top-3 priority fix recommendations from findings."""
    # Sort by severity weight
    weight = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    sorted_findings = sorted(findings, key=lambda f: weight.get(f.get('severity', 'info'), 0), reverse=True)

    fixes = []
    seen = set()
    fix_map = {
        'redis': 'sudo nano /etc/redis/redis.conf → set "requirepass StrongPassword" and "bind 127.0.0.1"',
        'mongodb': 'Enable auth in /etc/mongod.conf: security.authorization: enabled + bind 127.0.0.1',
        'elasticsearch': 'Set xpack.security.enabled: true in elasticsearch.yml + bind to localhost',
        'telnet': 'sudo systemctl disable --now telnetd && sudo apt install openssh-server -y',
        'ftp': 'sudo systemctl disable vsftpd && use SFTP instead: sftp user@host',
        'smb': 'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false',
        'hsts': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'csp': "Add header: Content-Security-Policy: default-src 'self'",
        'spf': 'Add DNS TXT record: v=spf1 include:YOUR_MAIL_PROVIDER ~all',
        'dmarc': 'Add DNS TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
        'ssl': 'sudo apt install certbot && sudo certbot --nginx -d yourdomain.com',
        'rdp': 'Enable NLA, disable if unused, place behind VPN, apply all Windows patches',
        'mysql': 'sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf → bind-address = 127.0.0.1',
        'vnc': 'Add VNC password auth + SSH tunnel: ssh -L 5900:localhost:5900 user@host',
        'backdoor': 'URGENT: Port 4444 open — check for active backdoors/Metasploit listeners immediately!',
    }

    for f in sorted_findings:
        if len(fixes) >= 3:
            break
        desc_lower = f.get('description', '').lower()
        cat_lower = f.get('category', '').lower()
        matched = False
        for keyword, fix_text in fix_map.items():
            if keyword in desc_lower or keyword in cat_lower:
                if keyword not in seen:
                    seen.add(keyword)
                    fixes.append({
                        'rank': len(fixes) + 1,
                        'issue': f.get('description', '')[:120],
                        'severity': f.get('severity', 'info'),
                        'fix': fix_text,
                    })
                    matched = True
                    break
        if not matched:
            key = f.get('category', 'issue')[:30]
            if key not in seen:
                seen.add(key)
                fixes.append({
                    'rank': len(fixes) + 1,
                    'issue': f.get('description', '')[:120],
                    'severity': f.get('severity', 'info'),
                    'fix': 'Review this finding and consult the AI Copilot for specific remediation steps.',
                })

    return fixes
