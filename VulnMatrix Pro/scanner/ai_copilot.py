"""
AI Engine — Multi-provider AI with automatic fallback chain.
Priority: Groq (free, fast) → Gemini → Offline KB

Groq AI: FREE at console.groq.com — models: llama3-70b, mixtral-8x7b
Gemini:  FREE at aistudio.google.com — model: gemini-1.5-flash
Offline: Always works — no key needed — rich built-in KB
"""
import requests
import json
import re

# ── Provider URLs ────────────────────────────────────────────────────────────
GROQ_URL   = 'https://api.groq.com/openai/v1/chat/completions'
GEMINI_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent'

# ── Global key storage (set via /api/set-keys) ──────────────────────────────
_groq_key   = ''
_gemini_key = ''

def set_keys(groq_key='', gemini_key=''):
    global _groq_key, _gemini_key
    if groq_key:   _groq_key   = groq_key.strip()
    if gemini_key: _gemini_key = gemini_key.strip()

def get_keys():
    return {'groq': _groq_key, 'gemini': _gemini_key}


# ── System Prompt ─────────────────────────────────────────────────────────────
_SYSTEM = """You are VulnCatch AI Copilot — an expert cybersecurity assistant built into VulnCatch AI (a cricket-themed vulnerability scanner for Kali Linux).

PERSONALITY:
- Expert, friendly, concise — like a senior pentester pair-programming with you
- Always give real terminal commands, actual config fixes, working code snippets
- Use cricket metaphors occasionally: "this vulnerability is a full toss — easy for attackers!", "patch this before they hit a six!"
- NEVER say you can't help — always give actionable steps

YOU KNOW EVERYTHING ABOUT:
- Network security: ports, protocols, nmap, firewall rules, packet analysis
- Web security: OWASP Top 10, HTTP headers, SSL/TLS, XSS, SQLi, CSRF, SSRF
- Email security: SPF, DKIM, DMARC, phishing header analysis
- OSINT: VirusTotal, AbuseIPDB, Shodan, WHOIS, DNS, Censys, Maltego
- Kali Linux tools: Nmap, Nikto, Nuclei, Metasploit, Burp Suite, SQLmap, Hydra
- Cloud security: AWS, GCP, Azure misconfigs, IAM, S3 bucket exposure
- CVE analysis, CVSS scoring, exploit-db, CVE lookup
- Vulnerability remediation with exact fix commands

VulnCatch AI modules: Basic Port Scan, Full Port Scan, Aggressive Scan, Service Detection,
Banner Grabbing, Security Headers, SSL/TLS Analysis, HTTP Methods, DNS Enumeration,
WHOIS Lookup, Nikto Web Scan, Nuclei Scan, Email Phishing Analyzer, OSINT & Threat Intel

FORMAT: Use markdown — **bold**, `code`, bullet points, numbered steps.
LIMIT: Under 500 words. Be specific, not vague."""


# ── Groq AI ──────────────────────────────────────────────────────────────────
def _call_groq(message: str, api_key: str, context_system: str = '') -> dict:
    """Call Groq API (OpenAI-compatible, free tier available)."""
    if not api_key or not api_key.startswith('gsk_'):
        return {'ok': False, 'error': 'invalid_groq_key'}

    system = context_system or _SYSTEM
    try:
        r = requests.post(
            GROQ_URL,
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
            },
            json={
                'model': 'llama3-70b-8192',
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user',   'content': message},
                ],
                'temperature': 0.4,
                'max_tokens': 800,
            },
            timeout=20,
        )
        if r.status_code == 401:
            return {'ok': False, 'error': 'invalid_groq_key', 'text': 'Invalid Groq API key'}
        if r.status_code == 429:
            return {'ok': False, 'error': 'rate_limit', 'text': 'Rate limited'}
        r.raise_for_status()
        text = r.json()['choices'][0]['message']['content'].strip()
        return {'ok': True, 'text': text, 'source': 'groq'}
    except requests.Timeout:
        return {'ok': False, 'error': 'timeout'}
    except Exception as e:
        return {'ok': False, 'error': str(e)[:80]}


# ── Gemini AI ─────────────────────────────────────────────────────────────────
def _call_gemini(message: str, api_key: str, context_system: str = '') -> dict:
    """Call Gemini API."""
    if not api_key or not api_key.startswith('AIzaSy'):
        return {'ok': False, 'error': 'invalid_gemini_key'}

    system = context_system or _SYSTEM
    try:
        payload = {
            'system_instruction': {'parts': [{'text': system}]},
            'contents': [{'role': 'user', 'parts': [{'text': message}]}],
            'generationConfig': {'temperature': 0.4, 'maxOutputTokens': 800},
        }
        r = requests.post(
            f'{GEMINI_URL}?key={api_key}',
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=25,
        )
        if r.status_code == 400:
            return {'ok': False, 'error': 'invalid_gemini_key'}
        if r.status_code == 429:
            return {'ok': False, 'error': 'rate_limit'}
        r.raise_for_status()
        text = r.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        return {'ok': True, 'text': text, 'source': 'gemini'}
    except requests.Timeout:
        return {'ok': False, 'error': 'timeout'}
    except Exception as e:
        return {'ok': False, 'error': str(e)[:80]}


# ── Main Query Function ───────────────────────────────────────────────────────
def query_ai(message: str, groq_key: str = '', gemini_key: str = '',
             scan_context: dict = None) -> dict:
    """
    Query AI with automatic fallback: Groq → Gemini → Offline KB.
    Uses globally stored keys as defaults.
    """
    gkey  = (groq_key   or _groq_key   or '').strip()
    mkey  = (gemini_key or _gemini_key or '').strip()

    # Build context-aware system prompt
    system = _SYSTEM
    if scan_context:
        target   = scan_context.get('target', 'unknown')
        score    = scan_context.get('score', 'N/A')
        findings = scan_context.get('findings', [])
        modules  = scan_context.get('modules', [])
        ctx_lines = [
            f'\n\n=== ACTIVE SCAN CONTEXT ===',
            f'Target: {target}',
            f'Risk Score: {score}/100',
            f'Modules Run: {", ".join(modules)}',
            f'Total Findings: {len(findings)}',
        ]
        if findings:
            ctx_lines.append('Top Findings (sorted by severity):')
            sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            top = sorted(findings, key=lambda x: sev_order.get(x.get('severity', 'info'), 0), reverse=True)[:10]
            for f in top:
                ctx_lines.append(f"  [{f.get('severity','info').upper()}] {f.get('category','')} — {f.get('description','')[:180]}")
        system += '\n'.join(ctx_lines)

    # Try Groq first (free, fast)
    if gkey:
        result = _call_groq(message, gkey, system)
        if result.get('ok'):
            return {'response': result['text'], 'source': 'groq', 'model': 'llama3-70b'}
        if result.get('error') == 'invalid_groq_key':
            pass  # fall through to Gemini
        elif result.get('error') == 'rate_limit':
            pass  # fall through

    # Try Gemini second
    if mkey:
        result = _call_gemini(message, mkey, system)
        if result.get('ok'):
            return {'response': result['text'], 'source': 'gemini', 'model': 'gemini-1.5-flash'}
        if result.get('error') == 'invalid_gemini_key':
            # Return helpful error
            return {
                'response': _invalid_key_msg(),
                'source': 'error',
            }

    # Offline KB fallback — always works
    return {
        'response': _offline_answer(message),
        'source': 'offline',
    }


def _invalid_key_msg() -> str:
    return (
        '🔑 **No valid AI key configured**\n\n'
        '**Option 1 — Groq AI (FREE, recommended, fast):**\n'
        '1. Go to **https://console.groq.com**\n'
        '2. Sign up (free)\n'
        '3. Click **API Keys** → **Create API Key**\n'
        '4. Copy the key (starts with `gsk_...`)\n'
        '5. Paste in **⚙ Settings** → Groq Key field\n\n'
        '**Option 2 — Google Gemini (free):**\n'
        '1. Go to **https://aistudio.google.com/app/apikey**\n'
        '2. Sign in → **Create API Key**\n'
        '3. Key starts with `AIzaSy...`\n\n'
        '> 📚 Meanwhile, I\'m answering from my built-in knowledge base!'
    )


# ── Offline Knowledge Base ───────────────────────────────────────────────────
_KB = {
    'groq': (
        '**Groq AI — Free & Fast!**\n\n'
        '1. Go to **https://console.groq.com**\n'
        '2. Sign up with email (free)\n'
        '3. Click **API Keys** → **Create API Key**\n'
        '4. Key looks like: `gsk_xxxxxxxxxxxx`\n'
        '5. Paste in ⚙ Settings inside VulnCatch\n\n'
        '**Free limits:** 14,400 requests/day, 30 req/min\n'
        '**Model used:** Llama 3 70B (very powerful!)'
    ),
    'gemini': (
        '**Google Gemini API Key:**\n\n'
        '1. Go to **https://aistudio.google.com/app/apikey**\n'
        '2. Sign in with Google\n'
        '3. Click **Create API Key**\n'
        '4. Key starts with `AIzaSy...`\n'
        '5. Free: 15 req/min, 1500 req/day'
    ),
    'api key': (
        '**Get a FREE AI API Key:**\n\n'
        '**🥇 Groq (Recommended — fastest, easiest):**\n'
        '→ https://console.groq.com → Sign up → API Keys → Create\n'
        '→ Key format: `gsk_...`\n\n'
        '**🥈 Google Gemini:**\n'
        '→ https://aistudio.google.com/app/apikey\n'
        '→ Key format: `AIzaSy...`'
    ),
    'hsts': (
        '**HSTS (HTTP Strict Transport Security)**\n\n'
        'Forces browsers to ALWAYS use HTTPS — prevents protocol downgrade attacks.\n\n'
        '**Fix — Add to your web server config:**\n'
        '```nginx\n# Nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";\n```\n'
        '```apache\n# Apache\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n```\n'
        '```python\n# Flask/Python\nresponse.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n```\n\n'
        '**Cricket analogy:** Without HSTS, attackers can bowl a googly and switch you to HTTP! 🏏'
    ),
    'csp': (
        '**Content Security Policy (CSP)**\n\n'
        'Blocks unauthorized scripts — prevents XSS attacks.\n\n'
        '**Fix:**\n'
        "```nginx\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:;\";\n```\n\n"
        '**Test your CSP:** https://csp-evaluator.withgoogle.com'
    ),
    'spf': (
        '**SPF (Sender Policy Framework)**\n\n'
        'Prevents email spoofing by authorizing which servers can send email for your domain.\n\n'
        '**Fix — Add DNS TXT record:**\n'
        '```\nv=spf1 include:_spf.google.com include:sendgrid.net ~all\n```\n\n'
        '**Check your SPF:** `dig TXT yourdomain.com`'
    ),
    'dkim': (
        '**DKIM (DomainKeys Identified Mail)**\n\n'
        'Cryptographically signs emails to prove they came from you.\n\n'
        '**Setup steps:**\n'
        '1. Generate keys via your email provider (Google Workspace, Postfix, etc.)\n'
        '2. Add public key as DNS TXT record: `mail._domainkey.yourdomain.com`\n'
        '3. Verify: `dig TXT mail._domainkey.yourdomain.com`'
    ),
    'dmarc': (
        '**DMARC**\n\n'
        'Enforces SPF+DKIM and sends you reports of email authentication failures.\n\n'
        '**Fix — Add DNS TXT record:**\n'
        '```\nv=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100\n```\n\n'
        '**Policies:** `none` (monitor) → `quarantine` → `reject` (strictest)'
    ),
    'ssl': (
        '**SSL/TLS Fix on Linux:**\n'
        '```bash\n# Install free SSL cert with Let\'s Encrypt\nsudo apt install certbot python3-certbot-nginx -y\nsudo certbot --nginx -d yourdomain.com\n\n# Auto-renew\nsudo systemctl enable certbot.timer\n```\n\n'
        '**Test SSL:** https://www.ssllabs.com/ssltest/'
    ),
    'redis': (
        '**Redis Exposed — CRITICAL FIX:**\n'
        '```bash\nsudo nano /etc/redis/redis.conf\n# Change these lines:\nbind 127.0.0.1\nrequirepass YourStrongPassword123!\nprotected-mode yes\n\nsudo systemctl restart redis\n```\n\n'
        '**Verify fix:** `redis-cli -a YourPassword ping` → should return PONG\n\n'
        '🚨 **Cricket**: This is a No Ball — easy wicket for attackers!'
    ),
    'mongodb': (
        '**MongoDB Exposed — Fix:**\n'
        '```yaml\n# /etc/mongod.conf\nsecurity:\n  authorization: enabled\nnet:\n  bindIp: 127.0.0.1\n  port: 27017\n```\n'
        '```bash\nsudo systemctl restart mongod\n```\n\n'
        '**Create admin user:**\n'
        '```javascript\ndb.createUser({user:"admin", pwd:"StrongPass!", roles:["root"]})\n```'
    ),
    'elasticsearch': (
        '**Elasticsearch Exposed — Fix:**\n'
        '```yaml\n# /etc/elasticsearch/elasticsearch.yml\nxpack.security.enabled: true\nnetwork.host: 127.0.0.1\n```\n'
        '```bash\nsudo systemctl restart elasticsearch\n# Set password\n/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto\n```'
    ),
    'ftp': (
        '**FTP is insecure (plaintext credentials!)**\n\n'
        '**Disable FTP:**\n'
        '```bash\nsudo systemctl disable --now vsftpd\n```\n\n'
        '**Use SFTP instead (SSH-based, encrypted):**\n'
        '```bash\nsftp user@hostname\n# Or with scp:\nscp file.txt user@hostname:/remote/path\n```'
    ),
    'telnet': (
        '**Telnet is CRITICAL RISK — completely unencrypted!**\n\n'
        '```bash\n# Disable Telnet immediately\nsudo systemctl disable --now telnetd\nsudo apt remove telnetd -y\n\n# Use SSH instead\nsudo apt install openssh-server -y\nsudo systemctl enable --now ssh\n```'
    ),
    'smb': (
        '**SMB / Port 445 Fix:**\n'
        '```bash\n# Linux — disable SMBv1\nsudo nano /etc/samba/smb.conf\n# Add under [global]:\nmin protocol = SMB2\nclient min protocol = SMB2\n\n# Firewall\nsudo ufw deny 445/tcp\n```'
    ),
    'rdp': (
        '**RDP / Port 3389 Security:**\n'
        '1. Enable **Network Level Authentication (NLA)**\n'
        '2. Change default port: `HKLM\\System\\CurrentControlSet\\Control\\TerminalServer\\WinStations\\RDP-Tcp\\PortNumber`\n'
        '3. Restrict via firewall to VPN IPs only\n'
        '4. Use **fail2ban** or **Windows firewall** to block brute force'
    ),
    'nmap': (
        '**Nmap Commands:**\n'
        '```bash\n# Basic scan\nnmap -sV target.com\n\n# Fast scan (top 100 ports)\nnmap -F target.com\n\n# All ports\nnmap -p- -T4 target.com\n\n# Aggressive (needs root)\nsudo nmap -A target.com\n\n# Install nmap\nsudo apt install nmap -y\n```'
    ),
    'nikto': (
        '**Nikto Web Scanner:**\n'
        '```bash\n# Install\nsudo apt install nikto -y\n\n# Basic scan\nnikto -h http://target.com\n\n# With SSL\nnikto -h https://target.com -ssl\n\n# Save report\nnikto -h target.com -o report.html -Format htm\n```'
    ),
    'nuclei': (
        '**Nuclei Vulnerability Scanner:**\n'
        '```bash\n# Install\nsudo apt install nuclei -y\n# OR\ngo install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\n# Update templates\nnuclei -update-templates\n\n# Scan\nnuclei -u https://target.com\n\n# Specific severity\nnuclei -u target.com -severity critical,high\n```'
    ),
    'phishing': (
        '**Phishing Email Indicators:**\n\n'
        '**Header Red Flags:**\n'
        '- SPF/DKIM/DMARC failures\n'
        '- Reply-To different from From address\n'
        '- Return-Path mismatch\n'
        '- Suspicious sending IP\n\n'
        '**Content Red Flags:**\n'
        '- Urgency/fear language\n'
        '- Generic greeting ("Dear Customer")\n'
        '- Hover links don\'t match display text\n'
        '- Requests for credentials/payment\n'
        '- Unusual attachments (.exe, .zip, .docm)'
    ),
    'xss': (
        '**XSS (Cross-Site Scripting) Fix:**\n'
        '```python\n# Always escape output\nfrom markupsafe import escape\nreturn f"<p>{escape(user_input)}</p>"\n```\n'
        '```nginx\n# Add CSP header\nadd_header Content-Security-Policy "default-src \'self\'; script-src \'self\'";\n```\n\n'
        '**Use:** `bleach` library for sanitization'
    ),
    'sqli': (
        '**SQL Injection Fix:**\n'
        '```python\n# WRONG — vulnerable:\nquery = f"SELECT * FROM users WHERE id = {user_id}"\n\n# CORRECT — parameterized:\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n```\n\n'
        '**Also use:** ORM (SQLAlchemy, Django ORM) — parameterized by default'
    ),
    'score': (
        '**Risk Score Meaning:**\n\n'
        '| Score | Rating | Action |\n'
        '|-------|--------|--------|\n'
        '| 90-100 | ✅ Excellent | Maintain |\n'
        '| 75-89  | 🟢 Good | Minor fixes |\n'
        '| 55-74  | 🟡 Fair | Fix within a week |\n'
        '| 35-54  | 🟠 Poor | Fix urgently |\n'
        '| 0-34   | 🔴 Critical | Fix NOW |\n\n'
        '**Scoring:** Critical=-25pts, High=-12pts, Medium=-5pts, Low=-2pts'
    ),
    'port 4444': (
        '🚨 **Port 4444 Open — URGENT!**\n\n'
        'Port 4444 is the **Metasploit default reverse shell port**.\n\n'
        '**Immediate steps:**\n'
        '```bash\n# Check what\'s listening\nsudo ss -tlnp | grep 4444\nsudo lsof -i :4444\n\n# Kill the process if suspicious\nsudo kill -9 <PID>\n\n# Block with firewall\nsudo ufw deny 4444/tcp\n```\n\n'
        '🏏 **Cricket**: This is a bouncer aimed at your stumps — duck NOW!'
    ),
    'open redirect': (
        '**Open Redirect Fix:**\n'
        '```python\n# Validate redirect URLs\nfrom urllib.parse import urlparse\n\ndef safe_redirect(url):\n    parsed = urlparse(url)\n    if parsed.netloc and parsed.netloc != "yourdomain.com":\n        return "/"\n    return url\n```'
    ),
    'default': (
        '🏏 **VulnCatch AI Copilot** — Ready to help!\n\n'
        'I can answer questions about:\n'
        '- 🔧 **Fix vulnerabilities** — "How do I fix Redis exposure?"\n'
        '- 📊 **Understand results** — "What does my risk score mean?"\n'
        '- 🐛 **Install tools** — "How do I install Nikto on Kali?"\n'
        '- 🔑 **Get free AI key** — "How do I get a Groq API key?"\n'
        '- 📧 **Phishing** — "What are signs of a phishing email?"\n'
        '- 🌐 **Web security** — "How do I fix XSS?"\n'
        '- 🛡 **Headers** — "How do I add HSTS?"\n\n'
        '> 🤖 **For real AI answers:** Get a **free Groq key** at console.groq.com\n'
        '> then paste it in **⚙ Settings**'
    ),
}


def _offline_answer(message: str) -> str:
    msg = message.lower()
    # Check multi-word keys first
    for kw in ['api key', 'port 4444', 'open redirect']:
        if kw in msg:
            return f'📚 **VulnCatch Offline KB:**\n\n{_KB[kw]}'
    # Single-word keys
    for kw, ans in _KB.items():
        if kw == 'default':
            continue
        if kw in msg:
            return f'📚 **VulnCatch Offline KB:**\n\n{ans}'
    return _KB['default']


# ── Legacy compatibility wrappers ──────────────────────────────────────────────
def query_ai_copilot(message: str, api_key: str = '', scan_context: dict = None) -> dict:
    """Legacy wrapper — routes through new multi-provider engine."""
    # api_key could be Groq or Gemini — detect by prefix
    groq_key   = api_key if (api_key or '').startswith('gsk_') else _groq_key
    gemini_key = api_key if (api_key or '').startswith('AIzaSy') else _gemini_key
    return query_ai(message, groq_key=groq_key, gemini_key=gemini_key, scan_context=scan_context)


def validate_scan_accuracy(findings: list, score: int, modules_run: list) -> dict:
    """Quick local accuracy validation — no API needed."""
    issues = []
    confidence = 90

    critical = sum(1 for f in findings if f.get('severity') == 'critical')
    high      = sum(1 for f in findings if f.get('severity') == 'high')

    if score >= 80 and critical > 0:
        issues.append(f'Score {score}/100 but {critical} Critical finding(s) exist — risk may be underestimated.')
        confidence -= 25
    if score >= 70 and (critical + high) >= 4:
        issues.append(f'{critical + high} Critical/High findings with score {score}/100 — run more modules for full picture.')
        confidence -= 15
    if len(findings) == 0 and len(modules_run) <= 2:
        issues.append('Very few modules run — add more scan modules for a complete assessment.')
        confidence -= 20
    tool_missing = [f for f in findings if 'Tool Missing' in f.get('category', '')]
    if tool_missing:
        issues.append(f'{len(tool_missing)} tool(s) missing (Nikto/Nuclei) — install with: sudo apt install nikto nuclei -y')
        confidence -= 10
    cdn_hint = any('cloudflare' in (f.get('description') or '').lower() or 'cdn' in (f.get('category') or '').lower() for f in findings)
    if cdn_hint:
        issues.append('Target appears behind CDN — real server ports may not be visible.')
        confidence -= 5

    return {
        'confidence': max(30, min(100, confidence)),
        'issues': issues,
        'recommendation': 'Results look reliable.' if not issues else 'Review flagged concerns above.',
    }
