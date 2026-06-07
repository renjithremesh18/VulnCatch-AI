"""
VulnCatch AI — 3-Agent Multi-Agent System
==========================================
Agent 1 (Monitor)    : Watches tool health, checks tool availability, validates targets
Agent 2 (Executor)   : Runs scan modules, interprets raw findings, normalizes data
Agent 3 (Supervisor) : Reviews both agents, cross-validates, fixes discrepancies, guides the other two

All three agents communicate via Gemini 1.5 Flash (REST API).
Each agent has a distinct system prompt, role, and responsibility.
"""

import requests
import json
import socket
import subprocess
import shutil
import threading
import time
import re
import os

GEMINI_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent'
GROQ_URL   = 'https://api.groq.com/openai/v1/chat/completions'
TIMEOUT = 20


def _call_groq(api_key: str, system: str, user: str) -> dict:
    """Call Groq AI (OpenAI-compatible, free, fast)."""
    if not api_key or not api_key.startswith('gsk_'):
        return {'error': 'no_groq_key', 'text': ''}
    try:
        r = requests.post(
            GROQ_URL,
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json={
                'model': 'llama3-70b-8192',
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user',   'content': user},
                ],
                'temperature': 0.2,
                'max_tokens': 1024,
                'response_format': {'type': 'json_object'},
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 401:
            return {'error': 'invalid_groq_key', 'text': ''}
        if r.status_code == 429:
            return {'error': 'rate_limit', 'text': ''}
        r.raise_for_status()
        text = r.json()['choices'][0]['message']['content'].strip()
        try:
            return {'ok': True, 'data': json.loads(text), 'text': text, 'source': 'groq'}
        except json.JSONDecodeError:
            return {'ok': True, 'data': {}, 'text': text, 'source': 'groq'}
    except requests.Timeout:
        return {'error': 'timeout', 'text': ''}
    except Exception as e:
        return {'error': str(e)[:80], 'text': ''}


def _call_gemini(api_key: str, system: str, user: str, json_mode: bool = False) -> dict:
    """Make a Gemini API call and return parsed result."""
    if not api_key:
        return {'error': 'No API key', 'text': ''}

    config = {'temperature': 0.2, 'maxOutputTokens': 1024}
    if json_mode:
        config['responseMimeType'] = 'application/json'

    payload = {
        'system_instruction': {'parts': [{'text': system}]},
        'contents': [{'role': 'user', 'parts': [{'text': user}]}],
        'generationConfig': config,
    }

    try:
        r = requests.post(
            f'{GEMINI_URL}?key={api_key}',
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        text = r.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        if json_mode:
            text = text.strip('```json').strip('```').strip()
            try:
                return {'ok': True, 'data': json.loads(text), 'text': text, 'source': 'gemini'}
            except json.JSONDecodeError:
                return {'ok': True, 'data': {}, 'text': text, 'source': 'gemini'}
        return {'ok': True, 'text': text, 'source': 'gemini'}
    except requests.HTTPError as e:
        code = e.response.status_code if e.response else 0
        if code == 429:
            return {'error': 'rate_limit', 'text': 'Rate limited — will retry'}
        if code == 400:
            return {'error': 'invalid_key', 'text': 'Invalid Gemini API key'}
        return {'error': f'http_{code}', 'text': f'HTTP error {code}'}
    except Exception as e:
        return {'error': str(e)[:80], 'text': ''}


def _call_ai(groq_key: str, gemini_key: str, system: str, user: str) -> dict:
    """Try Groq first, then Gemini, then return empty."""
    if groq_key:
        result = _call_groq(groq_key, system, user)
        if result.get('ok'):
            return result
    if gemini_key:
        result = _call_gemini(gemini_key, system, user, json_mode=True)
        if result.get('ok'):
            return result
    return {'error': 'no_ai', 'text': '', 'data': {}}


# ===========================================================================
# AGENT 1 — MONITOR AGENT
# Responsibility: checks tool health, target reachability, pre-scan validation
# ===========================================================================

_MONITOR_SYSTEM = """You are VulnCatch Monitor Agent — Agent 1 of 3 in the VulnCatch AI multi-agent system.

Your job is to:
1. Assess whether a given target is reachable and scannable
2. Check which security tools are installed and available
3. Identify any issues that would affect scan quality
4. Give PRECISE, TECHNICAL recommendations to Agent 2 (Executor)
5. Flag any issues for Agent 3 (Supervisor) to review

You must respond in JSON format with these exact keys:
{
  "target_reachable": true/false,
  "resolved_ip": "x.x.x.x or null",
  "is_cdn": true/false,
  "cdn_provider": "Cloudflare/Akamai/none",
  "tools_available": {"nmap": true/false, "nikto": true/false, "nuclei": true/false},
  "recommended_modules": ["port_scan", "headers", "ssl", "dns", "whois", "osint"],
  "skip_modules": ["reason why to skip, e.g. full_port_scan: host behind CDN"],
  "warnings": ["list of warnings"],
  "pre_scan_verdict": "ready/limited/blocked",
  "advice_to_executor": "specific technical advice for Agent 2"
}"""


class MonitorAgent:
    """Agent 1: Pre-scan environment and target validator."""

    def __init__(self, api_key: str = ''):
        self.api_key = api_key
        self.results = {}

    def _check_tool(self, name: str) -> bool:
        return shutil.which(name) is not None

    def _check_target(self, target: str) -> dict:
        clean = re.sub(r'^https?://', '', target).split('/')[0].strip()
        result = {'reachable': False, 'ip': None, 'is_cdn': False, 'cdn': 'none', 'latency_ms': None}
        try:
            ip = socket.gethostbyname(clean)
            result['ip'] = ip
            # Quick ping-style check
            t0 = time.time()
            s = socket.create_connection((clean, 80), timeout=5)
            s.close()
            result['latency_ms'] = round((time.time() - t0) * 1000, 1)
            result['reachable'] = True
        except Exception:
            try:
                ip = socket.gethostbyname(clean)
                result['ip'] = ip
                result['reachable'] = True  # resolves but port 80 filtered
            except Exception:
                pass

        # CDN detection
        if result.get('ip'):
            cdn_ranges = {
                'Cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
                               '104.21.', '104.22.', '104.23.', '104.24.', '104.25.',
                               '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.',
                               '162.158.', '188.114.', '190.93.'],
                'Akamai':    ['23.', '184.', '2.16.', '2.17.', '2.18.', '2.19.'],
                'Fastly':    ['151.101.', '199.232.'],
                'Cloudfront': ['13.', '52.84.', '52.46.'],
            }
            for cdn, prefixes in cdn_ranges.items():
                if any(result['ip'].startswith(p) for p in prefixes):
                    result['is_cdn'] = True
                    result['cdn'] = cdn
                    break
        return result

    def run(self, target: str) -> dict:
        """Run all monitor checks and optionally call Gemini for AI assessment."""
        target_info = self._check_target(target)
        tools = {
            'nmap':   self._check_tool('nmap'),
            'nikto':  self._check_tool('nikto'),
            'nuclei': self._check_tool('nuclei'),
        }

        local_assessment = {
            'target': target,
            'target_reachable': target_info['reachable'],
            'resolved_ip': target_info['ip'],
            'is_cdn': target_info['is_cdn'],
            'cdn_provider': target_info['cdn'],
            'latency_ms': target_info['latency_ms'],
            'tools_available': tools,
            'warnings': [],
        }

        if not target_info['reachable']:
            local_assessment['warnings'].append(f'Target {target} is not reachable (DNS or network issue)')
        if target_info['is_cdn']:
            local_assessment['warnings'].append(f'Target is behind {target_info["cdn"]} CDN — port scan results may be masked')
        if not tools['nmap']:
            local_assessment['warnings'].append('nmap not installed — port scans will use socket-only mode')
        if not tools['nikto']:
            local_assessment['warnings'].append('nikto not installed — run: sudo apt install nikto -y')
        if not tools['nuclei']:
            local_assessment['warnings'].append('nuclei not installed — run: sudo apt install nuclei -y')

        # Build recommended modules
        recommended = ['headers', 'ssl', 'dns', 'whois', 'osint']
        if tools['nmap'] and target_info['reachable']:
            recommended.insert(0, 'port_scan')
        else:
            recommended.insert(0, 'banner_grab')  # socket-based fallback
        if tools['nikto']:
            recommended.append('nikto')
        if tools['nuclei']:
            recommended.append('nuclei')

        local_assessment['recommended_modules'] = recommended

        # If API key available, call Gemini for smarter assessment
        if self.api_key:
            prompt = f"""Assess this target for vulnerability scanning:
Target: {target}
IP: {target_info.get('ip', 'unknown')}
Behind CDN: {target_info['is_cdn']} ({target_info['cdn']})
Reachable: {target_info['reachable']}
Latency: {target_info.get('latency_ms', 'N/A')}ms
Tools: nmap={tools['nmap']}, nikto={tools['nikto']}, nuclei={tools['nuclei']}

Provide your assessment as JSON."""

            result = _call_gemini(self.api_key, _MONITOR_SYSTEM, prompt, json_mode=True)
            if result.get('ok') and result.get('data'):
                ai_data = result['data']
                # Merge AI insights with local data
                local_assessment['ai_assessment'] = ai_data
                local_assessment['advice_to_executor'] = ai_data.get('advice_to_executor', '')
                local_assessment['pre_scan_verdict'] = ai_data.get('pre_scan_verdict', 'ready')
                # Add AI warnings
                for w in ai_data.get('warnings', []):
                    if w not in local_assessment['warnings']:
                        local_assessment['warnings'].append(w)
            else:
                local_assessment['pre_scan_verdict'] = 'ready' if target_info['reachable'] else 'blocked'
                local_assessment['advice_to_executor'] = (
                    f'Target {"is reachable" if target_info["reachable"] else "is NOT reachable"}. '
                    f'{"Behind CDN — real ports may not be visible. " if target_info["is_cdn"] else ""}'
                    f'Use modules: {", ".join(recommended)}'
                )
        else:
            local_assessment['pre_scan_verdict'] = 'ready' if target_info['reachable'] else 'blocked'
            local_assessment['advice_to_executor'] = (
                f'{"Target behind " + target_info["cdn"] + " CDN. " if target_info["is_cdn"] else ""}'
                f'Recommended modules: {", ".join(recommended)}.'
            )

        self.results = local_assessment
        return local_assessment


# ===========================================================================
# AGENT 2 — EXECUTOR AGENT
# Responsibility: interprets raw scan findings, normalizes data, fills gaps
# ===========================================================================

_EXECUTOR_SYSTEM = """You are VulnCatch Executor Agent — Agent 2 of 3 in the VulnCatch AI multi-agent system.

Your job is to:
1. Analyze raw scan findings and determine if they are accurate
2. Identify false positives (e.g., CDN-masked results, rate limiting, tool errors)
3. Normalize and enrich findings with additional context
4. Estimate severity correctly based on the full context
5. Report any anomalies to Agent 3 (Supervisor)

You must respond in JSON:
{
  "validated_findings": [
    {"original_severity": "high", "adjusted_severity": "medium", "reason": "...", "description": "...", "category": "..."}
  ],
  "false_positives_removed": [{"description": "...", "reason": "..."}],
  "gaps_identified": ["what the scan missed"],
  "anomalies": ["anything unexpected"],
  "normalized_score": 0-100,
  "executor_verdict": "accurate/inflated/deflated",
  "message_to_supervisor": "key points for Agent 3"
}"""


class ExecutorAgent:
    """Agent 2: Finding interpreter and normalizer."""

    def __init__(self, api_key: str = ''):
        self.api_key = api_key
        self.results = {}

    def _local_normalize(self, findings: list, monitor_data: dict) -> dict:
        """Rule-based normalization without API."""
        validated = []
        false_positives = []
        is_cdn = monitor_data.get('is_cdn', False)

        for f in findings:
            sev   = (f.get('severity') or 'info').lower()
            desc  = (f.get('description') or '').lower()
            cat   = (f.get('category') or '').lower()

            # CDN false positive: if behind Cloudflare, port scan findings are likely false
            if is_cdn and 'port risk' in cat and 'pre-scan' not in cat:
                false_positives.append({
                    'description': f.get('description', ''),
                    'reason': f'Target is behind CDN — port {f.get("port","?")} may not be the real server port',
                })
                continue

            # Tool missing is always info
            if 'tool missing' in cat:
                f['severity'] = 'info'
                sev = 'info'

            # Downgrade "low" SSL findings if cert is valid
            if sev == 'medium' and 'ssl' in desc and 'expired' not in desc and 'self-signed' not in desc:
                f['adjusted_severity'] = 'low'
            else:
                f['adjusted_severity'] = sev

            validated.append(f)

        return {
            'validated_findings': validated,
            'false_positives_removed': false_positives,
        }

    def run(self, findings: list, score: int, monitor_data: dict) -> dict:
        """Interpret and normalize findings."""
        local = self._local_normalize(findings, monitor_data)

        if self.api_key and findings:
            # Summarize findings for Gemini
            summary = []
            for i, f in enumerate(findings[:20], 1):
                summary.append(f"{i}. [{f.get('severity','info').upper()}] {f.get('category','')}: {f.get('description','')[:200]}")

            monitor_notes = monitor_data.get('advice_to_executor', '')
            prompt = f"""Raw scan results to validate:
Target: {monitor_data.get('target', 'unknown')}
Behind CDN: {monitor_data.get('is_cdn', False)} ({monitor_data.get('cdn_provider', 'none')})
Raw score: {score}/100
Monitor Agent notes: {monitor_notes}
Total findings: {len(findings)}

Findings:
{chr(10).join(summary)}

Validate these findings, remove false positives, and normalize severities. Respond in JSON."""

            result = _call_gemini(self.api_key, _EXECUTOR_SYSTEM, prompt, json_mode=True)
            if result.get('ok') and result.get('data'):
                ai_data = result['data']
                # Merge with local normalization
                ai_validated = ai_data.get('validated_findings', [])
                ai_fps       = ai_data.get('false_positives_removed', [])

                self.results = {
                    'validated_findings':    ai_validated or local['validated_findings'],
                    'false_positives_removed': ai_fps or local['false_positives_removed'],
                    'gaps_identified':       ai_data.get('gaps_identified', []),
                    'anomalies':             ai_data.get('anomalies', []),
                    'normalized_score':      ai_data.get('normalized_score', score),
                    'executor_verdict':      ai_data.get('executor_verdict', 'accurate'),
                    'message_to_supervisor': ai_data.get('message_to_supervisor', ''),
                    'source': 'gemini',
                }
                return self.results
            else:
                pass  # fall through to local

        # Local fallback
        n_valid = len(local['validated_findings'])
        n_fp    = len(local['false_positives_removed'])
        self.results = {
            **local,
            'gaps_identified': [],
            'anomalies': [],
            'normalized_score': score,
            'executor_verdict': 'accurate',
            'message_to_supervisor': f'Local normalization: {n_valid} valid findings, {n_fp} false positives removed.',
            'source': 'local',
        }
        return self.results


# ===========================================================================
# AGENT 3 — SUPERVISOR AGENT
# Responsibility: reviews both agents, cross-validates, writes final report
# ===========================================================================

_SUPERVISOR_SYSTEM = """You are VulnCatch Supervisor Agent — Agent 3 of 3 in the VulnCatch AI multi-agent system.

Your role is the HIGHEST authority in the system. You:
1. Review outputs from both Monitor Agent (Agent 1) and Executor Agent (Agent 2)
2. Cross-validate their findings — detect inconsistencies between them
3. Produce the FINAL, authoritative security report
4. Provide specific, actionable remediation steps
5. Assign a FINAL risk score based on ALL evidence
6. Flag any disagreements between agents and resolve them

You must respond in JSON:
{
  "final_score": 0-100,
  "final_label": "Excellent/Good/Fair/Poor/Critical",
  "final_color": "#hex",
  "agent_agreement": "agree/partial/disagree",
  "corrections_made": ["what you changed and why"],
  "top_risks": [
    {"rank": 1, "severity": "critical", "issue": "...", "fix": "exact command or config", "references": "CVE or OWASP"}
  ],
  "security_posture": "one paragraph overall assessment",
  "confidence_pct": 85,
  "immediate_actions": ["do this NOW"],
  "short_term_actions": ["do within 1 week"],
  "long_term_actions": ["do within 1 month"],
  "supervisor_verdict": "summary for user"
}"""


class SupervisorAgent:
    """Agent 3: Cross-validator, final authority, and report generator."""

    def __init__(self, api_key: str = ''):
        self.api_key = api_key
        self.results = {}

    def _local_supervise(self, monitor_data: dict, executor_data: dict, raw_score: int) -> dict:
        """Rule-based supervision without API."""
        final_score = executor_data.get('normalized_score', raw_score)
        validated   = executor_data.get('validated_findings', [])
        fps         = executor_data.get('false_positives_removed', [])
        gaps        = executor_data.get('gaps_identified', [])
        warnings    = monitor_data.get('warnings', [])
        corrections = []

        # Penalize if CDN masked scan
        if monitor_data.get('is_cdn') and final_score > 70:
            corrections.append(
                f'Score adjusted: target is behind {monitor_data.get("cdn_provider")} CDN — '
                'some findings may be masked. Accuracy may be limited.'
            )

        # Compute label
        if final_score >= 90: label, color = 'Excellent', '#10B981'
        elif final_score >= 75: label, color = 'Good', '#16A34A'
        elif final_score >= 55: label, color = 'Fair', '#F59E0B'
        elif final_score >= 35: label, color = 'Poor', '#F97316'
        else: label, color = 'Critical', '#EF4444'

        # Priority fixes
        weight = {'critical':4,'high':3,'medium':2,'low':1,'info':0}
        sorted_f = sorted(validated, key=lambda f: weight.get((f.get('severity') or 'info').lower(), 0), reverse=True)
        top_risks = []
        for i, f in enumerate(sorted_f[:5], 1):
            top_risks.append({
                'rank': i,
                'severity': f.get('severity', 'info'),
                'issue': f.get('description', '')[:150],
                'fix': _suggest_fix(f),
                'references': '',
            })

        all_issues = warnings + gaps + corrections
        return {
            'final_score': final_score,
            'final_label': label,
            'final_color': color,
            'agent_agreement': 'agree' if not corrections else 'partial',
            'corrections_made': corrections,
            'top_risks': top_risks,
            'security_posture': (
                f'Scan of {monitor_data.get("target","target")} completed. '
                f'{len(validated)} validated findings, {len(fps)} false positives removed. '
                f'{"CDN masking may affect accuracy. " if monitor_data.get("is_cdn") else ""}'
                f'Final risk score: {final_score}/100 ({label}).'
            ),
            'confidence_pct': max(50, 90 - (10 if monitor_data.get('is_cdn') else 0) - (5 * len(gaps))),
            'immediate_actions': [r['fix'] for r in top_risks[:2] if r.get('severity') in ('critical','high')],
            'short_term_actions': [r['fix'] for r in top_risks[2:4]],
            'long_term_actions': [r['fix'] for r in top_risks[4:]] + ['Run full scan monthly'],
            'supervisor_verdict': f'Risk is {label} ({final_score}/100). {len(corrections)} adjustment(s) made by Supervisor.',
            'source': 'local',
        }

    def run(self, monitor_data: dict, executor_data: dict, raw_score: int, raw_findings: list) -> dict:
        """Cross-validate and produce final authoritative report."""
        if self.api_key:
            validated   = executor_data.get('validated_findings', raw_findings)
            fps         = executor_data.get('false_positives_removed', [])
            gaps        = executor_data.get('gaps_identified', [])
            anomalies   = executor_data.get('anomalies', [])
            exec_msg    = executor_data.get('message_to_supervisor', '')
            mon_verdict = monitor_data.get('pre_scan_verdict', 'ready')
            exec_verdict = executor_data.get('executor_verdict', 'accurate')

            # Summarize validated findings
            f_lines = [f"{i}. [{f.get('severity','info').upper()}] {f.get('description','')[:150]}"
                       for i, f in enumerate(validated[:15], 1)]

            prompt = f"""Review this complete scan session from your two sub-agents:

=== MONITOR AGENT REPORT ===
Target: {monitor_data.get('target')}
IP: {monitor_data.get('resolved_ip')}
CDN: {monitor_data.get('is_cdn')} ({monitor_data.get('cdn_provider')})
Tools: {monitor_data.get('tools_available')}
Pre-scan verdict: {mon_verdict}
Warnings: {monitor_data.get('warnings', [])}

=== EXECUTOR AGENT REPORT ===
Raw score: {raw_score}/100
Normalized score: {executor_data.get('normalized_score', raw_score)}/100
Executor verdict: {exec_verdict}
FPs removed: {len(fps)}
Gaps: {gaps}
Anomalies: {anomalies}
Message: {exec_msg}

=== VALIDATED FINDINGS ({len(validated)}) ===
{chr(10).join(f_lines)}

=== YOUR TASK ===
Produce the final authoritative security report in JSON format."""

            result = _call_gemini(self.api_key, _SUPERVISOR_SYSTEM, prompt, json_mode=True)
            if result.get('ok') and result.get('data'):
                ai_data = result['data']
                ai_data['source'] = 'gemini'
                self.results = ai_data
                return ai_data

        # Local fallback
        local = self._local_supervise(monitor_data, executor_data, raw_score)
        self.results = local
        return local


def _suggest_fix(finding: dict) -> str:
    """Quick fix lookup from description keywords."""
    desc = (finding.get('description') or '').lower()
    fixes = {
        'redis':  'sudo nano /etc/redis/redis.conf → add: requirepass YourPassword && bind 127.0.0.1',
        'mongodb': 'Edit /etc/mongod.conf → security.authorization: enabled && bindIp: 127.0.0.1',
        'elasticsearch': 'elasticsearch.yml → xpack.security.enabled: true',
        'telnet': 'sudo systemctl disable --now telnetd && use SSH instead',
        'ftp':    'sudo systemctl disable vsftpd && use sftp://user@host instead',
        'smb':    'PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false',
        'vnc':    'Add SSH tunnel: ssh -L 5900:localhost:5900 user@host',
        'hsts':   'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'csp':    "Add header: Content-Security-Policy: default-src 'self'",
        'spf':    'Add DNS TXT: v=spf1 include:_spf.yourmailprovider.com ~all',
        'dmarc':  'Add DNS TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
        'ssl':    'sudo certbot --nginx -d yourdomain.com (free SSL)',
        'mysql':  '/etc/mysql/mysqld.cnf → bind-address = 127.0.0.1',
        'rdp':    'Enable NLA, restrict via firewall, place behind VPN',
        '4444':   'URGENT: Port 4444 open — check for active backdoor immediately!',
        'x-frame': 'Add header: X-Frame-Options: DENY',
        'x-content': 'Add header: X-Content-Type-Options: nosniff',
    }
    for kw, fix in fixes.items():
        if kw in desc:
            return fix
    return 'Investigate and remediate this finding. Ask AI Copilot for specific fix commands.'


# ===========================================================================
# ORCHESTRATOR — coordinates all 3 agents
# ===========================================================================

class MultiAgentOrchestrator:
    """
    Coordinates Monitor → Executor → Supervisor pipeline.
    Exposes run_pipeline() for use in app.py scan flow.
    """

    def __init__(self, api_key: str = ''):
        self.api_key = api_key
        self.monitor    = MonitorAgent(api_key)
        self.executor   = ExecutorAgent(api_key)
        self.supervisor = SupervisorAgent(api_key)
        self.pipeline_results = {}

    def run_monitor(self, target: str, callback=None) -> dict:
        """Phase 1: Monitor Agent assesses environment."""
        if callback:
            callback('log', {'message': '🤖 [Agent 1 — Monitor] Assessing target and environment...', 'level': 'info'})
        data = self.monitor.run(target)
        if callback:
            ip  = data.get('resolved_ip', 'unknown')
            cdn = f' [⚠ CDN: {data["cdn_provider"]}]' if data.get('is_cdn') else ''
            callback('log', {'message': f'  Monitor → IP: {ip}{cdn}  |  Verdict: {data.get("pre_scan_verdict","?")}', 'level': 'success'})
            for w in data.get('warnings', []):
                callback('log', {'message': f'  ⚠ {w}', 'level': 'warning'})
        return data

    def run_executor(self, findings: list, score: int, monitor_data: dict, callback=None) -> dict:
        """Phase 2: Executor Agent normalizes findings."""
        if callback:
            callback('log', {'message': f'🤖 [Agent 2 — Executor] Validating {len(findings)} finding(s)...', 'level': 'info'})
        data = self.executor.run(findings, score, monitor_data)
        if callback:
            n_fp = len(data.get('false_positives_removed', []))
            src  = data.get('source', 'local')
            callback('log', {'message': f'  Executor → {n_fp} false positive(s) removed | Source: {src.upper()}', 'level': 'success'})
            for gap in data.get('gaps_identified', [])[:3]:
                callback('log', {'message': f'  Gap: {gap}', 'level': 'warning'})
        return data

    def run_supervisor(self, monitor_data: dict, executor_data: dict, raw_score: int, raw_findings: list, callback=None) -> dict:
        """Phase 3: Supervisor Agent reviews and produces final report."""
        if callback:
            callback('log', {'message': '🤖 [Agent 3 — Supervisor] Cross-validating and generating final report...', 'level': 'info'})
        data = self.supervisor.run(monitor_data, executor_data, raw_score, raw_findings)
        if callback:
            src = data.get('source', 'local')
            callback('log', {
                'message': (f'  Supervisor → Final Score: {data.get("final_score","?")}/100 '
                            f'({data.get("final_label","?")}) | Confidence: {data.get("confidence_pct","?")}% | Source: {src.upper()}'),
                'level': 'success'
            })
            for corr in data.get('corrections_made', [])[:2]:
                callback('log', {'message': f'  📋 Correction: {corr}', 'level': 'warning'})
        return data

    def run_full_pipeline(self, target: str, findings: list, raw_score: int, callback=None) -> dict:
        """Run the complete 3-agent pipeline and return consolidated results."""
        if callback:
            callback('log', {'message': '═══ 🏏 VulnCatch Multi-Agent AI System Starting ═══', 'level': 'info'})

        # Agent 1
        monitor_data = self.run_monitor(target, callback)

        # Agent 2
        executor_data = self.run_executor(findings, raw_score, monitor_data, callback)

        # Agent 3
        supervisor_data = self.run_supervisor(monitor_data, executor_data, raw_score, findings, callback)

        self.pipeline_results = {
            'monitor':    monitor_data,
            'executor':   executor_data,
            'supervisor': supervisor_data,
            'final_score': supervisor_data.get('final_score', raw_score),
            'final_label': supervisor_data.get('final_label', 'Unknown'),
            'final_color': supervisor_data.get('final_color', '#94A3B8'),
            'confidence':  supervisor_data.get('confidence_pct', 80),
            'top_risks':   supervisor_data.get('top_risks', []),
            'verdict':     supervisor_data.get('supervisor_verdict', ''),
        }

        if callback:
            callback('log', {'message': '═══ ✅ Multi-Agent Pipeline Complete ═══', 'level': 'success'})
            callback('agent_report', self.pipeline_results)

        return self.pipeline_results
