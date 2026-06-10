"""VulnCatch AI Platform v2.0 — Flask Application with Authentication & Full Platform Routes"""
from flask import (Flask, request, jsonify, render_template, Response,
                   stream_with_context, redirect, url_for, session)
import threading
import queue
import uuid
import json
import time
import os
import functools
from datetime import datetime

from database.db import Database
from scanner.port_scanner import (basic_port_scan, full_port_scan,
                                  aggressive_scan, service_version_detection,
                                  banner_grab)
from scanner.web_scanner import (check_security_headers, http_methods_probe,
                                 nikto_scan, nuclei_scan)
from scanner.network_scanner import dns_enumeration, whois_lookup, ssl_analysis
from scanner.osint_scanner import run_osint_scan
from scanner.risk_engine import compute_risk_score, get_risk_label
from scanner.ai_copilot import query_ai_copilot, validate_scan_accuracy
from scanner.ai_validator import validate_with_ai
from scanner.email_analyzer import analyze_email
from scanner.multi_agent import MultiAgentOrchestrator

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vulncatch-secret-2024-platform')
db = Database()

_scan_queues: dict = {}
_scan_lock = threading.Lock()

# ── Pre-configured API keys ──────────────────────────────────────────────────
VT_API_KEY    = os.environ.get('VT_API_KEY',   '943390c19adeebacb22f03c1c5a65fcf8e0216bef605b181a4ff75bf3f3217b6')
GEMINI_KEY    = os.environ.get('GEMINI_API_KEY', '')
GROQ_KEY      = os.environ.get('GROQ_API_KEY',   '')
ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY',  '')

MODULES = {
    'port_scan'        : ('Basic Port Scan',             basic_port_scan,           'Network'),
    'full_port_scan'   : ('Full Port Scan',              full_port_scan,            'Network'),
    'aggressive_scan'  : ('Aggressive Scan',             aggressive_scan,           'Network'),
    'service_detection': ('Service & Version Detection', service_version_detection, 'Network'),
    'banner_grab'      : ('Banner Grabbing',             banner_grab,               'Network'),
    'headers'          : ('Security Headers Check',      check_security_headers,    'Web'),
    'ssl'              : ('SSL/TLS Analysis',            ssl_analysis,              'Web'),
    'http_methods'     : ('HTTP Methods Probe',          http_methods_probe,        'Web'),
    'dns'              : ('DNS Enumeration',             dns_enumeration,           'OSINT'),
    'whois'            : ('WHOIS Lookup',                whois_lookup,              'OSINT'),
    'osint'            : ('OSINT & Threat Intel',        run_osint_scan,            'OSINT'),
    'nikto'            : ('Nikto Web Scan',              nikto_scan,                'Web'),
    'nuclei'           : ('Nuclei Scan',                 nuclei_scan,               'Web'),
}

DEFAULT_QUICK_MODULES = ['port_scan', 'headers', 'ssl', 'dns', 'whois']


# ── Auth Helpers ─────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrapper


def get_current_user():
    uid = session.get('user_id')
    if uid:
        return db.get_user(uid)
    return None


def template_vars(**extra):
    """Common template variables injected into every page."""
    user = get_current_user()
    stats = db.get_dashboard_stats()
    base = dict(
        current_user   = user,
        active_page    = '',
        critical_count = stats.get('critical', 0),
        vt_configured  = bool(VT_API_KEY),
    )
    base.update(extra)   # extra keys override base keys — no conflict
    return base


# ── Scan Push Helper ─────────────────────────────────────────────────────────
def _push(q, msg_type, data):
    try:
        q.put_nowait({'type': msg_type, **data})
    except Exception:
        pass


# ── Scan Runner (all existing functionality preserved) ──────────────────────
def run_scan(scan_id, target, selected_modules, scan_type='custom'):
    q = _scan_queues.get(scan_id)
    if not q:
        return

    all_findings = []
    total = len(selected_modules)

    def callback(msg_type, data):
        if msg_type == 'finding':
            all_findings.append(data)
            try:
                db.save_finding(scan_id, data)
            except Exception:
                pass
        _push(q, msg_type, data)

    try:
        orchestrator = MultiAgentOrchestrator(api_key=GEMINI_KEY)
        monitor_data = orchestrator.run_monitor(target, callback=callback)

        if not monitor_data.get('target_reachable'):
            _push(q, 'log', {'message': '⚠ Monitor Agent: Target may not be reachable.', 'level': 'warning'})

        for idx, module_id in enumerate(selected_modules, 1):
            if module_id not in MODULES:
                continue
            name, func, category = MODULES[module_id]
            _push(q, 'progress', {'value': int((idx - 1) / total * 100), 'step': idx, 'total': total})
            _push(q, 'section_start', {'name': name, 'category': category, 'step': idx, 'total': total})
            try:
                if module_id == 'osint':
                    func(target, callback, vt_api_key=VT_API_KEY, abuseipdb_key=ABUSEIPDB_KEY)
                else:
                    func(target, callback)
            except Exception as e:
                callback('log', {'message': f'[{name}] error: {e}', 'level': 'error'})
            _push(q, 'section_end', {'name': name})

        raw_score, breakdown = compute_risk_score(all_findings)
        raw_label, raw_color = get_risk_label(raw_score)

        executor_data   = orchestrator.run_executor(all_findings, raw_score, monitor_data, callback=callback)
        supervisor_data = orchestrator.run_supervisor(monitor_data, executor_data, raw_score, all_findings, callback=callback)

        final_score = supervisor_data.get('final_score', raw_score)
        final_label = supervisor_data.get('final_label', raw_label)
        final_color = supervisor_data.get('final_color', raw_color)
        confidence  = supervisor_data.get('confidence_pct', 80)

        accuracy = validate_scan_accuracy(all_findings, final_score, selected_modules)
        db.update_scan(scan_id, status='completed', score=final_score)
        db.update_target_scan_info(target, final_score)

        _push(q, 'score', {
            'score': final_score, 'label': final_label, 'color': final_color,
            'accuracy': accuracy, 'confidence': confidence, **breakdown
        })
        _push(q, 'progress', {'value': 100, 'step': total, 'total': total})
        _push(q, 'complete', {
            'scan_id': scan_id, 'score': final_score, 'label': final_label,
            'findings': len(all_findings), 'accuracy': accuracy, 'confidence': confidence,
        })

        agent_report = {
            'monitor':    monitor_data,
            'executor':   executor_data,
            'supervisor': supervisor_data,
            'final_score': final_score, 'final_label': final_label,
            'confidence':  confidence,
            'top_risks':   supervisor_data.get('top_risks', []),
            'verdict':     supervisor_data.get('supervisor_verdict', ''),
            'security_posture': supervisor_data.get('security_posture', ''),
            'immediate_actions': supervisor_data.get('immediate_actions', []),
        }
        _push(q, 'agent_report', agent_report)

    except Exception as e:
        _push(q, 'error', {'message': str(e)})
        try:
            db.update_scan(scan_id, status='failed', score=0)
        except Exception:
            pass
    finally:
        def _cleanup():
            time.sleep(600)
            with _scan_lock:
                _scan_queues.pop(scan_id, None)
        threading.Thread(target=_cleanup, daemon=True).start()


# ════════════════════════════════════════════════════════════════════════════
# PLATFORM ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))


# ── Authentication ────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = None
    prefill = ''
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        prefill  = email
        user = db.login(email, password)
        if user:
            session['user_id']   = user['id']
            session['user_role'] = user['role']
            session.permanent    = bool(request.form.get('remember'))
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid email or password. Please try again.'
    return render_template('login.html', error=error, prefill_email=prefill)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    stats = db.get_dashboard_stats()
    return render_template('dashboard.html', stats=stats,
                           **template_vars(active_page='dashboard'))


# ── Targets ──────────────────────────────────────────────────────────────────
@app.route('/targets')
@login_required
def targets_page():
    targets = db.get_all_targets()
    return render_template('targets.html', targets=targets,
                           **template_vars(active_page='targets'))


@app.route('/api/targets', methods=['POST'])
@login_required
def api_add_target():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    host = (data.get('host') or '').strip()
    if not name or not host:
        return jsonify({'error': 'Name and host required'}), 400
    try:
        db.add_target(name, host, data.get('type', 'domain'), data.get('description', ''))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/targets/<int:target_id>', methods=['DELETE'])
@login_required
def api_delete_target(target_id):
    try:
        db.delete_target(target_id)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Scans ─────────────────────────────────────────────────────────────────────
@app.route('/scans')
@login_required
def scans_page():
    targets = db.get_all_targets()
    modules_json = json.dumps({mid: {'name': name, 'category': cat}
                               for mid, (name, _, cat) in MODULES.items()})
    default_json = json.dumps(DEFAULT_QUICK_MODULES)
    prefill = request.args.get('target', '')
    return render_template('scan.html',
                           modules=MODULES,
                           modules_json=modules_json,
                           default_modules=DEFAULT_QUICK_MODULES,
                           default_modules_json=default_json,
                           targets=targets,
                           prefill_target=prefill,
                           **template_vars(active_page='scans'))


@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    data      = request.get_json(silent=True) or {}
    target    = (data.get('target') or '').strip()
    modules   = data.get('modules') or []
    scan_type = data.get('scan_type', 'custom')
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    if not modules:
        return jsonify({'error': 'Select at least one scan module'}), 400

    scan_id = str(uuid.uuid4())
    q = queue.Queue(maxsize=2000)
    with _scan_lock:
        _scan_queues[scan_id] = q
    db.create_scan(scan_id, target, modules, scan_type)
    threading.Thread(target=run_scan, args=(scan_id, target, modules, scan_type), daemon=True).start()
    return jsonify({'scan_id': scan_id, 'status': 'started'})


@app.route('/stream/<scan_id>')
def stream(scan_id):
    def generate():
        q = _scan_queues.get(scan_id)
        if not q:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found'})}\n\n"
            return
        while True:
            try:
                item = q.get(timeout=90)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get('type') in ('complete', 'error'):
                    time.sleep(0.5)
                    for _ in range(20):
                        try:
                            item2 = q.get_nowait()
                            yield f"data: {json.dumps(item2)}\n\n"
                        except Exception:
                            break
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

    resp = Response(stream_with_context(generate()), mimetype='text/event-stream')
    resp.headers['Cache-Control']     = 'no-cache'
    resp.headers['X-Accel-Buffering'] = 'no'
    resp.headers['Connection']        = 'keep-alive'
    return resp


# ── Findings ──────────────────────────────────────────────────────────────────
@app.route('/findings')
@login_required
def findings_page():
    findings = db.get_all_findings(limit=500)
    finding_targets = sorted(set(f['target'] for f in findings if f.get('target')))
    finding_cats    = sorted(set(f['category'] for f in findings if f.get('category')))
    return render_template('findings.html',
                           findings=findings,
                           finding_targets=finding_targets,
                           finding_cats=finding_cats,
                           request_args=request.args,
                           **template_vars(active_page='findings'))


# ── Scan History ──────────────────────────────────────────────────────────────
@app.route('/history')
@login_required
def history_page():
    scans_raw = db.get_all_scans()
    # Enrich with finding count
    scans = []
    for s in scans_raw:
        details = db.get_scan_details(s['id'])
        s['finding_count'] = len(details.get('findings', [])) if details else 0
        scans.append(s)
    return render_template('history.html', scans=scans,
                           **template_vars(active_page='history'))


# ── Reports ───────────────────────────────────────────────────────────────────
@app.route('/reports')
@login_required
def reports_page():
    scans = db.get_all_scans()
    return render_template('reports.html', scans=scans,
                           **template_vars(active_page='reports'))


@app.route('/report/<scan_id>')
@login_required
def report(scan_id):
    scan = db.get_scan_details(scan_id)
    if not scan:
        return 'Scan not found', 404
    label, color = get_risk_label(scan.get('score') or 0)
    return render_template('report.html', scan=scan, label=label, color=color,
                           generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                           **template_vars(active_page='reports'))


# ── AI Analysis ───────────────────────────────────────────────────────────────
@app.route('/ai-analysis')
@login_required
def ai_analysis_page():
    scans = db.get_all_scans()
    return render_template('ai_analysis.html', scans=scans,
                           **template_vars(active_page='ai'))


# ── Threat Intel ─────────────────────────────────────────────────────────────
@app.route('/threat-intel')
@login_required
def threat_intel_page():
    return render_template('threat_intel.html',
                           **template_vars(active_page='intel'))


# ── Email Analyzer ────────────────────────────────────────────────────────────
@app.route('/email-analyzer')
@login_required
def email_analyzer_page():
    return render_template('email_analyzer.html',
                           **template_vars(active_page='email'))


# ── Settings ──────────────────────────────────────────────────────────────────
@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html', **template_vars(active_page='settings'))


# ════════════════════════════════════════════════════════════════════════════
# API ROUTES (all preserved + new ones)
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data     = request.get_json(silent=True) or {}
    message  = (data.get('message') or '').strip()
    req_key  = (data.get('apiKey') or '').strip()
    scan_id  = data.get('scanId')
    if not message:
        return jsonify({'error': 'Message required'}), 400
    scan_context = None
    if scan_id:
        try: scan_context = db.get_scan_details(scan_id)
        except Exception: pass
    result = query_ai_copilot(message, api_key=req_key or GROQ_KEY or GEMINI_KEY,
                              scan_context=scan_context)
    return jsonify(result)


@app.route('/api/ai-validate/<scan_id>', methods=['POST'])
@login_required
def api_ai_validate(scan_id):
    data    = request.get_json(silent=True) or {}
    api_key = (data.get('apiKey') or GEMINI_KEY or '').strip()
    try:
        scan = db.get_scan_details(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        result = validate_with_ai(scan.get('target',''), scan.get('findings',[]),
                                  scan.get('score', 0), scan.get('modules',[]), api_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/agent-status', methods=['GET'])
def api_agent_status():
    ai_mode = 'groq' if GROQ_KEY else ('gemini' if GEMINI_KEY else 'offline')
    return jsonify({
        'agents': [
            {'id': 1, 'name': 'Monitor Agent',    'role': 'Pre-scan environment assessment',    'status': 'ready'},
            {'id': 2, 'name': 'Validator Agent',  'role': 'Finding validation & deduplication', 'status': 'ready'},
            {'id': 3, 'name': 'Supervisor Agent', 'role': 'Cross-validation & final report',    'status': 'ready'},
            {'id': 4, 'name': 'Meta-Judge Agent', 'role': 'AI quality audit & oversight',       'status': 'ready'},
        ],
        'ai_mode':           ai_mode,
        'vt_configured':     bool(VT_API_KEY),
        'groq_configured':   bool(GROQ_KEY),
        'gemini_configured': bool(GEMINI_KEY),
    })


@app.route('/api/analyze-email', methods=['POST'])
@login_required
def api_analyze_email():
    data          = request.get_json(silent=True) or {}
    raw_email     = (data.get('rawEmail') or '').strip()
    vt_key        = (data.get('vtApiKey') or VT_API_KEY).strip()
    abuseipdb_key = (data.get('abuseipdbKey') or ABUSEIPDB_KEY).strip()
    if not raw_email:
        return jsonify({'error': 'Raw email content required'}), 400
    findings_collected, logs_collected = [], []
    def callback(msg_type, payload):
        if msg_type == 'finding': findings_collected.append(payload)
        elif msg_type == 'log':   logs_collected.append(payload)
    try:
        result = analyze_email(raw_email, vt_api_key=vt_key,
                               abuseipdb_key=abuseipdb_key, callback=callback)
        result['logs']          = logs_collected
        result['findings_list'] = findings_collected
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/threat-intel', methods=['POST'])
@login_required
def api_threat_intel():
    data   = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Target required'}), 400
    from scanner.osint_scanner import (check_virustotal_domain, check_virustotal_ip,
                                       check_abuseipdb, get_ip_info)
    import socket, re, concurrent.futures
    domain = re.sub(r'^https?://', '', target).split('/')[0].strip()
    try:    ip = socket.gethostbyname(domain)
    except: ip = None
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {'vt_domain': ex.submit(check_virustotal_domain, domain, VT_API_KEY)}
        if ip:
            futures['ipinfo'] = ex.submit(get_ip_info, ip)
            futures['vt_ip']  = ex.submit(check_virustotal_ip, ip, VT_API_KEY)
            if ABUSEIPDB_KEY:
                futures['abuseipdb'] = ex.submit(check_abuseipdb, ip, ABUSEIPDB_KEY)
        for k, f in futures.items():
            try:    results[k] = f.result(timeout=15)
            except Exception as e: results[k] = {'error': str(e)}
    results['target']      = target
    results['resolved_ip'] = ip
    return jsonify(results)


@app.route('/api/history')
@login_required
def api_history():
    return jsonify(db.get_all_scans())


@app.route('/api/scan/<scan_id>')
@login_required
def api_scan_detail(scan_id):
    scan = db.get_scan_details(scan_id)
    if not scan:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(scan)


@app.route('/api/set-keys', methods=['POST'])
@login_required
def api_set_keys():
    global GEMINI_KEY, ABUSEIPDB_KEY, GROQ_KEY
    data = request.get_json(silent=True) or {}
    if data.get('groqKey'):
        GROQ_KEY = data['groqKey'].strip()
        os.environ['GROQ_API_KEY'] = GROQ_KEY
    if data.get('geminiKey'):
        GEMINI_KEY = data['geminiKey'].strip()
        os.environ['GEMINI_API_KEY'] = GEMINI_KEY
    if data.get('abuseipdbKey'):
        ABUSEIPDB_KEY = data['abuseipdbKey'].strip()
        os.environ['ABUSEIPDB_KEY']  = ABUSEIPDB_KEY
    ai_mode = 'groq' if GROQ_KEY else ('gemini' if GEMINI_KEY else 'offline')
    return jsonify({'status': 'saved', 'ok': True, 'ai_mode': ai_mode,
                    'groq': bool(GROQ_KEY), 'gemini': bool(GEMINI_KEY),
                    'abuseipdb': bool(ABUSEIPDB_KEY)})


@app.route('/api/profile', methods=['POST'])
@login_required
def api_update_profile():
    data = request.get_json(silent=True) or {}
    uid  = session.get('user_id')
    try:
        db.update_profile(uid, data.get('full_name',''), data.get('email',''))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    data = request.get_json(silent=True) or {}
    uid  = session.get('user_id')
    user = db.get_user(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    # Verify current password
    full_user = db.login(user['email'], data.get('current_password',''))
    if not full_user:
        return jsonify({'error': 'Current password is incorrect'}), 400
    new_pw = (data.get('new_password') or '').strip()
    if len(new_pw) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    db.update_password(uid, new_pw)
    return jsonify({'ok': True})


@app.route('/api/modules')
def api_modules():
    return jsonify({mid: {'name': name, 'category': cat}
                    for mid, (name, _, cat) in MODULES.items()})


@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    return jsonify(db.get_dashboard_stats())


# ── Legacy redirect (old / route) ────────────────────────────────────────────
@app.route('/legacy')
def legacy_index():
    """Preserve old single-page interface."""
    return render_template('index.html', modules=MODULES)


# ════════════════════════════════════════════════════════════════════════════
# STARTUP
# ════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    db.init()
    print()
    print('╔' + '═'*58 + '╗')
    print('║   VulnCatch AI  v2.0  Platform  🛡️                     ║')
    print('║   Professional Vulnerability Management Platform        ║')
    print('╠' + '═'*58 + '╣')
    print('║  🌐  http://localhost:5000                              ║')
    print('║  🔑  Login: admin@vulncatch.ai / admin123               ║')
    print('║  🤖  4-Agent AI: Monitor → Validator → Supervisor →    ║')
    print('║      Meta-Judge                                         ║')
    print('║  🛡  VirusTotal: Pre-configured ✓                      ║')
    print('╚' + '═'*58 + '╝')
    print()
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5000)
