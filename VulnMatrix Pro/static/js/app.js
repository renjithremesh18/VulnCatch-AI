/* VulnCatch AI v4.0 — Main Application JavaScript */
'use strict';

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  scanId:      null,
  scanning:    false,
  startTime:   null,
  findings:    [],
  score:       null,
  modules:     [],
  target:      '',
  timerHandle: null,
  groqKey:    localStorage.getItem('vc_groq_key')   || '',
  geminiKey:  localStorage.getItem('vc_gemini_key') || '',
  abuseKey:   localStorage.getItem('vc_abuse_key')  || '',
  chatOpen:    false,
};

// ── Helpers ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const now = () => new Date().toLocaleTimeString('en-GB', {hour12:false});

function ts(msg) {
  const span = document.createElement('span');
  span.className = 'log-timestamp';
  span.textContent = now();
  return span;
}

// ── Module checkbox wiring ─────────────────────────────────────────────────
document.querySelectorAll('.module-item').forEach(item => {
  const cb = item.querySelector('.module-cb');
  if (cb.checked) item.classList.add('checked');
  item.addEventListener('click', () => {
    cb.checked = !cb.checked;
    item.classList.toggle('checked', cb.checked);
  });
});

function selectAll()  { document.querySelectorAll('.module-cb').forEach(cb => { cb.checked = true; cb.closest('.module-item').classList.add('checked'); }); }
function selectNone() { document.querySelectorAll('.module-cb').forEach(cb => { cb.checked = false; cb.closest('.module-item').classList.remove('checked'); }); }

// ── Tab switching ──────────────────────────────────────────────────────────
function switchTab(tab) {
  ['scan','email','history'].forEach(t => {
    $(`tab-${t}`).classList.toggle('active', t === tab);
    $(`panel-${t}`).classList.toggle('active', t === tab);
  });
  if (tab === 'history') loadHistory();
}

function switchTermTab(tab) {
  ['scan','email'].forEach(t => {
    $(`ttab-${t}`).classList.toggle('active', t === tab);
  });
  const terminal  = $('terminal');
  const emailPanel = $('emailResultPanel');
  if (tab === 'scan') {
    terminal.style.display  = 'block';
    emailPanel.style.display = 'none';
  } else {
    terminal.style.display  = 'none';
    emailPanel.style.display = emailPanel.classList.contains('active') ? 'block' : 'flex';
    emailPanel.style.alignItems = 'center';
    emailPanel.style.justifyContent = 'center';
    if (!emailPanel.classList.contains('active')) {
      emailPanel.style.display = 'flex';
      emailPanel.innerHTML = '<div style="color:var(--text-3);font-size:.82rem;text-align:center"><div style="font-size:2rem;opacity:.3">📧</div><p>Paste an email in the left panel and click Analyze</p></div>';
    }
  }
}

// ── Terminal writing ───────────────────────────────────────────────────────
function termLog(msg, level) {
  const placeholder = $('termPlaceholder');
  if (placeholder) placeholder.remove();

  const div = document.createElement('div');
  div.className = `log-${level || 'info'}`;

  const stamp = document.createElement('span');
  stamp.className = 'log-timestamp';
  stamp.textContent = now() + ' ';
  div.appendChild(stamp);
  div.appendChild(document.createTextNode(msg));

  const term = $('terminal');
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

function termSection(name, step, total) {
  const div = document.createElement('div');
  div.className = 'log-section';
  div.innerHTML = `<span class="step-badge">${step}/${total}</span> ${name}`;
  $('terminal').appendChild(div);
  $('terminal').scrollTop = $('terminal').scrollHeight;
}

function termFinding(finding) {
  const sev  = (finding.severity || 'info').toLowerCase();
  const div  = document.createElement('div');
  div.className = `log-finding sev-${sev}`;

  const sevBadge = {
    critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM',
    low: '🟢 LOW', info: '🔵 INFO'
  }[sev] || '⚪ INFO';

  div.innerHTML = `<strong>${sevBadge}</strong> &nbsp; ${escHtml(finding.description || '')}`;
  const term = $('terminal');
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Cricket Animations ─────────────────────────────────────────────────────
function startBallAnimation() {
  $('cricketBall').classList.add('active');
  $('scanOverlay').classList.add('active');
}

function stopBallAnimation() {
  $('cricketBall').classList.remove('active');
  $('scanOverlay').classList.remove('active');
}

let _caughtTimer = null;
function triggerCaughtAnimation(severity, desc) {
  const overlay = $('caughtOverlay');
  $('caughtSub').textContent = desc ? desc.slice(0,40) + (desc.length>40?'…':'') : 'Vulnerability Detected';

  // For critical — shoot wicket particles
  if (severity === 'critical') {
    for (let i = 0; i < 5; i++) {
      const p = document.createElement('div');
      p.className = 'wicket-particle';
      p.textContent = '🏏';
      const angle = (Math.random() * 360) * (Math.PI / 180);
      const dist  = 80 + Math.random() * 120;
      p.style.setProperty('--dx', `${Math.cos(angle)*dist}px`);
      p.style.setProperty('--dy', `${Math.sin(angle)*dist}px`);
      p.style.setProperty('--rot', `${(Math.random()-0.5)*360}deg`);
      p.style.left = '50%';
      p.style.top  = '50%';
      document.body.appendChild(p);
      setTimeout(() => p.remove(), 1100);
    }
  }

  overlay.classList.remove('show');
  void overlay.offsetWidth; // reflow
  overlay.classList.add('show');

  clearTimeout(_caughtTimer);
  _caughtTimer = setTimeout(() => overlay.classList.remove('show'), 2200);
}

function updateScoreboard(counter_id, newVal) {
  const el = $(counter_id);
  if (!el) return;
  el.textContent = newVal;
  el.classList.remove('bump');
  void el.offsetWidth;
  el.classList.add('bump');
  setTimeout(() => el.classList.remove('bump'), 350);
}

// ── Gauge update ───────────────────────────────────────────────────────────
const SCORE_COLORS = {
  critical:  '#EF4444',
  poor:      '#F97316',
  fair:      '#F59E0B',
  good:      '#10B981',
  excellent: '#059669',
};

function updateGauge(score, label, color) {
  const fill = $('gaugeFill');
  const arc  = 220; // stroke-dasharray of the gauge arc
  const pct  = Math.max(0, Math.min(100, score));
  fill.style.strokeDashoffset = arc - (arc * pct / 100);
  fill.style.stroke = color || '#10B981';
  $('gaugeScore').textContent = score;
  const badge = $('riskBadge');
  badge.textContent = (label || 'UNKNOWN').toUpperCase();
  badge.style.background = (color || '#10B981') + '22';
  badge.style.color = color || '#10B981';
  badge.style.border = `1px solid ${color || '#10B981'}44`;
}

// ── Severity bars ──────────────────────────────────────────────────────────
let _counts = {critical:0,high:0,medium:0,low:0,info:0};

function updateBars() {
  const total = Object.values(_counts).reduce((a,b)=>a+b, 0) || 1;
  ['critical','high','medium','low','info'].forEach(sev => {
    const c = _counts[sev];
    $(`cnt-${sev}`).textContent = c;
    $(`bar-${sev}`).style.width = (c / total * 100) + '%';
  });
  updateScoreboard('statFindings', Object.values(_counts).reduce((a,b)=>a+b, 0));
}

function addFinding(finding) {
  const sev = (finding.severity || 'info').toLowerCase();
  if (sev in _counts) _counts[sev]++;
  state.findings.push(finding);
  updateBars();
  termFinding(finding);

  // Cricket catch animation for critical/high
  if (sev === 'critical' || sev === 'high') {
    triggerCaughtAnimation(sev, finding.description);
  }
}

// ── Duration timer ─────────────────────────────────────────────────────────
function startTimer() {
  state.startTime = Date.now();
  state.timerHandle = setInterval(() => {
    const s = Math.floor((Date.now() - state.startTime) / 1000);
    const m = Math.floor(s / 60);
    $('statDuration').textContent = m > 0 ? `${m}m${s%60}s` : `${s}s`;
  }, 1000);
}

function stopTimer() {
  clearInterval(state.timerHandle);
}

// ── Start Scan ─────────────────────────────────────────────────────────────
async function startScan() {
  const target  = $('targetInput').value.trim();
  const modules = [...document.querySelectorAll('.module-cb:checked')].map(cb => cb.value);

  if (!target) { alert('Enter a target domain or IP first'); return; }
  if (!modules.length) { alert('Select at least one scan module'); return; }

  // Reset
  state.findings = [];
  state.scanId   = null;
  state.scanning = true;
  state.target   = target;
  state.modules  = modules;
  _counts = {critical:0,high:0,medium:0,low:0,info:0};
  updateBars();
  updateGauge(0,'SCANNING...','#94A3B8');
  $('statModules').textContent = modules.length;
  $('statStatus').textContent = 'Scanning';

  // UI state
  $('terminal').innerHTML = '<div class="scan-progress-overlay active" id="scanOverlay"></div>';
  $('scanBtn').classList.add('scanning');
  $('scanBtnText').textContent = 'Stop Scan';
  $('scanBtnIcon').textContent = '⏹';
  $('scanBtn').onclick = stopScan;
  $('reportBtn').disabled = true;
  $('reportBtnBottom').disabled = true;
  $('aiValidateBtn').disabled = true;
  $('scanTargetLabel').textContent = target;
  $('scanStatusBadge').className = 'scan-status-badge badge-running';
  $('scanStatusBadge').textContent = 'SCANNING';
  $('progressFill').style.width = '0%';
  $('aiValidationCard').style.display = 'none';

  // Cricket ball
  startBallAnimation();
  startTimer();

  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({target, modules})
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Scan failed to start');
    state.scanId = data.scan_id;
    listenSSE(state.scanId);
  } catch(err) {
    termLog(`Error: ${err.message}`, 'error');
    resetScanUI('error');
  }
}

let _evtSource = null;

function listenSSE(scanId) {
  if (_evtSource) _evtSource.close();
  _evtSource = new EventSource(`/stream/${scanId}`);

  _evtSource.onmessage = e => {
    const msg = JSON.parse(e.data);
    handleSSE(msg);
    if (msg.type === 'complete' || msg.type === 'error') {
      _evtSource.close();
    }
  };

  _evtSource.onerror = () => {
    _evtSource.close();
    if (state.scanning) {
      termLog('Connection lost. Scan may still be running.', 'warning');
      resetScanUI('error');
    }
  };
}

function handleSSE(msg) {
  switch (msg.type) {
    case 'log':
      termLog(msg.message, msg.level || 'info');
      break;
    case 'finding':
      addFinding(msg);
      break;
    case 'section_start':
      termSection(msg.name, msg.step, msg.total);
      break;
    case 'progress':
      $('progressFill').style.width = msg.value + '%';
      break;
    case 'score':
      updateGauge(msg.score, msg.label, msg.color);
      // Show accuracy
      if (msg.accuracy) showLocalAccuracy(msg.accuracy);
      break;
    case 'complete':
      onScanComplete(msg);
      break;
    case 'ai_validation':
      showAIValidation(msg);
      break;
    case 'error':
      termLog(msg.message || 'Scan error occurred', 'error');
      resetScanUI('error');
      break;
    case 'keepalive':
      break;
  }
}

function onScanComplete(msg) {
  stopTimer();
  stopBallAnimation();
  state.scanning = false;

  $('scanStatusBadge').className = 'scan-status-badge badge-done';
  $('scanStatusBadge').textContent = '✔ DONE';
  $('statStatus').textContent = 'Complete';
  $('progressFill').style.width = '100%';

  termLog(`✔ SCAN COMPLETE — Risk Score: ${msg.score}/100 (${msg.label}) — ${msg.findings} finding(s)`, 'success');

  $('scanBtn').classList.remove('scanning');
  $('scanBtnText').textContent = 'BOWL — Start Scan';
  $('scanBtnIcon').textContent = '🏏';
  $('scanBtn').onclick = startScan;
  $('reportBtn').disabled = false;
  $('reportBtnBottom').disabled = false;
  $('aiValidateBtn').disabled = false;

  // Show chat badge
  $('chatBadge').classList.add('show');

  // Load history
  loadHistory();
}

function stopScan() {
  if (_evtSource) _evtSource.close();
  resetScanUI('idle');
  termLog('Scan stopped by user.', 'warning');
}

function resetScanUI(status) {
  state.scanning = false;
  stopTimer();
  stopBallAnimation();
  $('scanBtn').classList.remove('scanning');
  $('scanBtnText').textContent = 'BOWL — Start Scan';
  $('scanBtnIcon').textContent = '🏏';
  $('scanBtn').onclick = startScan;
  $('scanStatusBadge').className = `scan-status-badge badge-${status === 'error' ? 'error' : 'idle'}`;
  $('scanStatusBadge').textContent = status === 'error' ? 'ERROR' : 'IDLE';
}

// ── AI Validation Display ──────────────────────────────────────────────────
function showLocalAccuracy(acc) {
  if (!acc.issues || !acc.issues.length) return;
  acc.issues.forEach(issue => {
    termLog(`⚠ AI Monitor: ${issue}`, 'warning');
  });
}

function showAIValidation(report) {
  const card = $('aiValidationCard');
  card.style.display = 'block';

  const verdict = report.accuracy_verdict || 'accurate';
  const conf    = report.confidence || 80;

  $('aiVerdict').className = `ai-val-verdict ${verdict}`;
  $('aiVerdict').innerHTML = `
    ${verdict === 'accurate' ? '✅' : verdict === 'underestimated' ? '⚠' : '📉'}
    ${verdict.charAt(0).toUpperCase()+verdict.slice(1)} — ${escHtml(report.accuracy_reason || '')}
  `;

  $('aiConfidencePct').textContent = conf + '%';
  $('aiConfidenceBar').style.width = conf + '%';

  // Gaps
  const gapsEl = $('aiGaps');
  gapsEl.innerHTML = '';
  if (report.gaps && report.gaps.length) {
    report.gaps.forEach(g => {
      const d = document.createElement('div');
      d.className = 'ai-gap-item';
      d.textContent = '⚠ ' + g;
      gapsEl.appendChild(d);
    });
  }

  // Priority fixes
  const fixEl = $('aiPriorityFixes');
  fixEl.innerHTML = '';
  if (report.priority_fixes && report.priority_fixes.length) {
    const title = document.createElement('div');
    title.style.cssText = 'font-size:.65rem;font-weight:700;color:var(--primary);margin:6px 0 4px;letter-spacing:.5px';
    title.textContent = '🔧 TOP PRIORITY FIXES';
    fixEl.appendChild(title);
    report.priority_fixes.forEach(fix => {
      const d = document.createElement('div');
      d.className = 'ai-priority-fix';
      d.innerHTML = `<strong>#${fix.rank} ${escHtml(fix.issue || '')}</strong>${escHtml(fix.fix || '')}`;
      fixEl.appendChild(d);
    });
  }

  if (report.source === 'gemini') {
    termLog(`🤖 AI Validation complete (Gemini) — Confidence: ${conf}% — Verdict: ${verdict}`, 'success');
  }
}

// ── AI Validate button ─────────────────────────────────────────────────────
async function runAiValidation() {
  if (!state.scanId) return;
  const key = state.geminiKey || prompt('Enter Gemini API key for AI validation (free at aistudio.google.com):') || '';
  if (!key) { alert('Gemini API key required for AI validation'); return; }
  state.geminiKey = key;

  $('aiValidateBtn').disabled = true;
  $('aiValidateBtn').textContent = '🤖 Validating...';

  try {
    const r = await fetch(`/api/ai-validate/${state.scanId}`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({apiKey: key})
    });
    const data = await r.json();
    showAIValidation(data);
  } catch(e) {
    alert('AI validation failed: ' + e.message);
  } finally {
    $('aiValidateBtn').disabled = false;
    $('aiValidateBtn').textContent = '🤖 AI Validate';
  }
}

// ── Report ─────────────────────────────────────────────────────────────────
function openReport() {
  if (state.scanId) window.open(`/report/${state.scanId}`, '_blank');
}

// ── History ────────────────────────────────────────────────────────────────
async function loadHistory() {
  const container = $('historyList');
  try {
    const r = await fetch('/api/history');
    const data = await r.json();
    container.innerHTML = '';
    if (!data.length) {
      container.innerHTML = '<div class="history-empty">No scans yet</div>';
      return;
    }
    data.slice(0,20).forEach(scan => {
      const item = document.createElement('div');
      item.className = 'history-item';
      const score = scan.score ?? '—';
      const scoreColor = getScoreColor(scan.score);
      const date = (scan.created_at || '').slice(0,16).replace('T',' ');
      item.innerHTML = `
        <div class="history-target">${escHtml(scan.target)}</div>
        <div class="history-meta">
          <span class="history-score" style="background:${scoreColor}22;color:${scoreColor}">${score}/100</span>
          <span class="history-date">${date}</span>
          <span class="history-date">${scan.status || ''}</span>
        </div>`;
      item.onclick = () => loadScanFromHistory(scan.id);
      container.appendChild(item);
    });
  } catch(e) {
    container.innerHTML = '<div class="history-empty">Failed to load history</div>';
  }
}

async function loadScanFromHistory(scanId) {
  try {
    const r = await fetch(`/api/scan/${scanId}`);
    const scan = await r.json();
    state.scanId   = scanId;
    state.target   = scan.target;
    state.findings = scan.findings || [];
    $('terminal').innerHTML = '';
    $('scanTargetLabel').textContent = scan.target;
    $('scanStatusBadge').className = 'scan-status-badge badge-done';
    $('scanStatusBadge').textContent = '✔ DONE';
    $('reportBtn').disabled = false;
    $('reportBtnBottom').disabled = false;
    $('aiValidateBtn').disabled = false;
    _counts = {critical:0,high:0,medium:0,low:0,info:0};
    state.findings.forEach(f => {
      const s = (f.severity||'info').toLowerCase();
      if (s in _counts) _counts[s]++;
    });
    updateBars();
    updateGauge(scan.score||0, scan.status||'done', getScoreColor(scan.score));
    termLog(`Loaded historical scan for ${scan.target} — ${state.findings.length} findings`, 'success');
    switchTab('scan');
  } catch(e) {
    alert('Failed to load scan: ' + e.message);
  }
}

function getScoreColor(score) {
  if (!score && score !== 0) return '#94A3B8';
  if (score >= 85) return '#059669';
  if (score >= 65) return '#10B981';
  if (score >= 45) return '#F59E0B';
  if (score >= 25) return '#F97316';
  return '#EF4444';
}

// ── Settings ───────────────────────────────────────────────────────────────
function openSettings() {
  $('settGroqKey').value   = state.groqKey   || '';
  $('settGeminiKey').value = state.geminiKey || '';
  $('settAbuseKey').value  = state.abuseKey  || '';
  $('settVtKey').value     = '';
  $('settingsModal').classList.add('open');
}

function closeSettings() {
  $('settingsModal').classList.remove('open');
}

async function saveSettings() {
  const groqKey  = $('settGroqKey').value.trim();
  const gemKey   = $('settGeminiKey').value.trim();
  const abuseKey = $('settAbuseKey').value.trim();
  const vtKey    = $('settVtKey').value.trim();

  state.groqKey   = groqKey;
  state.geminiKey = gemKey;
  state.abuseKey  = abuseKey;
  localStorage.setItem('vc_groq_key',    groqKey);
  localStorage.setItem('vc_gemini_key',  gemKey);
  localStorage.setItem('vc_abuse_key',   abuseKey);

  try {
    const resp = await fetch('/api/set-keys', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({groqKey, geminiKey: gemKey, abuseipdbKey: abuseKey, vtKey})
    });
    const data = await resp.json();
    const aiMode = data.ai_mode || (groqKey ? 'groq' : gemKey ? 'gemini' : 'offline');
    const modeLabels = {groq: '🚀 Groq AI (Llama 3) active', gemini: '🤖 Gemini AI active', offline: '📚 Offline mode'};
    $('chatHeaderSub').textContent = modeLabels[aiMode] || modeLabels.offline;
  } catch(e) {
    const aiMode = groqKey ? 'groq' : gemKey ? 'gemini' : 'offline';
    const modeLabels = {groq: '🚀 Groq AI (Llama 3) active', gemini: '🤖 Gemini AI active', offline: '📚 Offline mode'};
    $('chatHeaderSub').textContent = modeLabels[aiMode];
  }

  closeSettings();
  const active = groqKey ? 'Groq AI (Llama 3 70B)' : gemKey ? 'Gemini AI' : 'Offline Knowledge Base';
  alert(`✅ Settings saved!\nAI Mode: ${active}`);
}

// Close modal on overlay click
$('settingsModal').addEventListener('click', e => {
  if (e.target === $('settingsModal')) closeSettings();
});

// ── AI Chat ────────────────────────────────────────────────────────────────
function toggleChat() {
  state.chatOpen = !state.chatOpen;
  $('chatDrawer').classList.toggle('open', state.chatOpen);
  if (state.chatOpen) {
    $('chatBadge').classList.remove('show');
    $('chatInput').focus();
    // Update header based on key
    if (state.geminiKey) {
      $('chatHeaderSub').textContent = '🤖 Gemini AI mode active';
    }
  }
}

function sendQuick(msg) {
  $('chatInput').value = msg;
  sendChat();
}

async function sendChat() {
  const input = $('chatInput');
  const msg   = input.value.trim();
  if (!msg) return;

  input.value = '';
  $('chatSendBtn').disabled = true;

  addChatMsg(msg, 'user', null);

  // Typing indicator
  const typingEl = document.createElement('div');
  typingEl.className = 'chat-typing';
  typingEl.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
  $('chatMessages').appendChild(typingEl);
  $('chatMessages').scrollTop = $('chatMessages').scrollHeight;

  try {
    // Use Groq key first, then Gemini
    const activeKey = state.groqKey || state.geminiKey || '';

    const scanContext = state.scanId ? {
      target:   state.target,
      score:    state.score,
      findings: state.findings.slice(0, 15),
      modules:  state.modules,
    } : null;

    const r = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        message:  msg,
        apiKey:   activeKey,
        scanId:   state.scanId,
        context:  scanContext,
      })
    });
    const data = await r.json();
    typingEl.remove();
    addChatMsg(data.response || 'No response', 'ai', data.source);

    // Update header based on source
    const labels = {groq: '🚀 Groq AI (Llama 3) active', gemini: '🤖 Gemini AI active', offline: '📚 Offline KB', fallback: '📚 Fallback KB', error: '⚠ Check API key'};
    if (data.source && labels[data.source]) {
      $('chatHeaderSub').textContent = labels[data.source];
    }
  } catch(e) {
    typingEl.remove();
    addChatMsg('⚠ Could not reach server. Check your connection.', 'ai', 'error');
  } finally {
    $('chatSendBtn').disabled = false;
    input.focus();
  }
}

function addChatMsg(text, role, source) {
  const div = document.createElement('div');
  div.className = 'chat-msg ' + role;

  if (role === 'ai') {
    // Render markdown: bold, code, headers, bullets, line breaks
    const rendered = text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/^#{1,3} (.+)$/gm, '<strong>$1</strong>')
      .replace(/^[-*] (.+)$/gm, '&bull; $1')
      .replace(/\n/g, '<br>');
    div.innerHTML = rendered;

    // Source badge
    if (source) {
      const badge = document.createElement('span');
      badge.className = 'msg-source-badge';
      if (source === 'gemini') {
        badge.className += ' src-gemini';
        badge.textContent = '🤖 Gemini AI';
      } else if (source === 'offline') {
        badge.className += ' src-offline';
        badge.textContent = '📚 Offline KB — set ⚙ Gemini key for AI';
      } else if (source === 'fallback') {
        badge.className += ' src-fallback';
        badge.textContent = '📚 Fallback (rate limited)';
      } else if (source === 'error') {
        badge.className += ' src-error';
        badge.textContent = '⚠ Error — check API key in ⚙';
      }
      div.appendChild(document.createElement('br'));
      div.appendChild(badge);
    }
  } else {
    div.textContent = text;
  }

  const msgs = $('chatMessages');
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  return div;
}

// ── Email Analysis ─────────────────────────────────────────────────────────
async function analyzeEmail() {
  const raw = $('emailInput').value.trim();
  if (!raw) { alert('Paste raw email content first'); return; }

  $('analyzeEmailBtn').disabled = true;
  $('analyzeEmailBtn').textContent = '⏳ Analyzing...';
  switchTab('scan');
  switchTermTab('email');

  const panel = $('emailResultPanel');
  panel.innerHTML = '<div style="text-align:center;padding:30px;color:var(--text-3)"><div style="font-size:2rem">📧</div><p>Analyzing email...</p></div>';
  panel.classList.add('active');
  panel.style.display = 'block';

  try {
    const r = await fetch('/api/analyze-email', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        rawEmail: raw,
        abuseipdbKey: $('emailAbuseKey').value.trim() || state.abuseKey,
      })
    });
    const data = await r.json();
    renderEmailResult(data);
  } catch(e) {
    panel.innerHTML = `<div style="color:var(--danger);padding:16px">Error: ${escHtml(e.message)}</div>`;
  } finally {
    $('analyzeEmailBtn').disabled = false;
    $('analyzeEmailBtn').textContent = '📧 Analyze for Phishing';
  }
}

function renderEmailResult(data) {
  const panel = $('emailResultPanel');
  const verdictClass = (data.verdict||'').toLowerCase().replace(/\s+/g,'_');
  const verdictIcons = {safe:'✅',suspicious:'⚠️',likely_phishing:'🚨',confirmed_phishing:'🚨'};
  const score = data.phishing_score || 0;

  let html = `
  <div class="email-verdict-card ${verdictClass}">
    <div class="verdict-icon">${verdictIcons[verdictClass]||'📧'}</div>
    <div class="verdict-title">${escHtml(data.verdict||'Unknown')}</div>
    <div class="verdict-score">Phishing Risk Score: <strong>${score}/100</strong></div>
  </div>`;

  // Headers
  const headers = data.headers || {};
  if (Object.keys(headers).length) {
    html += `<div class="email-detail-section"><div class="email-detail-title">Email Headers</div>`;
    ['from','to','subject','date','reply_to','return_path'].forEach(k => {
      if (headers[k]) html += `<div class="email-header-row"><span class="email-header-key">${k.replace('_','-')}</span><span class="email-header-val">${escHtml(headers[k])}</span></div>`;
    });
    html += '</div>';
  }

  // Auth
  const auth = data.authentication || {};
  html += `<div class="email-detail-section"><div class="email-detail-title">Email Authentication</div>`;
  ['spf','dkim','dmarc'].forEach(k => {
    const v = auth[k] || 'unknown';
    const cls = v === 'pass' ? 'auth-pass' : v === 'fail' ? 'auth-fail' : 'auth-unknown';
    html += `<span class="auth-badge ${cls}">${k.toUpperCase()}: ${v.toUpperCase()}</span>`;
  });
  html += '</div>';

  // Findings
  const findings = data.findings_list || data.findings || [];
  if (findings.length) {
    html += `<div class="email-detail-section"><div class="email-detail-title">Findings (${findings.length})</div>`;
    findings.forEach(f => {
      html += `<div class="finding-chip ${(f.severity||'info').toLowerCase()}">
        <strong>${escHtml((f.severity||'info').toUpperCase())}</strong>
        <span>${escHtml(f.description||'')}</span>
      </div>`;
    });
    html += '</div>';
  }

  // URLs
  const urls = data.urls || [];
  if (urls.length) {
    html += `<div class="email-detail-section"><div class="email-detail-title">URLs Found (${urls.length})</div><ul class="url-list">`;
    urls.forEach(u => {
      const verdict = (u.verdict||'unknown').toLowerCase();
      html += `<li><div class="url-verdict-dot ${verdict}"></div><span>${escHtml(u.url||'')}</span><strong style="font-size:.7rem;color:${verdict==='clean'?'var(--success)':verdict==='malicious'?'var(--danger)':'var(--warning)'}">&nbsp;${verdict}</strong></li>`;
    });
    html += '</ul></div>';
  }

  panel.innerHTML = html;
  panel.classList.add('active');
  panel.style.display = 'block';
}

// ── Target dot validation ──────────────────────────────────────────────────
let _dotTimer = null;
$('targetInput').addEventListener('input', () => {
  clearTimeout(_dotTimer);
  const dot = $('targetDot');
  dot.className = 'target-status-dot';
  const val = $('targetInput').value.trim();
  if (!val) return;
  _dotTimer = setTimeout(() => {
    // Simple regex validation
    const valid = /^[a-zA-Z0-9][a-zA-Z0-9.\-_]+$/.test(val) || /^\d{1,3}(\.\d{1,3}){3}$/.test(val);
    dot.className = 'target-status-dot ' + (valid ? 'active' : 'error');
  }, 500);
});

// ── Init ───────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  loadHistory();

  // Restore Gemini key indicator
  if (state.geminiKey) {
    $('chatHeaderSub').textContent = '🤖 Gemini AI mode active';
    $('chatBadge').classList.add('show');
  }

  // Show a welcome badge on the chat
  setTimeout(() => $('chatBadge').classList.add('show'), 3000);
});
