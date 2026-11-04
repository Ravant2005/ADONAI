/* ADONAI Mac Dashboard Controller & 3D 1,000-Endpoint Cyber Range Visualizer */
let currentEnvFilter = '';
let rangeEndpoints = [];
let rangeScenarios = [];
let selectedEndpointId = 'sim-ep-0001';
let activeBeam = null; // { targetId, expiresAt }
let rotY = 0.45;
let rotX = 0.38;
let isDragging = false;
let lastMouseX = 0, lastMouseY = 0;
let projectedNodes = [];

const VIEW_TITLES = {
  'view-overview': '01 / SYSTEM OVERVIEW & EXPOSURE SUMMARY',
  'view-range': '02 / 3D CYBER RANGE (1,000 REGISTERED SIMULATED IDENTITIES)',
  'view-devices': '03 / ENDPOINT REGISTRY, PAIRING & ANDROID APP INVENTORY',
  'view-events': '04 / LIVE SECURITY EVENT TIMELINE (REAL vs LAB)',
  'view-intel': '05 / THREAT INTELLIGENCE & ISOLATED TEST FIXTURES',
  'view-rules': '06 / 10-LAYER DETERMINISTIC RULES & MITRE ATT&CK EXPLORER',
  'view-incidents': '07 / EVIDENCE-LINKED INCIDENTS & 5-QUESTION GUIDANCE',
  'view-scenarios': '08 / SAFE LAB SCENARIO CATALOGUE & DETERMINISTIC REPLAY',
  'view-eval': '09 / MEASURED GROUND-TRUTH EVALUATION BENCHMARK',
  'view-llm': '10 / LOCAL LLM ANALYST & DETERMINISTIC FALLBACK',
  'view-sources': '11 / THREAT DATA SOURCES, PROVENANCE & FRESHNESS',
  'view-privacy': '12 / PRIVACY CONSENT CENTER, RETENTION & AUDIT LOG',
  'view-guardian': '13 / 🛡️ GUARDIAN MEDIA VAULT — AI FRAUD DETECTION'
};

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
    item.classList.add('active');
    const target = item.getAttribute('data-view');
    document.getElementById(target).classList.add('active');
    document.getElementById('currentViewTitle').textContent = VIEW_TITLES[target] || 'ADONAI';
  });
});

function setEnvFilter(env) {
  currentEnvFilter = env;
  document.getElementById('filterAllBtn').className = env === '' ? 'btn btn-primary' : 'btn';
  document.getElementById('filterRealBtn').className = env === 'REAL' ? 'btn btn-primary' : 'btn';
  document.getElementById('filterLabBtn').className = env === 'LAB' ? 'btn btn-primary' : 'btn';
  refreshAll();
}

function badgeEnv(env) {
  return env === 'REAL'
    ? '<span class="badge badge-real">REAL DEVICE</span>'
    : '<span class="badge badge-lab">DEMO / LAB</span>';
}

function badgeEvidence(ev) {
  const cls = ev === 'CONFIRMED' ? 'badge-confirmed' : (ev === 'INFERRED' ? 'badge-inferred' : 'badge-observed');
  return `<span class="badge ${cls}">${ev}</span>`;
}

function badgeSeverity(sev) {
  const s = (sev || 'LOW').toUpperCase();
  const cls = s === 'CRITICAL' ? 'badge-critical' : (s === 'HIGH' ? 'badge-high' : (s === 'MEDIUM' ? 'badge-medium' : 'badge-low'));
  return `<span class="badge ${cls}">${s}</span>`;
}

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'API request failed');
  }
  return res.json();
}

async function loadOverview() {
  const q = currentEnvFilter ? `?environment=${currentEnvFilter}` : '';
  const data = await fetchJson(`/api/overview${q}`);
  const m = data.metrics;
  const ev = data.latest_evaluation;
  const kpiHtml = `
    <div class="card">
      <div class="kpi-label">Stored Security Events (${data.filter_environment})</div>
      <div class="kpi-value">${m.total_events}</div>
      <div class="kpi-sub">REAL: ${m.real_device_events} &bull; LAB: ${m.lab_simulation_events}</div>
    </div>
    <div class="card">
      <div class="kpi-label">Deterministic Detections</div>
      <div class="kpi-value">${m.total_detections}</div>
      <div class="kpi-sub">10 Active Detection Layers</div>
    </div>
    <div class="card card-elevated">
      <div class="kpi-label">Open Incidents</div>
      <div class="kpi-value" style="color:var(--alert);">${m.open_incidents}</div>
      <div class="kpi-sub">Evidence-linked with 5-Q guidance</div>
    </div>
    <div class="card">
      <div class="kpi-label">Registered Lab Identities</div>
      <div class="kpi-value">${m.registered_simulated_endpoints}</div>
      <div class="kpi-sub">Alerting Nodes: ${m.alerting_simulated_endpoints} (Simulated)</div>
    </div>
    <div class="card">
      <div class="kpi-label">Threat Intel Sources</div>
      <div class="kpi-value">${m.threat_sources_ingested} / ${m.threat_sources_total}</div>
      <div class="kpi-sub">Local bundles + live connectors</div>
    </div>
    <div class="card">
      <div class="kpi-label">Measured Benchmark F1</div>
      <div class="kpi-value">${ev ? (ev.f1_score * 100).toFixed(0) + '%' : 'Run Eval'}</div>
      <div class="kpi-sub">${ev ? `Prec ${(ev.precision_score*100).toFixed(0)}% / Rec ${(ev.recall_score*100).toFixed(0)}%` : 'Ground-truth harness ready'}</div>
    </div>
  `;
  document.getElementById('overviewKpis').innerHTML = kpiHtml;
}

async function loadIncidents() {
  const q = currentEnvFilter ? `?environment=${currentEnvFilter}` : '';
  const data = await fetchJson(`/api/incidents${q}`);
  const list = data.incidents || [];

  const shortHtml = list.slice(0, 4).map(inc => `
    <div style="padding:10px 0;border-bottom:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
        <strong>${inc.title}</strong>
        <div>${badgeEnv(inc.environment)} ${badgeEvidence(inc.evidence_class)} ${badgeSeverity(inc.severity)}</div>
      </div>
      <div style="font-size:12px;color:var(--muted);margin-top:4px;"><strong>WHAT:</strong> ${inc.what_observed}</div>
      <div style="font-size:12px;color:var(--muted);margin-top:2px;"><strong>NOW WHAT:</strong> ${inc.now_what_action}</div>
    </div>
  `).join('') || '<div style="color:var(--muted);">No incidents in current filter.</div>';
  document.getElementById('overviewIncidentsList').innerHTML = shortHtml;

  const fullHtml = list.map(inc => `
    <div class="card" style="background:var(--bg);margin-bottom:14px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;">
        <div>
          <span class="mono" style="color:var(--primary);">${inc.incident_id}</span> &bull;
          <strong style="font-size:15px;">${inc.title}</strong>
        </div>
        <div>
          ${badgeEnv(inc.environment)} ${badgeEvidence(inc.evidence_class)} ${badgeSeverity(inc.severity)}
          <span class="badge badge-observed">STATUS: ${inc.status}</span>
        </div>
      </div>
      <table class="data-table" style="margin-bottom:10px;">
        <tr><th style="width:170px;">1. WHAT WAS OBSERVED?</th><td>${inc.what_observed}</td></tr>
        <tr><th>2. WHERE IMPLICATED?</th><td class="mono">${inc.where_implicated}</td></tr>
        <tr><th>3. WHY IS IT RISKY?</th><td>${inc.why_risky} ${inc.attack_technique_id ? `<span class="badge badge-high">ATT&CK ${inc.attack_technique_id}</span>` : ''}</td></tr>
        <tr><th>4. EVIDENCE &amp; UNCERTAINTY</th><td>${badgeEvidence(inc.evidence_class)} ${inc.uncertainty_note}</td></tr>
        <tr><th>5. NOW WHAT? (SAFE ACTION)</th><td><strong>${inc.now_what_action}</strong></td></tr>
      </table>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="explainIncident('${inc.incident_id}')">Generate Local LLM / Deterministic Explanation</button>
        <button class="btn" onclick="markFeedback('${inc.incident_id}', 'CONFIRMED_THREAT')">Mark Confirmed Threat</button>
        <button class="btn" onclick="markFeedback('${inc.incident_id}', 'FALSE_POSITIVE')">Report False Positive</button>
      </div>
      <div id="exp-${inc.incident_id}" style="margin-top:10px;${inc.latest_explanation ? '' : 'display:none;'}" class="honesty-banner">
        ${inc.latest_explanation ? `<strong>[${inc.latest_explanation.generation_mode} | ${inc.latest_explanation.model_name}]</strong><br/>${inc.latest_explanation.summary_text}` : ''}
      </div>
    </div>
  `).join('') || '<div style="color:var(--muted);">No incidents recorded for selected filter.</div>';
  document.getElementById('incidentsFullList').innerHTML = fullHtml;
}

async function explainIncident(incId) {
  const box = document.getElementById(`exp-${incId}`);
  box.style.display = 'block';
  box.innerHTML = 'Generating schema-validated explanation...';
  const res = await fetchJson(`/api/incidents/${incId}/explain`, { method: 'POST' });
  box.innerHTML = `<strong>[${res.generation_mode} | ${res.model_name} | Schema Valid: ${res.schema_valid}]</strong><br/>${res.summary_text}`;
}

async function markFeedback(incId, disp) {
  await fetchJson('/api/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_type: 'INCIDENT', target_id: incId, disposition: disp })
  });
  await loadIncidents();
}

function fillPreset(kind) {
  if (kind === 'benign') {
    document.getElementById('quickUrl').value = 'https://cooking-recipes.example.org/sunday-dinner';
    document.getElementById('quickText').value = 'Here is the masala dosa recipe we talked about for Sunday dinner!';
    document.getElementById('quickSender').value = 'rec-mom-01';
  } else if (kind === 'otp') {
    document.getElementById('quickUrl').value = '';
    document.getElementById('quickText').value = 'URGENT BANK ALERT: Your account will be frozen in 10 minutes. Reply immediately with the 6-digit OTP verification code sent to your phone.';
    document.getElementById('quickSender').value = 'rec-unknown-03';
  } else if (kind === 'compromise') {
    document.getElementById('quickUrl').value = 'https://urgent-family-wire.example.test/otp-claim';
    document.getElementById('quickText').value = 'Hey I am stuck at the hospital and my card is locked, click https://urgent-family-wire.example.test/otp-claim and send me your 6-digit OTP code right now please!';
    document.getElementById('quickSender').value = 'rec-mom-01';
  }
}

async function submitQuickAnalyze() {
  const url = document.getElementById('quickUrl').value.trim() || null;
  const message_text = document.getElementById('quickText').value.trim();
  const sender = document.getElementById('quickSender').value;
  const outBox = document.getElementById('quickAnalyzeResult');
  outBox.style.display = 'block';
  outBox.textContent = 'Running deterministic 10-layer analysis...';
  const res = await fetchJson('/api/analyze/share', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: 'android-pixel8-real-01', environment: 'REAL', url, message_text, sender })
  });
  if (res.detections && res.detections.length > 0) {
    const d = res.detections[0];
    outBox.innerHTML = `<span class="badge badge-critical">ALERT TRIGGERED (${d.severity})</span> Rule: ${d.rule_id} v${d.rule_version}<br/><strong>Rationale:</strong> ${d.rationale}<br/><strong>Action:</strong> ${d.recommended_action}`;
  } else {
    outBox.innerHTML = `<span class="badge badge-observed">BENIGN / NO ALERT</span> Event ${res.event_id} recorded. Context-aware check passed with zero nuisance warning.`;
  }
  await refreshAll();
}

async function loadEvents() {
  const q = currentEnvFilter ? `?environment=${currentEnvFilter}` : '';
  const data = await fetchJson(`/api/events${q}`);
  const rows = (data.events || []).map(e => `
    <tr>
      <td class="mono">${e.event_id}</td>
      <td>${badgeEnv(e.environment)}</td>
      <td>${badgeEvidence(e.evidence_class)}</td>
      <td class="mono">${e.device_id}</td>
      <td><strong>${e.event_type}</strong><div class="mono" style="color:var(--muted);">${e.app_context}</div></td>
      <td class="mono">${e.destination}</td>
      <td>${e.summary}</td>
      <td class="mono" style="color:var(--muted);">${e.created_at.slice(11, 19)}Z</td>
    </tr>
  `).join('');
  document.getElementById('eventStreamTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Event ID</th><th>Env</th><th>Evidence</th><th>Device</th><th>Type / Context</th><th>Destination</th><th>Summary</th><th>Time</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

async function loadDevices() {
  const data = await fetchJson('/api/devices');
  document.getElementById('devicesTableContainer').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Device ID</th><th>Name</th><th>Platform</th><th>Status</th><th>Action</th></tr></thead>
      <tbody>
        ${data.devices.map(d => `
          <tr>
            <td class="mono">${d.device_id}</td>
            <td><strong>${d.name}</strong></td>
            <td>${d.platform} (${d.os_version})</td>
            <td><span class="badge ${d.status.includes('ONLINE') ? 'badge-confirmed' : 'badge-low'}">${d.status}</span></td>
            <td>${d.device_id.startsWith('android') ? `<button class="btn" onclick="revokeDevice('${d.device_id}')">Revoke Pairing</button>` : '<span class="mono">Host</span>'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('appInventoryContainer').innerHTML = `
    <table class="data-table">
      <thead><tr><th>App / Package</th><th>Installer</th><th>Granted Permissions</th><th>Risk</th><th>Rationale</th></tr></thead>
      <tbody>
        ${data.android_app_inventory.map(a => {
          const perms = JSON.parse(a.granted_permissions_json || '[]').map(p => p.replace('android.permission.', '')).join(', ');
          const badge = a.risk_score >= 0.7 ? 'badge-critical' : 'badge-low';
          return `
            <tr>
              <td><strong>${a.app_label}</strong><div class="mono" style="color:var(--muted);">${a.package_name} v${a.version_name}</div></td>
              <td class="mono">${a.installer_source}</td>
              <td class="mono" style="font-size:11px;">${perms}</td>
              <td><span class="badge ${badge}">${(a.risk_score*100).toFixed(0)}%</span></td>
              <td style="font-size:12px;color:var(--muted);">${a.risk_rationale}</td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

async function generatePairingCode() {
  const res = await fetchJson('/api/pairing/create', { method: 'POST' });
  const box = document.getElementById('pairingBox');
  box.style.display = 'block';
  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div>
        <div class="kpi-label">SHORT-LIVED 6-DIGIT PAIRING CODE (TTL 5 MIN)</div>
        <div style="font-size:26px;font-weight:800;letter-spacing:4px;color:var(--primary);font-family:var(--font-mono);margin:4px 0;">${res.pairing_code}</div>
        <div class="mono" style="color:var(--muted);font-size:11px;">QR Payload: ${res.qr_payload}</div>
      </div>
      <button class="btn btn-primary" onclick="simulatePhonePair('${res.pairing_code}')">Simulate Android Phone Pairing</button>
    </div>
  `;
}

async function simulatePhonePair(code) {
  await fetchJson('/api/pairing/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pairing_code: code, device_id: 'android-pixel8-real-01', device_name: 'Pixel 8 Pro (Paired Android Agent)' })
  });
  document.getElementById('pairingBox').innerHTML = '<span class="badge badge-confirmed">PAIRED &amp; AUTHENTICATED OVER LAN</span>';
  await loadDevices();
}

async function revokeDevice(deviceId) {
  await fetchJson(`/api/pairing/revoke/${deviceId}`, { method: 'POST' });
  await loadDevices();
}

async function loadThreatIntel() {
  const data = await fetchJson('/api/threat-intel');
  document.getElementById('prodIocsTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>IOC ID</th><th>Type</th><th>Indicator Value</th><th>Source</th><th>Severity</th><th>ATT&amp;CK</th></tr></thead>
      <tbody>
        ${data.production_iocs.map(i => `
          <tr>
            <td class="mono">${i.ioc_id}</td>
            <td class="mono">${i.indicator_type}</td>
            <td class="mono" style="word-break:break-all;">${i.value}</td>
            <td class="mono">${i.source_id}</td>
            <td>${badgeSeverity(i.severity)}</td>
            <td class="mono">${i.attack_technique_id || '-'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('testFixturesTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Fixture ID</th><th>Type</th><th>Reserved Safe Value</th><th>Scope</th><th>Technique</th></tr></thead>
      <tbody>
        ${data.test_fixtures.map(i => `
          <tr>
            <td class="mono">${i.ioc_id}</td>
            <td class="mono">${i.indicator_type}</td>
            <td class="mono" style="word-break:break-all;">${i.value}</td>
            <td><span class="badge badge-lab">${i.environment_scope}</span></td>
            <td class="mono">${i.attack_technique_id || '-'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('rulesTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Rule ID</th><th>Version</th><th>Layer / Type</th><th>Title &amp; Condition</th><th>Severity</th><th>ATT&amp;CK</th></tr></thead>
      <tbody>
        ${data.detection_rules.map(r => `
          <tr>
            <td class="mono">${r.rule_id}</td>
            <td class="mono">v${r.version}</td>
            <td><span class="badge badge-observed">${r.rule_type}</span></td>
            <td><strong>${r.title}</strong><div class="mono" style="color:var(--muted);font-size:11px;">Condition: ${r.condition_expr}</div></td>
            <td>${badgeSeverity(r.severity)}</td>
            <td class="mono">${r.attack_technique_id || '-'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('techniquesTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Technique ID</th><th>STIX ID</th><th>Name &amp; Tactic</th><th>D3FEND Countermeasure</th></tr></thead>
      <tbody>
        ${data.attack_techniques.map(t => `
          <tr>
            <td class="mono"><strong>${t.technique_id}</strong> (v${t.version})</td>
            <td class="mono" style="font-size:11px;color:var(--muted);">${t.stix_id}</td>
            <td><strong>${t.name}</strong> (${t.tactic})<div style="font-size:12px;color:var(--muted);">${t.description}</div></td>
            <td class="mono">${t.d3fend_countermeasure}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('sourcesHealthTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Source Name</th><th>Category</th><th>Version</th><th>Status</th><th>Records</th><th>License &amp; Rate-Limit Policy</th></tr></thead>
      <tbody>
        ${data.sources.map(s => `
          <tr>
            <td><strong>${s.name}</strong><div class="mono" style="color:var(--muted);font-size:11px;">${s.source_id}</div></td>
            <td class="mono">${s.category}</td>
            <td class="mono">${s.version}</td>
            <td><span class="badge ${s.status.startsWith('INGESTED') ? 'badge-confirmed' : 'badge-low'}">${s.status}</span></td>
            <td class="mono">${s.record_count}</td>
            <td style="font-size:12px;color:var(--muted);"><strong>${s.license}</strong> &bull; ${s.rate_limit_policy}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function loadCyberRange() {
  const data = await fetchJson('/api/cyber-range/state');
  rangeEndpoints = data.endpoints || [];
  rangeScenarios = data.scenarios || [];
  document.getElementById('rangeStateBadge').textContent = `STATE: ${data.controller_state.range_status} | NODES: ${data.total_simulated_endpoints}`;

  const sel = document.getElementById('rangeScenarioSelect');
  if (sel && sel.options.length === 0) {
    sel.innerHTML = rangeScenarios.map(s => `<option value="${s.scenario_id}">${s.name}</option>`).join('');
  }

  document.getElementById('scenariosCatalogueTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>ID / Code</th><th>Scenario Name &amp; Safety Notice</th><th>Expected</th><th>ATT&amp;CK</th><th>Actions</th></tr></thead>
      <tbody>
        ${rangeScenarios.map((s, idx) => {
          const ep1 = `sim-ep-${String(idx + 1).padStart(4, '0')}`;
          const ep2 = `sim-ep-${String(idx + 101).padStart(4, '0')}`;
          return `
            <tr>
              <td class="mono"><strong>${s.scenario_id}</strong><div style="color:var(--muted);font-size:11px;">${s.code}</div></td>
              <td><strong>${s.name}</strong><div style="font-size:12px;color:var(--muted);">${s.description}</div><div class="mono" style="color:var(--primary);font-size:11px;margin-top:2px;">${s.safety_notice}</div></td>
              <td>${s.expected_detection ? badgeSeverity(s.expected_severity) : '<span class="badge badge-observed">BENIGN (0 FP)</span>'}</td>
              <td class="mono">${s.attack_technique_id || 'N/A'}</td>
              <td>
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                  <button class="btn btn-primary" onclick="runScenarioById('${s.scenario_id}', '${ep1}', false)">Run on ${ep1}</button>
                  <button class="btn" onclick="runScenarioById('${s.scenario_id}', '${ep2}', true)">Replay on ${ep2}</button>
                </div>
              </td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

async function runScenarioById(scenId, epId, isReplay) {
  const res = await fetchJson('/api/cyber-range/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario_id: scenId, target_endpoint_id: epId, is_replay: isReplay })
  });
  activeBeam = { targetId: epId, expiresAt: Date.now() + 5500 };
  selectedEndpointId = epId;
  await refreshAll();
  await inspectEndpoint(epId);
}

async function triggerRangeScenario(isReplay) {
  const scenId = document.getElementById('rangeScenarioSelect').value;
  let epId = document.getElementById('rangeTargetEp').value.trim() || 'sim-ep-0001';
  if (isReplay) {
    const num = parseInt(epId.replace('sim-ep-', ''), 10) || 1;
    const nextNum = (num % 1000) + 1;
    epId = `sim-ep-${String(nextNum).padStart(4, '0')}`;
    document.getElementById('rangeTargetEp').value = epId;
  }
  await runScenarioById(scenId, epId, isReplay);
}

async function controlRange(action) {
  await fetchJson('/api/cyber-range/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action })
  });
  await refreshAll();
}

async function inspectEndpoint(epId) {
  selectedEndpointId = epId;
  const data = await fetchJson(`/api/cyber-range/endpoints/${epId}`);
  const ep = data.endpoint;
  const evs = data.events || [];
  const dets = data.detections || [];
  document.getElementById('nodeInspectorContent').innerHTML = `
    <div style="margin-bottom:10px;">
      <span class="badge badge-lab">${ep.entity_type}</span>
      <span class="badge ${ep.status === 'ALERT' ? 'badge-critical' : 'badge-observed'}">${ep.status}</span>
    </div>
    <table class="data-table" style="margin-bottom:12px;">
      <tr><th>Endpoint ID</th><td class="mono">${ep.endpoint_id}</td></tr>
      <tr><th>Label</th><td>${ep.label} (Simulated Identity)</td></tr>
      <tr><th>Sector / Ring</th><td class="mono">${ep.sector}</td></tr>
      <tr><th>Virtual IP</th><td class="mono">${ep.virtual_ip}</td></tr>
      <tr><th>OS Profile</th><td class="mono">${ep.os_profile}</td></tr>
    </table>
    <div style="font-weight:700;margin-bottom:6px;">Detections (${dets.length}):</div>
    ${dets.map(d => `
      <div style="padding:8px;background:var(--bg);border:1px solid var(--primary);margin-bottom:6px;font-size:12px;">
        <div><strong>${d.rule_id} (v${d.rule_version})</strong> ${badgeSeverity(d.severity)}</div>
        <div style="color:var(--muted);margin-top:3px;">${d.rationale}</div>
      </div>
    `).join('') || '<div style="font-size:12px;color:var(--muted);margin-bottom:8px;">No detections on this node.</div>'}
    <div style="font-weight:700;margin:8px 0 6px 0;">Recent Events (${evs.length}):</div>
    ${evs.map(e => `
      <div style="padding:6px;background:var(--bg);border:1px solid var(--border);margin-bottom:4px;font-size:11px;" class="mono">
        ${e.event_type} (${e.evidence_class}) &bull; ${e.created_at.slice(11, 19)}Z
      </div>
    `).join('') || '<div style="font-size:12px;color:var(--muted);">No lab events emitted for this node yet.</div>'}
  `;
}

async function runFullEvaluation() {
  document.getElementById('evalMetricsSummary').innerHTML = '<div class="mono">Executing 10 ground-truth scenarios across isolated simulated endpoints...</div>';
  const res = await fetchJson('/api/cyber-range/evaluate', { method: 'POST' });
  renderEvaluationResult(res);
  await refreshAll();
}

function renderEvaluationResult(res) {
  if (!res) return;
  const per = res.per_scenario || JSON.parse(res.details_json || '[]');
  const prec = res.precision !== undefined ? res.precision : res.precision_score;
  const rec = res.recall !== undefined ? res.recall : res.recall_score;
  const f1 = res.f1_score;
  const fpr = res.false_positive_rate;
  const ttd = res.mean_ttd_ms;
  const cont = res.containment_rate;

  document.getElementById('evalMetricsSummary').innerHTML = `
    <div class="kpi-grid">
      <div class="card card-elevated"><div class="kpi-label">Precision</div><div class="kpi-value">${(prec*100).toFixed(1)}%</div><div class="kpi-sub">TP: ${res.true_positives} | FP: ${res.false_positives}</div></div>
      <div class="card card-elevated"><div class="kpi-label">Recall</div><div class="kpi-value">${(rec*100).toFixed(1)}%</div><div class="kpi-sub">FN: ${res.false_negatives} | TN: ${res.true_negatives}</div></div>
      <div class="card"><div class="kpi-label">F1 Score</div><div class="kpi-value">${(f1*100).toFixed(1)}%</div><div class="kpi-sub">10 Labeled Ground-Truth Scenarios</div></div>
      <div class="card"><div class="kpi-label">False-Positive Rate</div><div class="kpi-value">${(fpr*100).toFixed(1)}%</div><div class="kpi-sub">Benign Family Control Verified</div></div>
      <div class="card"><div class="kpi-label">Mean Detection Latency</div><div class="kpi-value">${ttd} ms</div><div class="kpi-sub">Deterministic Engine</div></div>
      <div class="card"><div class="kpi-label">Containment Rate</div><div class="kpi-value">${(cont*100).toFixed(1)}%</div><div class="kpi-sub">Supported Lab Controls</div></div>
    </div>
    <div class="honesty-banner"><strong>Test Conditions:</strong> ${res.test_conditions}</div>
  `;

  document.getElementById('evalPerScenarioTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Scenario</th><th>Endpoint</th><th>Ground Truth</th><th>Detected</th><th>Outcome</th><th>Latency (ms)</th></tr></thead>
      <tbody>
        ${per.map(p => `
          <tr>
            <td><strong>${p.name}</strong><div class="mono" style="color:var(--muted);">${p.code}</div></td>
            <td class="mono">${p.target_endpoint_id}</td>
            <td>${p.ground_truth_malicious ? '<span class="badge badge-high">MALICIOUS / RISKY</span>' : '<span class="badge badge-observed">BENIGN CONTROL</span>'}</td>
            <td class="mono">${p.detected ? 'YES' : 'NO'}</td>
            <td><span class="badge badge-confirmed">${p.outcome}</span></td>
            <td class="mono">${p.time_to_detect_ms} ms</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function loadLlmAndPrivacy() {
  const ov = await fetchJson('/api/overview');
  const llm = ov.llm_status;
  document.getElementById('llmStatusBox').innerHTML = `
    <table class="data-table">
      <tr><th>Configured Endpoint</th><td class="mono">${llm.configured_endpoint}</td></tr>
      <tr><th>Configured Model</th><td class="mono">${llm.configured_model}</td></tr>
      <tr><th>Local Server Reachable</th><td><span class="badge ${llm.llm_online ? 'badge-confirmed' : 'badge-observed'}">${llm.llm_online ? 'ONLINE' : 'OFFLINE (FALLBACK ACTIVE)'}</span></td></tr>
      <tr><th>Active Explanation Mode</th><td><span class="badge badge-high">${llm.active_mode}</span></td></tr>
      <tr><th>Security Policy</th><td style="font-size:12px;color:var(--muted);">${llm.policy}</td></tr>
    </table>
  `;
  if (ov.latest_evaluation && !document.getElementById('evalMetricsSummary').innerHTML.trim()) {
    renderEvaluationResult(ov.latest_evaluation);
  }

  const priv = await fetchJson('/api/privacy-audit');
  document.getElementById('consentControlsList').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Feature</th><th>Scope &amp; Boundaries</th><th>Status</th><th>Toggle</th></tr></thead>
      <tbody>
        ${priv.consents.map(c => `
          <tr>
            <td><strong>${c.feature_name}</strong><div class="mono" style="color:var(--muted);font-size:11px;">${c.feature_key}</div></td>
            <td style="font-size:12px;color:var(--muted);">${c.scope_description}</td>
            <td><span class="badge ${c.granted ? 'badge-confirmed' : 'badge-low'}">${c.granted ? 'OPTED IN' : 'REVOKED'}</span></td>
            <td><button class="btn" onclick="toggleConsent('${c.feature_key}', ${!c.granted})">${c.granted ? 'Revoke' : 'Grant'}</button></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('trustedContactsTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Contact</th><th>Channel</th><th>Trust Level</th><th>Override Policy</th></tr></thead>
      <tbody>
        ${priv.trusted_contacts.map(tc => `
          <tr>
            <td><strong>${tc.display_name}</strong><div class="mono" style="color:var(--muted);">${tc.identifier}</div></td>
            <td>${tc.channel_type}</td>
            <td><span class="badge ${tc.trust_level === 'TRUSTED' ? 'badge-confirmed' : 'badge-low'}">${tc.trust_level}</span></td>
            <td class="mono" style="font-size:11px;">${tc.override_policy}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('auditLogsTable').innerHTML = `
    <table class="data-table">
      <thead><tr><th>Audit ID</th><th>Actor</th><th>Action</th><th>Resource</th><th>Env</th><th>Status</th><th>Timestamp</th></tr></thead>
      <tbody>
        ${priv.audit_logs.slice(0, 20).map(a => `
          <tr>
            <td class="mono">${a.audit_id}</td>
            <td class="mono">${a.actor}</td>
            <td><strong>${a.action}</strong></td>
            <td class="mono">${a.resource_type}:${a.resource_id}</td>
            <td>${badgeEnv(a.environment)}</td>
            <td><span class="badge badge-observed">${a.status}</span></td>
            <td class="mono" style="color:var(--muted);">${a.created_at.slice(0, 19)}Z</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function toggleConsent(featureKey, granted) {
  await fetchJson('/api/privacy/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: 'android-pixel8-real-01', feature_key: featureKey, granted })
  });
  await loadLlmAndPrivacy();
}

async function purgeData(env) {
  await fetchJson(`/api/privacy/purge-events?environment=${env}`, { method: 'DELETE' });
  await refreshAll();
}

/* 3D Cyber Range WebGL/Canvas Perspective Renderer for 1,000 Registered Identities */
function init3DRangeCanvas() {
  const canvas = document.getElementById('cyberRangeCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  canvas.addEventListener('mousedown', e => {
    isDragging = true;
    lastMouseX = e.clientX;
    lastMouseY = e.clientY;
  });
  window.addEventListener('mouseup', () => { isDragging = false; });
  window.addEventListener('mousemove', e => {
    if (!isDragging) return;
    const dx = e.clientX - lastMouseX;
    const dy = e.clientY - lastMouseY;
    rotY += dx * 0.006;
    rotX = Math.max(-1.1, Math.min(1.1, rotX + dy * 0.006));
    lastMouseX = e.clientX;
    lastMouseY = e.clientY;
  });

  canvas.addEventListener('click', e => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
    const my = (e.clientY - rect.top) * (canvas.height / rect.height);
    let best = null;
    let bestDist = 14;
    for (const n of projectedNodes) {
      const d = Math.hypot(n.sx - mx, n.sy - my);
      if (d < bestDist) {
        bestDist = d;
        best = n;
      }
    }
    if (best) {
      inspectEndpoint(best.endpoint_id);
    }
  });

  function renderFrame() {
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const cx = canvas.width / 2;
    const cy = canvas.height / 2 + 10;
    const fov = 520;
    const camDist = 115;

    rotY += 0.0012; // subtle orbital drift
    const cosY = Math.cos(rotY), sinY = Math.sin(rotY);
    const cosX = Math.cos(rotX), sinX = Math.sin(rotX);

    function project3D(x, y, z) {
      const x1 = x * cosY - z * sinY;
      const z1 = z * cosY + x * sinY;
      const y2 = y * cosX - z1 * sinX;
      const z2 = z1 * cosX + y * sinX + camDist;
      if (z2 <= 5) return null;
      const scale = fov / z2;
      return { sx: cx + x1 * scale, sy: cy + y2 * scale, scale, z2 };
    }

    // Draw 5 orbital sector rings
    for (let r = 1; r <= 5; r++) {
      const rad = 16.0 + r * 9.5;
      ctx.beginPath();
      for (let a = 0; a <= 64; a++) {
        const ang = (a / 64) * Math.PI * 2;
        const p = project3D(Math.cos(ang) * rad, 0, Math.sin(ang) * rad);
        if (p) {
          if (a === 0) ctx.moveTo(p.sx, p.sy);
          else ctx.lineTo(p.sx, p.sy);
        }
      }
      ctx.strokeStyle = 'rgba(229, 9, 20, 0.18)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Project all 1,000 registered SimulatedEndpoint records
    projectedNodes = [];
    for (const ep of rangeEndpoints) {
      const rad = ep.orbit_radius || 30;
      const ang = ep.orbit_angle || 0;
      const x = Math.cos(ang) * rad;
      const z = Math.sin(ang) * rad;
      const y = ep.orbit_height || 0;
      const p = project3D(x, y, z);
      if (p) {
        projectedNodes.push({
          endpoint_id: ep.endpoint_id,
          status: ep.status,
          sx: p.sx,
          sy: p.sy,
          z2: p.z2,
          scale: p.scale
        });
      }
    }

    projectedNodes.sort((a, b) => b.z2 - a.z2);

    // Draw central Mac Intelligence Core
    const coreP = project3D(0, 0, 0);
    if (coreP) {
      ctx.beginPath();
      ctx.arc(coreP.sx, coreP.sy, 11, 0, Math.PI * 2);
      ctx.fillStyle = '#E50914';
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = '#F5F5F5';
      ctx.stroke();
      ctx.fillStyle = '#F5F5F5';
      ctx.font = 'bold 10px monospace';
      ctx.fillText('ADONAI MAC CORE', coreP.sx - 44, coreP.sy - 16);
    }

    // Draw nodes
    for (const n of projectedNodes) {
      const isAlert = n.status === 'ALERT';
      const isSel = n.endpoint_id === selectedEndpointId;
      const r = isAlert ? Math.max(4.2, 320 / n.z2) : (isSel ? 4.0 : Math.max(1.7, 175 / n.z2));

      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
      if (isAlert) {
        ctx.fillStyle = '#FF3030';
      } else if (n.status === 'BENIGN_VERIFIED') {
        ctx.fillStyle = '#F5F5F5';
      } else {
        ctx.fillStyle = 'rgba(229, 9, 20, 0.58)';
      }
      ctx.fill();

      if (isSel || isAlert) {
        ctx.strokeStyle = isAlert ? '#FF3030' : '#F5F5F5';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Draw active scenario telemetry vector ONLY when an actual event was emitted
      if ((activeBeam && activeBeam.targetId === n.endpoint_id && Date.now() < activeBeam.expiresAt) || isAlert) {
        if (coreP) {
          ctx.beginPath();
          ctx.moveTo(coreP.sx, coreP.sy);
          ctx.lineTo(n.sx, n.sy);
          ctx.strokeStyle = isAlert ? 'rgba(255, 48, 48, 0.85)' : 'rgba(245, 245, 245, 0.6)';
          ctx.lineWidth = isAlert ? 2.0 : 1.2;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(renderFrame);
  }
  requestAnimationFrame(renderFrame);
}

async function refreshAll() {
  await Promise.all([
    loadOverview(),
    loadIncidents(),
    loadEvents(),
    loadDevices(),
    loadThreatIntel(),
    loadCyberRange(),
    loadLlmAndPrivacy()
  ]);
}

// ============================================================
// ADONAI GUARDIAN — Media Authenticity & Fraud Detection JS
// ============================================================

async function loadGuardianBlockchain() {
  const el = document.getElementById('guardianBlockchainState');
  const kpiEl = document.getElementById('guardianKpis');
  try {
    const r = await fetch('/api/guardian/blockchain');
    if (!r.ok) { el.innerHTML = '<p style="color:var(--muted);">Guardian modules loading…</p>'; return; }
    const data = await r.json();
    const integrity = data.chain_integrity || {};
    const recent = data.recent_registrations || [];

    // KPIs
    if (kpiEl) {
      kpiEl.innerHTML = `
        <div class="kpi-card"><div class="kpi-label">Chain Blocks</div><div class="kpi-value">${integrity.block_count || 0}</div></div>
        <div class="kpi-card"><div class="kpi-label">Chain Integrity</div><div class="kpi-value" style="color:${integrity.valid ? '#00ff88' : 'var(--primary)'}">${integrity.valid ? '✅ VALID' : '❌ BROKEN'}</div></div>
        <div class="kpi-card"><div class="kpi-label">Media Registered</div><div class="kpi-value">${recent.length}</div></div>
        <div class="kpi-card"><div class="kpi-label">Verification Engine</div><div class="kpi-value" style="color:#00ff88">3-STAGE ACTIVE</div></div>
      `;
    }

    // Recent registrations table
    if (!recent.length) {
      el.innerHTML = '<p style="color:var(--muted);font-size:12px;">No media registered yet. Use the ADONAI Guardian app to capture and register media.</p>';
      return;
    }
    el.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead><tr style="color:var(--muted);">
        <th style="text-align:left;padding:6px 8px;">Block</th>
        <th style="text-align:left;padding:6px 8px;">Type</th>
        <th style="text-align:left;padding:6px 8px;">Hash (short)</th>
        <th style="text-align:left;padding:6px 8px;">Device</th>
        <th style="text-align:left;padding:6px 8px;">Registered</th>
      </tr></thead>
      <tbody>${recent.map(b => `<tr style="border-top:1px solid var(--border);">
        <td style="padding:6px 8px;color:var(--primary);">#${b.block_index}</td>
        <td style="padding:6px 8px;">${b.media_type || '—'}</td>
        <td style="padding:6px 8px;font-family:monospace;color:#aaa;">${(b.media_hash || '').slice(0,16)}…</td>
        <td style="padding:6px 8px;color:var(--muted);">${(b.device_id || '').slice(0,20)}</td>
        <td style="padding:6px 8px;color:var(--muted);">${(b.block_timestamp || '').slice(0,19)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch(e) {
    el.innerHTML = `<p style="color:var(--muted);font-size:12px;">Guardian API not yet reachable: ${e.message}</p>`;
  }
}

async function loadGuardianVerdicts() {
  const el = document.getElementById('guardianVerdictsTable');
  if (!el) return;
  try {
    const r = await fetch('/api/guardian/verdicts?limit=20');
    if (!r.ok) { el.innerHTML = '<p style="color:var(--muted);">No verdicts yet.</p>'; return; }
    const data = await r.json();
    const verdicts = data.verdicts || [];
    if (!verdicts.length) {
      el.innerHTML = '<p style="color:var(--muted);font-size:12px;">No verifications run yet. Use the panel above or the Guardian Android app.</p>';
      return;
    }
    const verdictColor = v => {
      if (v === 'VERIFIED_AUTHENTIC') return '#00ff88';
      if (v === 'LIKELY_AUTHENTIC') return '#88ff88';
      if (v === 'UNCERTAIN') return '#ffcc00';
      if (v === 'LIKELY_AI_GENERATED') return '#ff8800';
      if (v === 'ALMOST_CERTAINLY_FAKE' || v === 'FRAUD_SCHEME_DETECTED') return 'var(--primary)';
      return 'var(--muted)';
    };
    el.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead><tr style="color:var(--muted);">
        <th style="text-align:left;padding:6px 8px;">Time</th>
        <th style="text-align:left;padding:6px 8px;">Type</th>
        <th style="text-align:left;padding:6px 8px;">Verdict</th>
        <th style="text-align:left;padding:6px 8px;">AI%</th>
        <th style="text-align:left;padding:6px 8px;">Fake%</th>
        <th style="text-align:left;padding:6px 8px;">Money Risk</th>
        <th style="text-align:left;padding:6px 8px;">Stage</th>
      </tr></thead>
      <tbody>${verdicts.map(v => `<tr style="border-top:1px solid var(--border);">
        <td style="padding:6px 8px;color:var(--muted);">${(v.created_at||'').slice(0,19)}</td>
        <td style="padding:6px 8px;">${v.media_type||'?'}</td>
        <td style="padding:6px 8px;font-weight:700;color:${verdictColor(v.overall_verdict)};">${v.overall_verdict||'—'}</td>
        <td style="padding:6px 8px;">${v.stage3_ai_probability != null ? Math.round(v.stage3_ai_probability*100)+'%' : '—'}</td>
        <td style="padding:6px 8px;">${v.stage3_fake_possibility != null ? Math.round(v.stage3_fake_possibility*100)+'%' : '—'}</td>
        <td style="padding:6px 8px;color:${v.money_risk_level==='HIGH'||v.money_risk_level==='CRITICAL'?'var(--primary)':'var(--muted)'};">${v.money_risk_level||'—'}</td>
        <td style="padding:6px 8px;color:var(--muted);">Stage ${v.stage_reached||0}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch(e) {
    el.innerHTML = `<p style="color:var(--muted);font-size:12px;">Could not load verdicts: ${e.message}</p>`;
  }
}

async function runGuardianVerify() {
  const mediaType = document.getElementById('guardianMediaType').value;
  const contextText = document.getElementById('guardianContextText').value.trim();
  const fileInput = document.getElementById('guardianFileInput');
  const resultEl = document.getElementById('guardianVerifyResult');

  resultEl.innerHTML = `<div style="color:var(--muted);font-size:12px;">⏳ Running ${mediaType === 'TEXT' ? 'text' : '3-stage Guardian'} verification…</div>`;

  try {
    let response;
    if (mediaType === 'TEXT') {
      // Text analysis
      response = await fetch('/api/guardian/analyze-text', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ text: contextText, context_text: contextText })
      });
    } else {
      // Media verification
      let contentB64 = null;
      if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const bytes = await file.arrayBuffer();
        const uint8 = new Uint8Array(bytes);
        let binary = '';
        for (let i = 0; i < uint8.length; i++) binary += String.fromCharCode(uint8[i]);
        contentB64 = btoa(binary);
      }
      response = await fetch('/api/guardian/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          media_type: mediaType,
          context_text: contextText,
          content_b64: contentB64,
          run_full_forensics: true
        })
      });
    }

    if (!response.ok) {
      const err = await response.json();
      resultEl.innerHTML = `<div style="color:var(--primary);font-size:12px;">⚠️ ${err.detail || 'Verification failed'}</div>`;
      return;
    }

    const data = await response.json();
    const verdict = data.overall_verdict || data.verdict || 'UNKNOWN';
    const verdictColor = {
      'VERIFIED_AUTHENTIC': '#00ff88', 'LIKELY_AUTHENTIC': '#88ff88',
      'UNCERTAIN': '#ffcc00', 'LIKELY_AI_GENERATED': '#ff8800',
      'ALMOST_CERTAINLY_FAKE': '#E50914', 'FRAUD_SCHEME_DETECTED': '#E50914'
    }[verdict] || 'var(--muted)';

    const aiPct = data.ai_probability_percent ?? (data.ai_probability != null ? Math.round(data.ai_probability*100) : '—');
    const fakePct = data.fake_possibility_percent ?? (data.fake_possibility != null ? Math.round(data.fake_possibility*100) : '—');
    const reasons = data.reasons || data.why_it_could_be_fake || [];
    const moneyRisk = data.money_risk_level || 'NONE';
    const moneyRiskColor = ['HIGH','CRITICAL'].includes(moneyRisk) ? 'var(--primary)' : moneyRisk === 'MEDIUM' ? '#ffcc00' : '#00ff88';

    const stagesHtml = data.stages ? Object.entries(data.stages).map(([k, s]) => `
      <div style="margin-top:10px;padding:10px;background:var(--surface);border-radius:4px;border-left:3px solid ${s.passed?'#00ff88':'var(--primary)'};">
        <div style="font-weight:700;font-size:11px;text-transform:uppercase;color:${s.passed?'#00ff88':'var(--primary)'};">
          ${s.passed ? '✅' : '❌'} ${s.name||k}
        </div>
        ${s.corroboration_found !== undefined ? `<div style="font-size:11px;color:var(--muted);margin-top:4px;">Corroboration: ${s.corroboration_found?'Found':'Not found'} | Scheme: ${s.scheme_detected?'⚠️ '+s.scheme_name:'None detected'}</div>` : ''}
        ${s.ai_probability !== undefined ? `<div style="font-size:11px;color:var(--muted);margin-top:4px;">AI Probability: ${Math.round(s.ai_probability*100)}% | Fake Possibility: ${Math.round(s.fake_possibility*100)}%</div>` : ''}
        ${s.watermark_valid !== undefined ? `<div style="font-size:11px;color:var(--muted);margin-top:4px;">Watermark: ${s.watermark_valid?'✅ Valid':'❌ Not found'} | Blockchain: ${s.details?.blockchain_found?'✅ Registered':'❌ Not registered'}</div>` : ''}
      </div>`).join('') : '';

    resultEl.innerHTML = `
      <div style="border:1px solid ${verdictColor};border-radius:6px;padding:16px;margin-top:8px;">
        <div style="font-size:18px;font-weight:900;color:${verdictColor};margin-bottom:12px;">
          ${data.verdict_badge || verdict}
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;">
          <div style="text-align:center;padding:10px;background:var(--surface);border-radius:4px;">
            <div style="font-size:22px;font-weight:900;color:${aiPct>=60?'var(--primary)':'#ffcc00'}">${aiPct}%</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;">AI Generated</div>
          </div>
          <div style="text-align:center;padding:10px;background:var(--surface);border-radius:4px;">
            <div style="font-size:22px;font-weight:900;color:${fakePct>=60?'var(--primary)':'#ffcc00'}">${fakePct}%</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;">Fake Possibility</div>
          </div>
          <div style="text-align:center;padding:10px;background:var(--surface);border-radius:4px;">
            <div style="font-size:18px;font-weight:900;color:${moneyRiskColor}">${moneyRisk}</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;">Money Risk</div>
          </div>
        </div>
        ${data.money_context ? `<div style="padding:8px;background:#1a0000;border:1px solid var(--primary);border-radius:4px;font-size:12px;color:#ff9999;margin-bottom:10px;">💰 ${data.money_context}</div>` : ''}
        ${data.explanation ? `<div style="font-size:12px;color:var(--muted);margin-bottom:10px;">${data.explanation}</div>` : ''}
        ${reasons.length ? `<div style="margin-top:10px;"><div style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:6px;">Why It Could Be Fake:</div>
          <ul style="margin:0;padding-left:16px;">${reasons.map(r=>`<li style="font-size:12px;color:#ccc;margin-bottom:3px;">${r}</li>`).join('')}</ul></div>` : ''}
        ${stagesHtml}
        ${data.scheme_detected ? `<div style="margin-top:10px;padding:10px;background:#1a0000;border:1px solid var(--primary);border-radius:4px;font-weight:700;color:var(--primary);">🚨 FRAUD SCHEME: ${data.scheme_name}</div>` : ''}
      </div>
    `;
    // Reload verdicts table after a successful verification
    setTimeout(loadGuardianVerdicts, 500);
  } catch(e) {
    resultEl.innerHTML = `<div style="color:var(--primary);font-size:12px;">Error: ${e.message}</div>`;
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  init3DRangeCanvas();
  await refreshAll();
  await inspectEndpoint('sim-ep-0001');
  // Load Guardian data in background
  loadGuardianBlockchain();
  loadGuardianVerdicts();
});
