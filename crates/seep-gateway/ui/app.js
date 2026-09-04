/* SeeP control UI.
 *
 * No framework, no build step. The gateway is often installed on a machine with
 * no outbound internet, so everything here has to work from the binary alone.
 *
 * One rule runs through this file: never use innerHTML with server data. Node
 * names, alert titles, and tool output all originate outside the gateway, and a
 * dashboard that renders them as markup is an XSS hole in a tool whose whole
 * point is being trustworthy.
 */

const state = {
  session: null,
  socket: null,
  reconnectDelay: 1000,
  view: 'chat',
  streaming: null,
};

/* ── DOM helpers ──────────────────────────────────────────────────────── */

const $ = (id) => document.getElementById(id);

/** Build an element. Text is always set as text, never parsed as HTML. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function relative(iso) {
  if (!iso) return '';
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (!isFinite(seconds)) return '';
  if (seconds < 60) return `${Math.max(seconds, 0)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

async function api(path, options) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

/* ── Connection ───────────────────────────────────────────────────────── */

function setConnection(status, text) {
  const dot = $('conn-dot');
  dot.className = `dot ${status}`;
  dot.title = text;
  $('conn-text').textContent = text;
}

function connect() {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  state.socket = socket;

  socket.onopen = () => {
    setConnection('live', 'connected');
    // Reset the backoff only on a connection that actually opened, so a
    // server that accepts and immediately closes still backs off.
    state.reconnectDelay = 1000;
    refreshAll();
  };

  socket.onclose = () => {
    setConnection('lost', `reconnecting in ${Math.round(state.reconnectDelay / 1000)}s`);
    setTimeout(connect, state.reconnectDelay);
    state.reconnectDelay = Math.min(state.reconnectDelay * 2, 30000);
  };

  socket.onerror = () => setConnection('lost', 'connection error');

  socket.onmessage = (raw) => {
    let payload;
    try { payload = JSON.parse(raw.data); } catch { return; }
    if (payload.type === 'hello') {
      state.session = payload.session;
    } else if (payload.type === 'event') {
      handleEvent(payload.envelope);
    } else if (payload.type === 'message') {
      handleMessage(payload);
    }
  };
}

/* ── Events ───────────────────────────────────────────────────────────── */

function handleEvent(envelope) {
  const e = envelope.event;

  switch (envelope.event) {
    case 'session_delta':
      appendDelta(envelope.text);
      break;
    case 'session_complete':
      finishDelta();
      break;
    case 'session_tool_call':
      addMessage('tool', `→ ${envelope.tool}`);
      break;
    case 'session_tool_result':
      addMessage('tool', `${envelope.ok ? '✓' : '✗'} ${envelope.tool} — ${envelope.preview || ''}`);
      break;
    case 'session_error':
      addMessage('error', envelope.error);
      break;
    case 'subscriber_lagged':
      // Say so rather than rendering a view with an invisible hole in it.
      addMessage('tool', `(missed ${envelope.dropped} events while disconnected — refreshing)`);
      refreshAll();
      break;
    case 'approval_requested':
    case 'approval_signed':
    case 'approval_resolved':
      loadApprovals();
      break;
    case 'incident_opened':
    case 'incident_updated':
    case 'incident_resolved':
      loadIncidents();
      break;
    case 'node_connected':
    case 'node_disconnected':
    case 'node_status_changed':
    case 'node_enrolled':
    case 'node_removed':
      loadFleet();
      break;
    case 'run_started':
    case 'run_finished':
      loadRuns();
      break;
    case 'audit_appended':
      if (state.view === 'audit') loadAudit();
      break;
    default:
      break;
  }
  void e;
}

function handleMessage(payload) {
  const message = payload.message || {};
  const parts = [];
  if (message.title) parts.push(message.title);
  if (message.text) parts.push(message.text);
  addMessage('agent', parts.join('\n\n'), message.code_block);
}

/* ── Chat ─────────────────────────────────────────────────────────────── */

function addMessage(kind, text, code) {
  if (!text && !code) return;
  const stream = $('stream');
  const node = el('div', `msg ${kind}`, text || '');
  if (code) node.appendChild(el('pre', null, code));
  stream.appendChild(node);
  stream.scrollTop = stream.scrollHeight;
  return node;
}

function appendDelta(text) {
  if (!state.streaming) {
    state.streaming = addMessage('agent', '');
  }
  state.streaming.textContent += text;
  const stream = $('stream');
  stream.scrollTop = stream.scrollHeight;
}

function finishDelta() {
  state.streaming = null;
}

function send(text) {
  if (!state.socket || state.socket.readyState !== WebSocket.OPEN) {
    addMessage('error', 'Not connected. Waiting to reconnect…');
    return;
  }
  addMessage('user', text);
  finishDelta();
  state.socket.send(JSON.stringify({ text, operator: 'web' }));
}

/* ── Approvals ────────────────────────────────────────────────────────── */

async function loadApprovals() {
  let pending = [];
  try { pending = await api('/api/v1/approvals'); } catch { return; }

  const container = $('approvals');
  clear(container);
  $('approvals-empty').hidden = pending.length > 0;

  const badge = $('approvals-count');
  badge.hidden = pending.length === 0;
  badge.textContent = pending.length;

  for (const request of pending) {
    const card = el('div', `card ${request.blast_radius === 'CRIT' || request.blast_radius === 'HIGH' ? 'danger' : 'warn'}`);

    const heading = el('h3');
    heading.appendChild(el('span', `pill ${request.blast_radius}`, request.blast_radius));
    heading.appendChild(document.createTextNode(' ' + request.summary));
    card.appendChild(heading);

    const meta = [
      `Target: ${request.target_description || 'unspecified'}`,
      `${request.target_nodes.length} node(s)`,
      `${request.required_signatures} signature(s) required`,
      `expires ${relative(request.expires_at).replace(' ago', ' from now')}`,
    ].join(' · ');
    card.appendChild(el('div', 'meta', meta));

    if (request.policy_reasons && request.policy_reasons.length) {
      card.appendChild(el('div', 'meta', 'Why: ' + request.policy_reasons.join('; ')));
    }
    card.appendChild(el('div', 'detail', request.detail));

    const actions = el('div', 'actions');
    let confirmation = null;

    if (request.require_typed_confirmation) {
      confirmation = el('input');
      confirmation.placeholder = `Type "${request.confirmation_phrase}" to approve`;
      actions.appendChild(confirmation);
    }

    const approve = el('button', 'primary', 'Approve');
    approve.onclick = () => decide(request.id, 'approve', confirmation ? confirmation.value : '');
    const deny = el('button', 'danger', 'Deny');
    deny.onclick = () => decide(request.id, 'deny', '');

    actions.appendChild(approve);
    actions.appendChild(deny);
    card.appendChild(actions);
    container.appendChild(card);
  }
}

async function decide(id, decision, confirmation) {
  try {
    await api(`/api/v1/approvals/${encodeURIComponent(id)}/decide`, {
      method: 'POST',
      body: JSON.stringify({ operator: 'web', decision, confirmation }),
    });
  } catch (e) {
    addMessage('error', `Could not record the decision: ${e.message}`);
  }
  loadApprovals();
}

/* ── Fleet ────────────────────────────────────────────────────────────── */

async function loadFleet() {
  let nodes = [];
  try { nodes = await api('/api/v1/nodes'); } catch { return; }

  const container = $('fleet');
  clear(container);
  $('fleet-empty').hidden = nodes.length > 0;

  for (const node of nodes) {
    const card = el('div', 'card node');

    const title = el('h4');
    title.appendChild(document.createTextNode(node.name + ' '));
    title.appendChild(el('span', `pill ${node.status}`, node.status));
    card.appendChild(title);
    card.appendChild(el('div', 'host', `${node.hostname} · ${node.env} · ${node.os}/${node.arch}`));

    const metrics = node.metrics;
    if (metrics) {
      const memoryPercent = metrics.memory_total_bytes
        ? (metrics.memory_used_bytes / metrics.memory_total_bytes) * 100 : 0;
      meter(card, 'CPU', metrics.cpu_percent);
      meter(card, 'Memory', memoryPercent,
        `${bytes(metrics.memory_used_bytes)} / ${bytes(metrics.memory_total_bytes)}`);
    }

    card.appendChild(el('div', 'meta',
      node.last_seen ? `seen ${relative(node.last_seen)}` : 'never connected'));
    container.appendChild(card);
  }
}

function meter(card, label, percent, detail) {
  const value = Math.max(0, Math.min(100, percent || 0));
  const row = el('div', 'metric-label');
  row.appendChild(el('span', null, label));
  row.appendChild(el('span', null, detail || `${value.toFixed(0)}%`));
  card.appendChild(row);

  const bar = el('div', value > 90 ? 'meter hot' : 'meter');
  const fill = el('span');
  fill.style.width = `${value}%`;
  bar.appendChild(fill);
  card.appendChild(bar);
}

/* ── Incidents ────────────────────────────────────────────────────────── */

async function loadIncidents() {
  let incidents = [];
  try { incidents = await api('/api/v1/incidents?limit=50'); } catch { return; }

  const container = $('incidents');
  clear(container);
  $('incidents-empty').hidden = incidents.length > 0;

  const open = incidents.filter((i) => i.status !== 'resolved' && i.status !== 'suppressed');
  const badge = $('incidents-count');
  badge.hidden = open.length === 0;
  badge.textContent = open.length;

  for (const incident of incidents) {
    const severe = incident.severity === 'S1' || incident.severity === 'S2';
    const card = el('div', `card ${incident.status === 'resolved' ? 'ok' : severe ? 'danger' : 'warn'}`);

    const heading = el('h3', null, `#${incident.number} ${incident.title}`);
    card.appendChild(heading);

    const meta = [
      incident.severity,
      incident.status,
      `opened ${relative(incident.opened_at)}`,
      incident.occurrence_count > 1 ? `${incident.occurrence_count} occurrences` : null,
    ].filter(Boolean).join(' · ');
    card.appendChild(el('div', 'meta', meta));

    if (incident.hypothesis) {
      card.appendChild(el('div', 'detail', incident.hypothesis));
    }

    if (incident.status !== 'resolved' && incident.status !== 'suppressed') {
      const actions = el('div', 'actions');
      const resolve = el('button', 'primary', 'Resolve');
      resolve.onclick = async () => {
        try {
          await api(`/api/v1/incidents/${encodeURIComponent(incident.id)}/resolve`, {
            method: 'POST', body: JSON.stringify({ operator: 'web' }),
          });
        } catch (e) { addMessage('error', e.message); }
        loadIncidents();
      };
      actions.appendChild(resolve);
      card.appendChild(actions);
    }
    container.appendChild(card);
  }
}

/* ── Runs ─────────────────────────────────────────────────────────────── */

async function loadRuns() {
  let runs = [];
  try { runs = await api('/api/v1/runs?limit=40'); } catch { return; }

  const container = $('runs');
  clear(container);
  $('runs-empty').hidden = runs.length > 0;

  for (const run of runs) {
    const good = run.status === 'succeeded';
    const card = el('div', `card ${good ? 'ok' : run.status === 'rejected' ? 'danger' : 'warn'}`);
    card.appendChild(el('h3', null, run.summary || run.status));
    card.appendChild(el('div', 'meta',
      `${run.id} · ${run.status} · ${run.results.length} step(s) · started ${relative(run.started_at)}`));

    const failures = run.results.filter((r) => r.status === 'failed' || r.status === 'refused');
    if (failures.length) {
      card.appendChild(el('div', 'detail',
        failures.map((f) => `step ${f.step_id}: ${f.error || f.output}`).join('\n')));
    }
    container.appendChild(card);
  }
}

/* ── Audit ────────────────────────────────────────────────────────────── */

async function loadAudit() {
  try {
    const report = await api('/api/v1/audit/verify');
    const status = $('chain-status');
    status.className = `chain ${report.intact ? 'intact' : 'broken'}`;
    clear(status);
    status.appendChild(el('strong', null, report.intact ? '✓ Chain intact' : '✗ Chain problems found'));
    status.appendChild(document.createTextNode(' — ' + report.verdict));
    if (!report.intact) {
      for (const problem of report.problems) {
        status.appendChild(el('div', 'meta', problem));
      }
    }
  } catch { /* leave the previous status in place */ }

  let entries = [];
  try { entries = await api('/api/v1/audit?limit=100'); } catch { return; }

  const container = $('audit');
  clear(container);
  for (const entry of entries) {
    const row = el('div', 'entry');
    row.appendChild(el('div', 'when', new Date(entry.at).toLocaleString()));
    row.appendChild(el('div', 'kind', entry.kind));
    const body = el('div');
    body.appendChild(el('div', null, entry.summary));
    body.appendChild(el('div', 'who', `${entry.actor} · #${entry.seq}${entry.sig ? ' · signed' : ''}`));
    row.appendChild(body);
    container.appendChild(row);
  }
}

/* ── Status ───────────────────────────────────────────────────────────── */

async function loadStatus() {
  try {
    const health = await api('/api/v1/status');
    const fleet = health.fleet || {};
    const parts = [`v${health.version}`];
    if (fleet.total) parts.push(`${fleet.online}/${fleet.total} nodes`);
    if (health.sovereign) parts.push('sovereign');
    $('tagline').textContent = parts.join(' · ');
  } catch { /* the header is cosmetic */ }
}

function refreshAll() {
  loadStatus();
  loadApprovals();
  loadFleet();
  loadIncidents();
  loadRuns();
  if (state.view === 'audit') loadAudit();
}

/* ── Wiring ───────────────────────────────────────────────────────────── */

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
    tab.classList.add('active');
    state.view = tab.dataset.view;
    $(`view-${state.view}`).classList.add('active');
    if (state.view === 'audit') loadAudit();
  });
});

$('composer').addEventListener('submit', (event) => {
  event.preventDefault();
  const input = $('input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  send(text);
});

connect();
setInterval(refreshAll, 30000);
