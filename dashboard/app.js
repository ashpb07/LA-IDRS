// dashboard/app.js
'use strict';

const API_BASE = `http://${location.hostname}:8000/api/v1`;
const POLL_MS  = 5000;

// ── Helpers ────────────────────────────────────────────────────────────────

async function apiFetch(path) {
  try {
    const res = await fetch(API_BASE + path);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    console.warn('API fetch failed:', path, e.message);
    return null;
  }
}

async function apiDelete(path) {
  try {
    const res = await fetch(API_BASE + path, { method: 'DELETE' });
    return res.ok;
  } catch {
    return false;
  }
}

function scoreClass(score) {
  if (score >= 71) return 'score-high';
  if (score >= 31) return 'score-mid';
  return 'score-low';
}

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString();
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

// ── Status ─────────────────────────────────────────────────────────────────

async function refreshStatus() {
  const data = await apiFetch('/status');
  const pill  = document.getElementById('status-pill');
  const badge = document.getElementById('baseline-badge');

  if (!data) {
    pill.textContent = '● Offline';
    pill.className   = 'status-pill offline';
    return;
  }

  pill.textContent = '● Online';
  pill.className   = 'status-pill online';

  document.getElementById('stat-tracked').textContent = data.tracked_ips ?? '—';
  document.getElementById('stat-blocked').textContent = data.blocked_count ?? '—';

  if (data.baseline_learning) {
    badge.textContent = `⏳ Baseline learning ${data.baseline_pct?.toFixed(1)}%`;
  } else {
    badge.textContent = '';
  }
}

// ── Alerts ─────────────────────────────────────────────────────────────────

async function refreshAlerts() {
  const data = await apiFetch('/alerts');
  const tbody = document.getElementById('alerts-body');
  if (!data || !data.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">No alerts yet.</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(a => {
    const cls      = scoreClass(a.risk_score);
    const pct      = Math.min(a.risk_score, 100);
    const lastEvt  = a.events?.at(-1);
    const evtText  = lastEvt ? `${lastEvt.type}` : '—';
    const statusBadge = a.is_blocked
      ? '<span class="badge badge-red">BLOCKED</span>'
      : a.risk_score >= 71
        ? '<span class="badge badge-yellow">HIGH RISK</span>'
        : '<span class="badge badge-green">MONITORING</span>';
    const unblockBtn = a.is_blocked
      ? `<button class="btn-unblock" data-ip="${a.ip}">Unblock</button>`
      : '—';
    return `
      <tr>
        <td style="font-family:monospace">${a.ip}</td>
        <td>
          <div class="score-bar ${cls}">
            <span class="score-num">${a.risk_score}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
          </div>
        </td>
        <td>${statusBadge}</td>
        <td style="color:var(--text-muted);font-size:.78rem">${evtText}</td>
        <td>${unblockBtn}</td>
      </tr>`;
  }).join('');

  // Bind unblock buttons
  tbody.querySelectorAll('.btn-unblock').forEach(btn => {
    btn.addEventListener('click', () => openUnblockModal(btn.dataset.ip));
  });
}

// ── Blocked list ────────────────────────────────────────────────────────────

async function refreshBlocks() {
  const data  = await apiFetch('/blocks');
  const list  = document.getElementById('blocked-list');
  const hpStat = await apiFetch('/honeypots');

  document.getElementById('stat-honeypot').textContent =
    hpStat?.contact_count ?? '—';

  if (!data || !data.length) {
    list.innerHTML = '<li class="empty">None blocked.</li>';
    return;
  }
  list.innerHTML = data.map(b => `
    <li>
      <span>${b.ip}</span>
      <button class="btn-unblock" data-ip="${b.ip}">Unblock</button>
    </li>`).join('');

  list.querySelectorAll('.btn-unblock').forEach(btn => {
    btn.addEventListener('click', () => openUnblockModal(btn.dataset.ip));
  });
}

// ── Attack graphs ───────────────────────────────────────────────────────────

async function refreshGraphs() {
  const data = await apiFetch('/graphs');
  const container = document.getElementById('graphs-container');
  document.getElementById('stat-graphs').textContent = data?.length ?? '—';

  if (!data || !data.length) {
    container.innerHTML = '<p class="empty">No attack graphs recorded yet.</p>';
    return;
  }

  container.innerHTML = data.slice(-20).reverse().map(g => {
    const nodes = (g.nodes || []).map(n =>
      `<span>${n.event_type}</span>`).join('<span class="graph-arrow">→</span>');
    return `
      <div class="graph-card">
        <div class="graph-ip">${g.ip} <span style="color:var(--text-muted);font-size:.7rem;font-family:monospace">${g.graph_id}</span></div>
        <div class="graph-narrative">${nodes || '<em>No events</em>'}</div>
      </div>`;
  }).join('');
}

// ── XAI Reports ─────────────────────────────────────────────────────────────

async function refreshReports() {
  const data = await apiFetch('/reports');
  const container = document.getElementById('reports-container');

  if (!data || !data.length) {
    container.innerHTML = '<p class="empty">No block reports yet.</p>';
    return;
  }

  container.innerHTML = data.slice(0, 20).map(r => {
    const reasons = (r.reasons || []).map(s => `<li>${s}</li>`).join('');
    return `
      <div class="report-card">
        <div class="report-header">
          <span class="report-ip">${r.ip}</span>
          <span class="report-score">Score: ${r.risk_score}/100</span>
        </div>
        <div class="report-ts">Blocked at: ${fmtDate(r.blocked_at)}</div>
        <ul class="report-reasons">${reasons}</ul>
      </div>`;
  }).join('');
}

// ── Unblock modal ───────────────────────────────────────────────────────────

let _pendingUnblockIp = null;

function openUnblockModal(ip) {
  _pendingUnblockIp = ip;
  document.getElementById('modal-ip').textContent = ip;
  document.getElementById('modal-overlay').classList.remove('hidden');
}

document.getElementById('modal-cancel').addEventListener('click', () => {
  document.getElementById('modal-overlay').classList.add('hidden');
  _pendingUnblockIp = null;
});

document.getElementById('modal-confirm').addEventListener('click', async () => {
  if (!_pendingUnblockIp) return;
  await apiDelete(`/blocks/${_pendingUnblockIp}`);
  document.getElementById('modal-overlay').classList.add('hidden');
  _pendingUnblockIp = null;
  refreshAll();
});

// ── Manual refresh buttons ──────────────────────────────────────────────────

document.getElementById('btn-refresh-alerts') .addEventListener('click', refreshAlerts);
document.getElementById('btn-refresh-blocks') .addEventListener('click', refreshBlocks);
document.getElementById('btn-refresh-graphs') .addEventListener('click', refreshGraphs);
document.getElementById('btn-refresh-reports').addEventListener('click', refreshReports);

// ── Poll loop ───────────────────────────────────────────────────────────────

async function refreshAll() {
  await refreshStatus();
  await refreshAlerts();
  await refreshBlocks();
  await refreshGraphs();
  await refreshReports();
}

refreshAll();
setInterval(refreshAll, POLL_MS);
