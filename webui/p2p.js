// P2P page: shows the mesh grouped by PSK, which is exactly the automatic
// discovery set, plus the live punch state between devices.
//
// /api/mesh/groups supplies the groups (already bucketed by PSK, with member
// nodes attached) and the overall status. /api/mesh/links supplies the live
// per-peer state.

let p2pGroups = [];
let p2pLinks = [];
let p2pStatus = {};
// PSKs are operator-supplied, so they can contain quotes. They are never
// spliced into an inline onclick; handlers take an index into this array.
let p2pGroupPSKs = [];

function fmtAgo(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 0) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

async function loadP2P() {
  // show_psk=1 returns the unmasked PSK. The UI only ever displays the masked
  // label, but "Copy PSK" and "Re-punch" need the real value to act on.
  const [groups, links] = await Promise.all([
    fetchAPI('/api/mesh/groups?show_psk=1'),
    fetchAPI('/api/mesh/links')
  ]);
  if (!groups) {
    showToast('Could not load the mesh — is the tun control plane running?', 'error');
    return;
  }
  p2pGroups = groups.groups || [];
  p2pStatus = groups.status || {};
  p2pLinks = (links && links.links) || [];

  renderStats();
  renderGroups();
  renderLinks();
}

function setText(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

function renderStats() {
  // meshStatus() has no link totals, and the links array is the live truth.
  const direct = p2pLinks.filter(l => l.direct).length;
  const tested = p2pLinks.filter(l => l.tested).length;

  setText('stat-devices', p2pStatus.nodes != null ? p2pStatus.nodes : 0);
  setText('stat-groups', p2pGroups.length);
  setText('stat-direct', direct);
  setText('stat-tested-sub', tested + ' of ' + direct + ' answer a link test');
  setText('p2p-online', p2pStatus.online != null ? p2pStatus.online : 0);

  const ctrl = p2pStatus.control_listen || '—';
  const hub = p2pStatus.relay_listen || '—';
  const ep = document.getElementById('stat-endpoints');
  if (ep) {
    ep.className = 'stat-value compact';
    ep.textContent = ctrl + ' / ' + hub;
    ep.title = 'Control ' + ctrl + ' · hole-punch hub ' + hub;
  }

  const badge = document.getElementById('nav-p2p-count');
  if (badge) {
    const n = p2pStatus.online || 0;
    badge.textContent = n;
    badge.style.display = n ? '' : 'none';
  }
}

function renderGroups() {
  const host = document.getElementById('groups');
  if (!host) return;

  if (!p2pGroups.length) {
    host.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">
      <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M7.5 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zm9 0a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM4 22h16v-2H4v2z"/></svg></div>
      <h3>No devices enrolled</h3>
      <p>Enroll a device to get a PSK, then run the client on it. Devices sharing a PSK discover each other automatically.</p>
    </div></div></div>`;
    return;
  }

  p2pGroupPSKs = p2pGroups.map(g => g.psk || '');
  host.innerHTML = p2pGroups.map((g, gi) => {
    const members = (g.members || []).map(m => {
      const chip = m.online
        ? '<span class="chip active"><span class="chip-dot"></span>online</span>'
        : '<span class="chip inactive"><span class="chip-dot"></span>offline</span>';
      const ep = m.relay_ep
        ? '<span class="mono">' + escapeHtml(m.relay_ep) + '</span>'
        : '<span class="td-sub">no hub endpoint</span>';
      const peers = m.peers || 0;
      const directPeers = m.direct_peers || 0;
      const testedPeers = m.tested_peers || 0;
      return `<tr>
        <td><span class="td-label">${escapeHtml(m.name || m.id)}</span>
            <div class="td-sub mono">${escapeHtml(m.id)}</div></td>
        <td>${chip}</td>
        <td class="mono">${escapeHtml(m.control_ip || '—')}</td>
        <td>${ep}</td>
        <td class="mono"${testedPeers < directPeers ? ' title="' + directPeers + ' direct, ' + testedPeers + ' answering a test"' : ''}>${directPeers} / ${peers} direct</td>
        <td class="td-sub">${fmtAgo(m.last_seen)}</td>
        <td><button class="btn btn-sm btn-danger" onclick="removeNode('${escapeHtml(m.id)}')">Remove</button></td>
      </tr>`;
    }).join('');

    const health = g.online === g.nodes
      ? '<span class="chip active"><span class="chip-dot"></span>all online</span>'
      : '<span class="chip inactive"><span class="chip-dot"></span>' + (g.online || 0) + ' of ' + g.nodes + ' online</span>';

    return `<div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Group ${escapeHtml(g.label || g.psk)}</div>
          <div class="card-subtitle">${g.nodes} device(s) · ${g.direct_links || 0} of ${g.links || 0} links direct · max ${p2pStatus.max_peers != null ? p2pStatus.max_peers : 8} peers each</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          ${health}
          <button class="btn btn-sm btn-secondary" onclick="copyPsk(${gi})">Copy PSK</button>
          <button class="btn btn-sm btn-secondary" onclick="rePunch(${gi})">Re-punch</button>
        </div>
      </div>
      <div class="table-wrapper">
        <table>
          <thead><tr>
            <th>Device</th><th>Status</th><th>Control IP</th><th>Hub endpoint</th>
            <th>Peers</th><th>Last seen</th><th></th>
          </tr></thead>
          <tbody>${members}</tbody>
        </table>
      </div>
    </div>`;
  }).join('');
}

function renderLinks() {
  const tbody = document.getElementById('links-tbody');
  if (!tbody) return;

  if (!p2pLinks.length) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">
      <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M7.5 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zm9 0a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM4 22h16v-2H4v2z"/></svg></div>
      <h3>No peer links</h3>
      <p>When two devices in the same group are online they link up on their own. Nothing to do here yet.</p>
    </div></td></tr>`;
    return;
  }

  tbody.innerHTML = p2pLinks.map(l => {
    const state = l.direct
      ? '<span class="chip active"><span class="chip-dot"></span>direct</span>'
      : '<span class="chip inactive"><span class="chip-dot"></span>via hub</span>';
    return `<tr>
      <td><span class="td-label">${escapeHtml(l.from_name || l.from)}</span>
          <div class="td-sub mono">${escapeHtml(l.from)}</div></td>
      <td><span class="td-label">${escapeHtml(l.to_name || l.to)}</span>
          <div class="td-sub mono">${escapeHtml(l.to)}</div></td>
      <td class="mono">${escapeHtml(l.endpoint || '—')}</td>
      <td>${state}</td>
      <td>${linkTestCell(l)}</td>
      <td class="td-sub">${l.direct_since ? fmtAgo(l.direct_since) : '—'}</td>
      <td><button class="btn btn-sm btn-secondary" onclick="rePunchPair('${escapeHtml(l.from)}','${escapeHtml(l.to)}')">Re-punch</button></td>
    </tr>`;
  }).join('');
}

// The link test is the only figure here that is a measurement rather than a
// state, so it gets its own cell and says plainly what it does not know: a
// direct link whose test has no answer is a link that punched and then went
// quiet, which is exactly the case a bare "direct" badge hides.
function linkTestCell(l) {
  if (!l.online) return '<span class="td-sub">offline</span>';
  if (l.tested) {
    const ms = l.rtt_ms != null ? l.rtt_ms : 0;
    return `<span class="chip active"><span class="chip-dot"></span>${ms} ms</span>`;
  }
  if (l.direct) {
    return '<span class="chip warn" data-tip="Punched, but the peer did not answer a test packet"><span class="chip-dot"></span>no answer</span>';
  }
  return '<span class="td-sub">not tested yet</span>';
}

// Auto-meshing is already on; re-punch is the manual retry for a stuck link.
async function rePunch(gi) {
  try {
    await postJSON('/api/mesh/p2p/mesh', { group: p2pGroupPSKs[gi], enable: true });
    showToast('Re-punched the group', 'success');
    loadP2P();
  } catch (e) {
    showToast('Re-punch failed: ' + e.message, 'error');
  }
}

async function rePunchPair(a, b) {
  try {
    await postJSON('/api/mesh/p2p/connect', { a: a, b: b });
    showToast('Hole punch requested', 'success');
    loadP2P();
  } catch (e) {
    showToast('Punch failed: ' + e.message, 'error');
  }
}

async function removeNode(id) {
  if (!confirm('Remove this device? It will be disconnected and its identity released. Peer links are dropped.')) return;
  try {
    await postJSON('/api/mesh/node/remove', { id: id });
    showToast('Device removed', 'success');
    loadP2P();
  } catch (e) {
    showToast('Could not remove device: ' + e.message, 'error');
  }
}

function copyPsk(gi) {
  navigator.clipboard.writeText(p2pGroupPSKs[gi] || '').then(
    () => showToast('PSK copied', 'success'),
    () => showToast('Could not copy the PSK', 'error')
  );
}

// ---- Enroll dialog ------------------------------------------------------

function showEnrollError(msg) {
  const box = document.getElementById('enroll-error');
  const text = document.getElementById('enroll-error-text');
  if (!box || !text) return;
  text.textContent = msg;
  box.style.display = msg ? '' : 'none';
}

function openEnroll() {
  showEnrollError('');
  document.getElementById('enroll-form').style.display = '';
  document.getElementById('enroll-result').style.display = 'none';
  document.getElementById('enroll-submit').style.display = '';
  document.getElementById('enroll-copy').style.display = 'none';
  document.getElementById('enroll-name').value = '';
  document.getElementById('enroll-psk').value = '';
  document.getElementById('enroll-modal').classList.add('open');
}

function closeEnroll() {
  document.getElementById('enroll-modal').classList.remove('open');
}

async function submitEnroll() {
  showEnrollError('');

  const name = document.getElementById('enroll-name').value.trim();
  const psk = document.getElementById('enroll-psk').value.trim();

  const btn = document.getElementById('enroll-submit');
  btn.disabled = true;
  try {
    const r = await postJSON('/api/mesh/node/add', { name: name, psk: psk });
    document.getElementById('enroll-cmd').value = 'tun ' + serverHostOrPlaceholder() + ' ' + r.psk;
    document.getElementById('enroll-form').style.display = 'none';
    document.getElementById('enroll-result').style.display = '';
    document.getElementById('enroll-submit').style.display = 'none';
    document.getElementById('enroll-copy').style.display = '';
    showToast('Device enrolled', 'success');
    loadP2P();
  } catch (e) {
    showEnrollError(e.message);
  } finally {
    btn.disabled = false;
  }
}

function serverHostOrPlaceholder() {
  return window.location.hostname || '<server-ip>';
}

function copyEnrollCmd() {
  const ta = document.getElementById('enroll-cmd');
  if (!ta) return;
  navigator.clipboard.writeText(ta.value).then(
    () => showToast('Command copied', 'success'),
    () => { ta.select(); showToast('Press Ctrl+C to copy the selected command'); }
  );
}

document.addEventListener('DOMContentLoaded', () => {
  loadP2P();
  // Punch state changes on its own, so poll rather than needing a reload.
  setInterval(loadP2P, 5000);
});
