// TRP page: maps a service port on a device onto a port on this server, so a
// service on a device behind a NAT becomes reachable at <server>:<port>.
//
// Data comes from /api/trp/proxies, which already resolves the device name and
// online flag for each mapping. /api/mesh/nodes is only needed to populate the
// device picker in the "add" dialog.

let trpProxies = [];
let trpNodes = [];

// The server does not know the public hostname operators use to reach it, so the
// browser supplies it: whatever address this page was loaded from.
function serverHost() {
  return window.location.hostname || 'this server';
}

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

async function loadTRP() {
  const [trp, mesh] = await Promise.all([
    fetchAPI('/api/trp/proxies'),
    fetchAPI('/api/mesh/nodes')
  ]);
  if (!trp) {
    showToast('Could not load TRP mappings — is the tun control plane running?', 'error');
    return;
  }
  trpProxies = trp.proxies || [];
  trpNodes = (mesh && mesh.nodes) || [];

  renderStats();
  renderRows();
  renderDevicePicker();
}

function renderStats() {
  const conns = trpProxies.reduce((n, p) => n + (p.active || 0), 0);
  const onlineDevices = new Set(trpProxies.filter(p => p.online).map(p => p.node_id)).size;

  setText('stat-mappings', trpProxies.length);
  setText('stat-conns', conns);
  setText('stat-devices', onlineDevices + ' / ' + new Set(trpProxies.map(p => p.node_id)).size);
  setText('stat-host', serverHost());
  setText('trp-count', trpProxies.length);

  // Nav badge: hide at zero, matching renderSidebarStatus.
  const badge = document.getElementById('nav-trp-count');
  if (badge) {
    badge.textContent = trpProxies.length;
    badge.style.display = trpProxies.length ? '' : 'none';
  }

  // The header diagram shows the first mapping as a concrete example.
  const first = trpProxies[0];
  if (first) {
    setText('flow-public', serverHost() + ':' + first.bind_port);
    setText('flow-target', (first.node_name || first.node_id) +
      ' ' + (first.target_ip || '127.0.0.1') + ':' + first.target_port);
  } else {
    setText('flow-public', serverHost() + ':<port>');
    setText('flow-target', 'device 127.0.0.1:8022');
  }
}

function setText(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

function renderRows() {
  const tbody = document.getElementById('trp-tbody');
  if (!tbody) return;

  if (!trpProxies.length) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">
      <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M20 18c1.1 0 1.99-.9 1.99-2L22 5c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v11c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 5h16v11H4V5zm8 8.5c-2.49 0-4.5-2.01-4.5-4.5S9.51 4.5 12 4.5s4.5 2.01 4.5 4.5-2.01 4.5-4.5 4.5z"/></svg></div>
      <h3>No port mappings</h3>
      <p>Add a mapping to reach a service running on a device at this server's IP address.</p>
    </div></td></tr>`;
    return;
  }

  tbody.innerHTML = trpProxies.map(p => {
    const url = serverHost() + ':' + p.bind_port;
    const status = p.online
      ? '<span class="chip active"><span class="chip-dot"></span>online</span>'
      : '<span class="chip inactive"><span class="chip-dot"></span>device offline</span>';
    return `<tr>
      <td><span class="td-label mono">${escapeHtml(url)}</span>
          ${p.bind_ip && p.bind_ip !== '0.0.0.0' ? `<div class="td-sub mono">on ${escapeHtml(p.bind_ip)}</div>` : ''}</td>
      <td><span class="td-label">${escapeHtml(p.node_name || p.node_id)}</span>
          <div class="td-sub mono">${escapeHtml(p.node_id)}</div></td>
      <td class="mono">${escapeHtml(p.target_ip || '127.0.0.1')}:${escapeHtml(p.target_port)}</td>
      <td>${status}</td>
      <td class="mono">${p.active || 0}</td>
      <td class="td-sub">${fmtAgo(p.created_at)}</td>
      <td><button class="btn btn-sm btn-danger" onclick="removeProxy('${escapeHtml(p.id)}')">Delete</button></td>
    </tr>`;
  }).join('');
}

function renderDevicePicker() {
  const sel = document.getElementById('trp-node');
  if (!sel) return;
  const prev = sel.value;

  if (!trpNodes.length) {
    sel.innerHTML = '<option value="">no devices enrolled</option>';
    return;
  }

  const online = trpNodes.filter(n => n.online);
  const offline = trpNodes.filter(n => !n.online);
  sel.innerHTML = '';

  const addGroup = (label, list) => {
    if (!list.length) return;
    const g = document.createElement('optgroup');
    g.label = label;
    list.forEach(n => {
      const o = document.createElement('option');
      o.value = n.id;
      o.textContent = n.name || n.id;
      g.appendChild(o);
    });
    sel.appendChild(g);
  };
  addGroup('Online', online);
  addGroup('Offline', offline);

  if (prev) sel.value = prev;
  else if (online.length) sel.value = online[0].id;
}

function showTRPError(msg) {
  const box = document.getElementById('trp-error');
  const text = document.getElementById('trp-error-text');
  if (!box || !text) return;
  text.textContent = msg;
  box.style.display = msg ? '' : 'none';
}

function openTRP() {
  showTRPError('');
  document.getElementById('trp-target-port').value = '8022';
  document.getElementById('trp-bind-port').value = '';
  document.getElementById('trp-bind-ip').value = '';
  document.getElementById('trp-modal').classList.add('open');
}

function closeTRP() {
  document.getElementById('trp-modal').classList.remove('open');
}

async function submitTRP() {
  showTRPError('');

  const nodeId = document.getElementById('trp-node').value;
  const targetPort = document.getElementById('trp-target-port').value.trim();
  const bindPort = document.getElementById('trp-bind-port').value.trim();
  const bindIP = document.getElementById('trp-bind-ip').value.trim();

  if (!nodeId) {
    showTRPError('Enroll a device on the P2P page first.');
    return;
  }
  if (!targetPort || targetPort < 1 || targetPort > 65535) {
    showTRPError('The service port must be between 1 and 65535.');
    return;
  }
  if (bindPort && (bindPort < 1 || bindPort > 65535)) {
    showTRPError('The server port must be between 1 and 65535, or left blank for auto.');
    return;
  }

  const btn = document.getElementById('trp-submit');
  btn.disabled = true;
  try {
    const r = await postJSON('/api/trp/proxy/add', {
      node_id: nodeId,
      bind_ip: bindIP,
      bind_port: bindPort,
      target_port: targetPort
    });
    closeTRP();
    showToast('Mapping created: ' + serverHost() + ':' + r.bind_port, 'success');
    loadTRP();
  } catch (e) {
    showTRPError(e.message);
  } finally {
    btn.disabled = false;
  }
}

async function removeProxy(id) {
  if (!confirm('Delete this mapping? The port on the server stops listening immediately.')) return;
  try {
    await postJSON('/api/trp/proxy/remove', { id: id });
    showToast('Mapping deleted', 'success');
    loadTRP();
  } catch (e) {
    showToast('Could not delete mapping: ' + e.message, 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadTRP();
  // Mapping state and device presence change on their own, so poll.
  setInterval(loadTRP, 10000);
});
