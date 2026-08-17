let term, fitAddon, ws, currentTarget = '';
let lastConfig = '';
let pendingRemoveKey = '';
let pendingRemoveName = '';

async function loadPeers() {
  const status = await fetchAPI('/api/status');
  if (!status) return;
  const peers = status.peers || [];
  const countEl = document.getElementById('peer-count');
  if (countEl) countEl.textContent = peers.length;

  const tbody = document.getElementById('peers-tbody');
  if (peers.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8">
      <div class="empty-state">
        <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M4 6h18V4H4c-1.1 0-2 .9-2 2v11H0v3h14v-3H4V6zm19 2h-6c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h6c.55 0 1-.45 1-1V9c0-.55-.45-1-1-1zm-1 9h-4v-7h4v7z"/></svg></div>
        <h3>No peers yet</h3>
        <p>Add an existing WireGuard key or generate a config to get started.</p>
      </div>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = peers.map(p => {
    const isOnline = p.last_handshake_sec && (Date.now() / 1000 - p.last_handshake_sec) < 180;
    const ip = p.allowed_ips ? p.allowed_ips.split(',')[0].trim().replace('/32', '') : '';
    const name = p.device_name || p.device_id || '—';
    const safeName = escapeHtml(name);
    return `<tr>
      <td><span class="chip ${isOnline ? 'active' : 'inactive'}"><span class="chip-dot"></span>${isOnline ? 'Online' : 'Offline'}</span></td>
      <td><span class="td-label">${escapeHtml(name)}</span></td>
      <td class="mono">${escapeHtml(p.allowed_ips || '—')}</td>
      <td class="mono" title="${escapeHtml(p.public_key)}">${escapeHtml(p.public_key.substring(0, 12))}…</td>
      <td class="mono">${escapeHtml(p.endpoint || '—')}</td>
      <td class="mono">${formatBytes(p.tx_bytes)} / ${formatBytes(p.rx_bytes)}</td>
      <td>${timeAgo(p.last_handshake_sec)}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-outline" data-action="ssh" data-ip="${escapeHtml(ip)}" data-name="${safeName}">
          <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM9 15H7v-4h2v4zm4 0h-2V7h2v8zm4 0h-2v-6h2v6z"/></svg>
          SSH
        </button>
        <button class="btn btn-sm btn-outline" data-action="qr" data-ip="${escapeHtml(ip)}" data-key="${escapeHtml(p.public_key)}" data-name="${safeName}">
          <svg viewBox="0 0 24 24"><path d="M3 11h8V3H3v8zm2-6h4v4H5V5zM3 21h8v-8H3v8zm2-6h4v4H5v-4zm8-12v8h8V3h-8zm6 6h-4V5h4v4zm-5.99 4h2v2h-2zm2 2h2v2h-2zm-2 2h2v2h-2zm4 0h2v2h-2zm2 2h2v2h-2zm-4 0h2v2h-2zm2-6h2v2h-2zm2 2h2v2h-2z"/></svg>
          QR
        </button>
        <button class="btn btn-sm btn-danger" data-action="remove" data-key="${escapeHtml(p.public_key)}" data-name="${safeName}">
          <svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
          Remove
        </button>
      </td>
    </tr>`;
  }).join('');
}

document.getElementById('peers-tbody').addEventListener('click', e => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const key = btn.dataset.key || '';
  const ip = btn.dataset.ip || '';
  const name = btn.dataset.name || '';
  if (action === 'ssh') openSSH(ip, name);
  else if (action === 'qr') showPeerConfig(ip, key, name);
  else if (action === 'remove') askRemovePeer(key, name);
});

function switchAddTab(name) {
  document.querySelectorAll('#add-peer-form .tab-btn').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('#add-peer-form .tab-panel').forEach(t => t.classList.remove('active'));
  document.querySelector(`#add-peer-form .tab-btn[data-tab="${name}"]`).classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

function quickConfig() {
  showAddPeer();
  switchAddTab('generate');
  const hostInput = document.getElementById('server-host-input');
  if (!hostInput.value) hostInput.value = location.hostname;
}

function showAddPeer() {
  document.getElementById('add-peer-form').style.display = 'block';
  document.getElementById('add-peer-form').scrollIntoView({ behavior: 'smooth' });
}

function hideAddPeer() {
  document.getElementById('add-peer-form').style.display = 'none';
  document.getElementById('config-result').style.display = 'none';
}

function hideConfigResult() {
  document.getElementById('config-result').style.display = 'none';
}

async function addPeer(e) {
  e.preventDefault();
  const f = e.target;
  const data = {
    public_key: f.public_key.value,
    allowed_ip: f.allowed_ip.value,
    device_id: f.device_id.value,
    device_name: f.device_name.value,
    preshared_key: f.preshared_key.value
  };
  const r = await fetchAPI('/api/peer/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  if (r && r.success) { showToast('Peer added', 'success'); hideAddPeer(); f.reset(); loadPeers(); }
  else showToast('Failed to add peer: ' + (r?.error || 'unknown'), 'error');
}

async function generateConfig(e) {
  e.preventDefault();
  const f = e.target;
  const btn = document.getElementById('gen-btn');
  btn.disabled = true;
  btn.textContent = 'Generating...';

  const data = {
    device_name: f.device_name.value,
    device_id: f.device_id.value,
    server_host: f.server_host.value || location.hostname,
    dns: f.dns.value || '1.1.1.1',
    allowed_ip: f.allowed_ip.value || ''
  };

  const r = await fetchAPI('/api/peer/generate-config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });

  btn.disabled = false;
  btn.textContent = 'Generate Config';

  if (r && r.success) {
    showToast('Config generated for ' + r.allowed_ip, 'success');
    displayConfig(r.config, r.device_name || r.allowed_ip);
    f.reset();
    loadPeers();
  } else {
    showToast('Failed: ' + (r?.error || 'unknown'), 'error');
  }
}

async function showPeerConfig(ip, pubkey, name) {
  const r = await fetchAPI('/api/peer/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: pubkey, server_host: location.hostname })
  });
  if (r && r.config) {
    displayConfig(r.config, name || ip);
  } else {
    showToast('No config available for this peer: ' + (r?.error || 'unknown'), 'error');
  }
}

function displayConfig(config, name) {
  lastConfig = config;
  document.getElementById('config-textarea').value = config;
  document.getElementById('config-device-name').textContent = '— ' + (name || '');
  document.getElementById('config-result').style.display = 'block';
  document.getElementById('config-result').scrollIntoView({ behavior: 'smooth' });

  const qrEl = document.getElementById('qrcode');
  qrEl.innerHTML = '';
  const canvas = document.createElement('canvas');
  qrEl.appendChild(canvas);
  try {
    QRCode.toCanvas(canvas, config, { width: 220, margin: 2, color: { dark: '#1A73E8', light: '#fff' } }, function(err) {
      if (err) qrEl.innerHTML = '<div style="color:var(--on-surface-med);padding:20px">QR Error</div>';
    });
  } catch (e) {
    qrEl.innerHTML = '<div style="color:var(--on-surface-med);padding:20px">QR unavailable</div>';
  }
}

function copyConfig() {
  if (!lastConfig) return;
  navigator.clipboard.writeText(lastConfig).then(() => {
    showToast('Config copied to clipboard', 'success');
  }).catch(() => {
    document.getElementById('config-textarea').select();
    document.execCommand('copy');
    showToast('Config copied', 'success');
  });
}

function downloadConfig() {
  if (!lastConfig) return;
  const blob = new Blob([lastConfig], { type: 'application/octet-stream' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'tanguard.conf';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('Config downloaded', 'success');
}

function askRemovePeer(key, name) {
  const displayName = name || (key ? key.substring(0, 12) + '…' : 'this peer');
  pendingRemoveKey = key;
  pendingRemoveName = displayName;
  document.getElementById('delete-pubkey').textContent = key ? key.substring(0, 12) + '…' : '';
  document.getElementById('delete-confirm-label').textContent = displayName;
  const input = document.getElementById('delete-input');
  input.value = '';
  input.placeholder = 'Type ' + displayName;
  document.getElementById('delete-confirm-btn').disabled = true;
  document.getElementById('delete-modal').classList.add('open');
  setTimeout(() => input.focus(), 50);
}

function closeDeleteModal() {
  document.getElementById('delete-modal').classList.remove('open');
  pendingRemoveKey = '';
  pendingRemoveName = '';
}

function confirmRemovePeer() {
  if (!pendingRemoveKey || !pendingRemoveName) return;
  const input = document.getElementById('delete-input');
  if (input.value.trim() !== pendingRemoveName) {
    showToast('Name does not match. Peer was not removed.', 'error');
    return;
  }
  const btn = document.getElementById('delete-confirm-btn');
  btn.disabled = true;
  btn.textContent = 'Removing...';
  fetchAPI('/api/peer/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: pendingRemoveKey })
  }).then(r => {
    btn.textContent = 'Remove Peer';
    if (r && r.success) { showToast('Peer removed', 'success'); closeDeleteModal(); loadPeers(); }
    else showToast('Failed to remove peer: ' + (r?.error || 'unknown'), 'error');
  });
}

document.getElementById('delete-input').addEventListener('input', e => {
  const ok = e.target.value.trim() === pendingRemoveName;
  document.getElementById('delete-confirm-btn').disabled = !ok;
});
document.getElementById('delete-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !document.getElementById('delete-confirm-btn').disabled) confirmRemovePeer();
});

function openSSH(ip, name) {
  if (!ip) { showToast('No IP available for this peer', 'error'); return; }
  document.getElementById('terminal-title').textContent = 'SSH: ' + (name || ip);
  document.getElementById('terminal-container').classList.add('open');
  currentTarget = ip + ':22';
  initTerminal();
}

function closeTerminal() {
  document.getElementById('terminal-container').classList.remove('open');
  if (ws) { ws.close(); ws = null; }
  if (term) { term.dispose(); term = null; }
}

function initTerminal() {
  const el = document.getElementById('terminal');
  el.innerHTML = '';
  term = new Terminal({ cursorBlink: true, fontSize: 14, fontFamily: 'Menlo,Monaco,monospace', theme: { background: '#1a1a2e', foreground: '#e4e6f0', cursor: '#22c55e' } });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(el);
  setTimeout(() => fitAddon.fit(), 50);
  term.focus();
  term.write('\r\n\x1b[1;32mTunGuard SSH Terminal\x1b[0m\r\n');
  term.write('Connecting to \x1b[33m' + currentTarget + '\x1b[0m...\r\n');

  term.onResize(size => { if (ws) ws.send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows })); });

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/api/ws/ssh');

  ws.onopen = () => {
    ws.send(JSON.stringify({ target: currentTarget, username: '', password: '' }));
    term.onData(data => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'input', data })); });
  };

  ws.onmessage = e => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === 'auth') {
        showPasswordPrompt();
      } else if (msg.type === 'output') {
        term.write(msg.data);
      } else if (msg.type === 'error') {
        term.write('\r\n\x1b[1;31mError: ' + msg.message + '\x1b[0m\r\n');
      } else if (msg.type === 'closed') {
        term.write('\r\n\x1b[2m[connection closed]\x1b[0m\r\n');
      }
    } catch {
      term.write(e.data);
    }
  };

  ws.onclose = () => {
    term.write('\r\n\x1b[2m[disconnected]\x1b[0m\r\n');
    ws = null;
  };

  ws.onerror = () => {
    term.write('\r\n\x1b[1;31mWebSocket error\x1b[0m\r\n');
  };
}

function showPasswordPrompt() {
  term.write('\r\nUsername: ');
  let buf = '', field = 'username';
  term.onData(data => {
    if (data === '\r' || data === '\n') {
      if (field === 'username') {
        ws.send(JSON.stringify({ type: 'auth', username: buf }));
        buf = '';
        field = 'password';
        term.write('\r\nPassword: ');
      } else {
        ws.send(JSON.stringify({ type: 'auth', password: buf }));
        buf = '';
        field = 'done';
        term.onData(data => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'input', data })); });
      }
    } else if (data === '\x7f') {
      if (buf.length > 0) { buf = buf.slice(0, -1); term.write('\b \b'); }
    } else {
      buf += data;
      if (field === 'username') term.write(data);
    }
  });
}

(function init() {
  const params = new URLSearchParams(location.search);
  if (params.get('action') === 'generate') {
    showAddPeer();
    switchAddTab('generate');
    const hostInput = document.getElementById('server-host-input');
    if (!hostInput.value) hostInput.value = location.hostname;
  }
  loadPeers();
  setInterval(loadPeers, 10000);
})();
