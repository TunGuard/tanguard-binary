let term, fitAddon, ws, currentTarget = '';
let lastConfig = '';

async function loadPeers() {
  const status = await fetchAPI('/api/status');
  if (!status) return;
  const peers = status.peers || [];
  document.getElementById('peer-count').textContent = peers.length;

  const tbody = document.getElementById('peers-tbody');
  if (peers.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No peers connected</td></tr>';
    return;
  }
  tbody.innerHTML = peers.map(p => {
    const isOnline = p.last_handshake_sec && (Date.now() / 1000 - p.last_handshake_sec) < 180;
    const ip = p.allowed_ips ? p.allowed_ips.split(',')[0].trim().replace('/32', '') : '';
    return `<tr>
      <td><span class="status-dot ${isOnline ? 'online' : 'offline'}"></span></td>
      <td style="font-family:inherit;font-weight:600">${p.device_name || p.device_id || '—'}</td>
      <td>${p.allowed_ips || '—'}</td>
      <td title="${p.public_key}">${p.public_key.substring(0, 12)}…</td>
      <td>${p.endpoint || '—'}</td>
      <td>${formatBytes(p.tx_bytes)} / ${formatBytes(p.rx_bytes)}</td>
      <td>${timeAgo(p.last_handshake_sec)}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm btn-outline-primary" onclick="openSSH('${ip}','${p.device_name || p.device_id || ''}')">SSH</button>
        <button class="btn btn-sm btn-outline-success" onclick="showPeerConfig('${ip}','${p.public_key}','${p.device_name || p.device_id || ''}')">QR</button>
        <button class="btn btn-sm btn-outline-danger" onclick="removePeer('${p.public_key}')">Remove</button>
      </td>
    </tr>`;
  }).join('');
}

function switchAddTab(name) {
  document.querySelectorAll('#add-peer-form .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('#add-peer-form .tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`#add-peer-form .tab[data-tab="${name}"]`).classList.add('active');
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
  const status = await fetchAPI('/api/status');
  if (!status) return;
  const host = location.hostname;
  const port = status.listen_port || 13231;
  const srvPub = hexToBase64(status.server_public_key || '');
  const config = `[Interface]
Address = ${ip}/24
DNS = 1.1.1.1

[Peer]
PublicKey = ${srvPub}
Endpoint = ${host}:${port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
  displayConfig(config, name || ip);
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
    QRCode.toCanvas(canvas, config, { width: 220, margin: 2, color: { dark: '#16a34a', light: '#fff' } }, function(err) {
      if (err) qrEl.innerHTML = '<div style="color:#6c757d;padding:20px">QR Error</div>';
    });
  } catch (e) {
    qrEl.innerHTML = '<div style="color:#6c757d;padding:20px">QR unavailable</div>';
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

async function removePeer(key) {
  if (!confirm('Remove peer ' + key.substring(0, 12) + '…?')) return;
  const r = await fetchAPI('/api/peer/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: key })
  });
  if (r && r.success) { showToast('Peer removed', 'success'); loadPeers(); }
  else showToast('Failed to remove peer', 'error');
}

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
