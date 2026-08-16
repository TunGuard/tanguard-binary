const CURRENT_PAGE = document.body.dataset.page || 'dashboard';

const NAV_ICONS = {
  dashboard: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
  peers: 'M4 6h18V4H4c-1.1 0-2 .9-2 2v11H0v3h14v-3H4V6zm19 2h-6c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h6c.55 0 1-.45 1-1V9c0-.55-.45-1-1-1zm-1 9h-4v-7h4v7z',
  settings: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z'
};

document.body.insertAdjacentHTML('beforeend', `
<div id="change-creds-screen">
  <div class="login-card">
    <div class="login-logo">
      <div class="login-logo-icon">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
      </div>
      <div class="login-logo-text">TunGuard</div>
    </div>
    <h2 class="login-title">Set your dashboard login</h2>
    <p class="login-sub">For security you must change the default <code>admin</code> / <code>tanguard</code> login before using the dashboard.</p>
    <form class="web-login-form" onsubmit="changeCredentials(event)">
      <div class="form-group">
        <label class="form-label">Username</label>
        <input class="form-control" name="username" placeholder="New username" required autocomplete="off">
      </div>
      <div class="form-group">
        <label class="form-label">New password (min 8 chars)</label>
        <input class="form-control" name="password" type="password" placeholder="New password" required autocomplete="new-password">
      </div>
      <div class="form-group">
        <label class="form-label">Confirm password</label>
        <input class="form-control" name="confirm_password" type="password" placeholder="Confirm password" required autocomplete="new-password">
      </div>
      <button type="submit" class="btn btn-primary btn-block">Save &amp; Log In</button>
    </form>
  </div>
</div>

<div id="toast-container" class="toast-container"></div>
`);

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('mobile-open');
}

function showToast(msg, type) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  if (type === 'error') t.style.background = '#C5221F';
  else if (type === 'success') t.style.background = '#188038';
  document.getElementById('toast-container').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 3000);
}

function logout() {
  showToast('The dashboard uses HTTP Basic Auth. Close the browser or open a private window to sign out.');
}

function formatBytes(b) {
  if (!b || b === 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(b) / Math.log(1024));
  return (b / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
}

function timeAgo(sec) {
  if (!sec || sec === 0) return 'never';
  const diff = Date.now() / 1000 - sec;
  if (diff < 60) return Math.floor(diff) + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return new Date(sec * 1000).toLocaleDateString();
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function hexToBase64(hex) {
  const b = new Uint8Array(hex.match(/.{1,2}/g).map(x => parseInt(x, 16)));
  return btoa(Array.from(b).map(x => String.fromCharCode(x)).join(''));
}

async function fetchAPI(path, opts) {
  try {
    const r = await fetch(path, opts);
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  }
}

async function loadSidebarStatus() {
  const list = document.getElementById('sidebarStatusList');
  if (!list) return;
  try {
    const status = await fetchAPI('/api/status');
    if (!status) { list.innerHTML = '<div class="sidebar-status-item"><span class="status-dot offline"></span><span>Status unavailable</span></div>'; return; }
    const peers = status.peers || [];
    const online = peers.filter(p => p.last_handshake_sec && (Date.now() / 1000 - p.last_handshake_sec) < 180).length;
    const navBadge = document.getElementById('nav-peer-count');
    if (navBadge) { navBadge.textContent = peers.length; navBadge.style.display = peers.length ? '' : 'none'; }
    const rows = [
      { label: 'Listen port', value: status.listen_port || '—' },
      { label: 'Subnet', value: status.subnet || '—' },
      { label: 'Peers', value: peers.length + ' total · ' + online + ' online' }
    ];
    list.innerHTML = rows.map(r => `
      <div class="sidebar-status-item" title="${escapeHtml(r.value)}">
        <span class="status-dot ${r.label === 'Peers' ? (online > 0 ? 'online' : 'offline') : 'info'}"></span>
        <span class="sidebar-status-name">${escapeHtml(r.label)}</span>
        <span class="sidebar-status-state">${escapeHtml(r.value)}</span>
      </div>`).join('');
  } catch (e) {
    list.innerHTML = '<div class="sidebar-status-item"><span class="status-dot offline"></span><span>Status unavailable</span></div>';
  }
}

async function restoreBackup(e) {
  const input = e.target;
  const file = input.files[0];
  if (!file) return;
  const resultEl = document.getElementById('backup-result');
  if (resultEl) resultEl.innerHTML = '';
  if (!confirm('Restore this backup? This replaces the current peers, server key, dashboard login and SSH host key, then applies them to the running server. If the server key differs from your current one, connected clients will need the updated config.')) {
    input.value = '';
    return;
  }
  const fd = new FormData();
  fd.append('backup', file);
  const r = await fetchAPI('/api/backup/restore', {
    method: 'POST',
    body: fd
  });
  if (r && r.success) {
    if (resultEl) resultEl.innerHTML = '<div class="alert alert-success"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>Backup restored: ' + r.peer_count + ' peers, server key ' + (r.server_public_key ? r.server_public_key.substring(0, 12) + '…' : '') + '</div>';
    showToast('Backup restored', 'success');
    setTimeout(() => location.reload(), 1500);
  } else {
    showToast('Restore failed: ' + (r?.error || 'unknown'), 'error');
  }
  input.value = '';
}

async function changeCredentials(e) {
  e.preventDefault();
  const f = e.target;
  if (f.password.value !== f.confirm_password.value) {
    showToast('Passwords do not match', 'error');
    return;
  }
  const btn = f.querySelector('button[type=submit]');
  btn.disabled = true;
  const r = await fetchAPI('/api/web/credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: f.username.value,
      password: f.password.value,
      confirm_password: f.confirm_password.value
    })
  });
  btn.disabled = false;
  if (r && r.success) {
    document.getElementById('change-creds-screen').classList.remove('open');
    f.reset();
    showToast('Credentials updated. Log in again with the new credentials.', 'success');
    setTimeout(() => location.reload(), 1500);
  } else {
    showToast('Failed to update credentials: ' + (r?.error || 'unknown'), 'error');
  }
}

async function checkAuthStatus() {
  const r = await fetchAPI('/api/auth/status');
  if (r && r.must_change) {
    document.getElementById('change-creds-screen').classList.add('open');
  }
}

async function loadAPIKey() {
  const input = document.getElementById('api-key-input');
  if (!input) return;
  const r = await fetchAPI('/api/key');
  if (r && r.key) {
    input.value = r.key;
  } else {
    input.value = '';
  }
}

function copyAPIKey() {
  const input = document.getElementById('api-key-input');
  if (!input || !input.value) return;
  navigator.clipboard.writeText(input.value).then(() => {
    showToast('API key copied', 'success');
  }).catch(() => {
    input.select();
    document.execCommand('copy');
    showToast('API key copied', 'success');
  });
}

async function regenerateAPIKey() {
  if (!confirm('Regenerate the API key? Existing integrations using the current key will stop working immediately.')) return;
  const r = await fetchAPI('/api/key/regenerate', {
    method: 'POST'
  });
  const resultEl = document.getElementById('api-key-result');
  if (r && r.key) {
    document.getElementById('api-key-input').value = r.key;
    if (resultEl) resultEl.innerHTML = '<div class="alert alert-success"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>API key regenerated on ' + new Date(r.created_at).toLocaleString() + '. Update any integrations that use the old key.</div>';
    showToast('API key regenerated', 'success');
  } else {
    if (resultEl) resultEl.innerHTML = '<div class="alert alert-danger"><svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>' + (r?.error || 'unknown error') + '</div>';
    showToast('Failed to regenerate API key: ' + (r?.error || 'unknown'), 'error');
  }
}

checkAuthStatus();
loadSidebarStatus();
loadAPIKey();
setInterval(loadSidebarStatus, 10000);
