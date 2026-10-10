const CURRENT_PAGE = document.body.dataset.page || 'dashboard';

const NAV_ICONS = {
  dashboard: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
  peers: 'M4 6h18V4H4c-1.1 0-2 .9-2 2v11H0v3h14v-3H4V6zm19 2h-6c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h6c.55 0 1-.45 1-1V9c0-.55-.45-1-1-1zm-1 9h-4v-7h4v7z',
  settings: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z'
};

document.body.insertAdjacentHTML('beforeend', `
<div id="toast-container" class="toast-container"></div>
`);

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('mobile-open');
}

function applyThemeLabel() {
  const label = document.getElementById('themeLabel');
  if (label) label.textContent = document.documentElement.classList.contains('light') ? 'Light' : 'Dark';
}

function toggleTheme() {
  const html = document.documentElement;
  const next = html.classList.contains('light') ? 'dark' : 'light';
  html.classList.toggle('light', next === 'light');
  try { localStorage.setItem('tg-theme', next); } catch (e) { /* private mode */ }
  applyThemeLabel();
}

// Collapse / restore a window panel's body (WinBox minimize button).
function toggleWinPanel(btn) {
  const win = btn.closest('.card');
  if (!win) return;
  const collapsed = win.classList.toggle('collapsed');
  btn.textContent = collapsed ? '+' : '\u2013';
  btn.title = collapsed ? 'Expand' : 'Collapse';
}

// Expand a window panel over the workspace (WinBox maximize button).
function toggleWinMax(btn) {
  const win = btn.closest('.card');
  if (!win) return;
  const maxed = win.classList.toggle('maximized');
  btn.textContent = maxed ? '\u2922' : '\u25A1';
  btn.title = maxed ? 'Restore' : 'Maximize';
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
  if (diff < 3600) { const m = Math.floor(diff / 60); const s = Math.floor(diff % 60); return m + 'm' + (s > 0 ? s + 's' : '') + ' ago'; }
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
    if (!opts) opts = {};
    if (!opts.credentials) opts.credentials = 'same-origin';
    const r = await fetch(path, opts);
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  }
}

// postJSON sends a JSON body to a mutating endpoint. Unlike fetchAPI it throws
// on failure, because a page that silently swallows a failed action looks
// identical to one that worked.
async function postJSON(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  });
  let data = null;
  try {
    data = await r.json();
  } catch (e) {
    throw new Error('server returned a non-JSON response (' + r.status + ')');
  }
  if (!r.ok) {
    throw new Error(data && data.error ? data.error : 'request failed (' + r.status + ')');
  }
  return data;
}

async function loadSidebarStatus() {
  const list = document.getElementById('sidebarStatusList');
  if (!list) return;
  try {
    const status = await fetchAPI('/api/status');
    if (!status) { list.innerHTML = '<div class="sidebar-status-item"><span class="status-dot offline"></span><span>Status unavailable</span></div>'; return; }
    renderSidebarStatus(status);
  } catch (e) {
    list.innerHTML = '<div class="sidebar-status-item"><span class="status-dot offline"></span><span>Status unavailable</span></div>';
  }
}

function renderSidebarStatus(status) {
  const list = document.getElementById('sidebarStatusList');
  if (!list) return;
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
    f.reset();
    showToast('Credentials updated. Log in again with the new credentials.', 'success');
    setTimeout(() => location.reload(), 1500);
  } else {
    showToast('Failed to update credentials: ' + (r?.error || 'unknown'), 'error');
  }
}

// A server still on the shipped login has no usable dashboard, so the setup
// form is a page of its own rather than a popup over the page the user asked
// for. login.html sends them on once the login has been changed.
async function checkAuthStatus() {
  if (CURRENT_PAGE === 'login') return;
  const r = await fetchAPI('/api/auth/status');
  if (r && r.must_change) {
    location.replace('login.html');
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

// ---- WinBox-style window manager (desktop shell only) ---------------
// The dashboard shell (index.html, no ?embed=1) turns every page into a
// floating, draggable, resizable window holding that page in an iframe.
// Pages keep working standalone: ?embed=1 just strips the outer chrome.
const WIN_DEFS = {
  dashboard: { title: 'Dashboard',        icon: 'fa-gauge',           href: 'index.html' },
  peers:     { title: 'Peers',            icon: 'fa-users',           href: 'peers.html' },
  p2p:       { title: 'P2P Mesh',         icon: 'fa-diagram-project', href: 'p2p.html' },
  trp:       { title: 'TRP Port Mapping', icon: 'fa-route',           href: 'trp.html' },
  domains:   { title: 'Domains',           icon: 'fa-globe',           href: 'domains.html' },
  policy:    { title: 'Policy Groups',    icon: 'fa-shield-halved',   href: 'policy.html' },
  terminal:  { title: 'Terminal',         icon: 'fa-terminal',        href: 'terminal.html' },
  systemlogs:{ title: 'System Logs',      icon: 'fa-file-lines',      href: 'systemlogs.html' },
  settings:  { title: 'Settings',         icon: 'fa-gear',            href: 'settings.html' }
};
let winZ = 30;
let winCascade = 0;

function isShell() {
  return document.documentElement.classList.contains('shell');
}

function clamp(v, lo, hi) {
  return Math.min(Math.max(v, lo), hi);
}

function getWinRects() {
  try { return JSON.parse(localStorage.getItem('tg-win-rects')) || {}; } catch (e) { return {}; }
}
function saveWinRect(key, rect) {
  try {
    const all = getWinRects();
    all[key] = rect;
    localStorage.setItem('tg-win-rects', JSON.stringify(all));
  } catch (e) { /* private mode */ }
}
function currentRect(win) {
  return { left: win.offsetLeft, top: win.offsetTop, width: win.offsetWidth, height: win.offsetHeight };
}
function persistWin(win) {
  if (win.classList.contains('maximized') || win.classList.contains('minimized')) return;
  saveWinRect(win.dataset.key, currentRect(win));
}

function embedHref(href) {
  return href + (href.indexOf('?') >= 0 ? '&' : '?') + 'embed=1';
}

function focusWin(key) {
  const win = document.getElementById('win-' + key);
  if (!win) return;
  winZ += 1;
  win.style.zIndex = winZ;
  document.querySelectorAll('.wb-window.focused').forEach(w => w.classList.remove('focused'));
  win.classList.add('focused');
  if (!isShell()) return;
  const href = (WIN_DEFS[key] || {}).href || '';
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(a => {
    a.classList.toggle('active', (a.getAttribute('href') || '').split(/[?#]/)[0] === href);
  });
  const title = document.querySelector('.topbar-title');
  if (title && WIN_DEFS[key]) title.textContent = WIN_DEFS[key].title;
}

function openWin(key, href) {
  const def = WIN_DEFS[key];
  const ws = document.getElementById('workspace');
  if (!def || !ws || !isShell()) return false;

  const target = href || def.href;
  let win = document.getElementById('win-' + key);
  if (win) {
    const frame = win.querySelector('iframe');
    if (frame && frame.dataset.src !== target) {
      frame.dataset.src = target;
      win.querySelector('.window-body').classList.add('loading');
      frame.src = embedHref(target);
    }
    if (win.classList.contains('minimized')) toggleWinMin(key);
    focusWin(key);
    return true;
  }

  const wsW = ws.clientWidth;
  const wsH = ws.clientHeight;
  if (wsW < 400 || wsH < 260) return false;

  const saved = getWinRects()[key] || {};
  const width = Math.min(saved.width || Math.min(920, wsW - 140), wsW - 16);
  const height = Math.min(saved.height || Math.min(640, wsH - 90), wsH - 16);
  const defLeft = 34 + (winCascade % 6) * 26;
  const defTop = 18 + (winCascade % 6) * 22;
  winCascade += 1;
  const left = clamp(saved.left != null ? saved.left : defLeft, -(width - 140), Math.max(0, wsW - 140));
  const top = clamp(saved.top != null ? saved.top : defTop, 0, Math.max(0, wsH - 26));

  win = document.createElement('div');
  win.className = 'wb-window';
  win.id = 'win-' + key;
  win.dataset.key = key;
  win.style.left = left + 'px';
  win.style.top = top + 'px';
  win.style.width = width + 'px';
  win.style.height = height + 'px';
  win.style.zIndex = ++winZ;
  win.innerHTML =
    '<div class="window-header">' +
      '<div class="window-title"><i class="fa-solid ' + def.icon + '"></i><span>' + def.title + '</span></div>' +
      '<div class="window-btns">' +
        '<button type="button" data-act="max" title="Maximize"><i class="fa-solid fa-maximize"></i></button>' +
        '<button type="button" data-act="min" title="Minimize"><i class="fa-solid fa-minus"></i></button>' +
        '<button type="button" data-act="close" title="Close"><i class="fa-solid fa-xmark"></i></button>' +
      '</div>' +
    '</div>' +
    '<div class="window-body loading">' +
      '<div class="window-loader"><div class="spinner"></div></div>' +
      '<iframe title="' + def.title + '"></iframe>' +
    '</div>' +
    ['n', 's', 'e', 'w', 'nw', 'ne', 'sw', 'se'].map(d => '<div class="rs rs-' + d + '" data-dir="' + d + '"></div>').join('');
  ws.appendChild(win);

  const frame = win.querySelector('iframe');
  frame.dataset.src = target;
  frame.src = embedHref(target);
  frame.addEventListener('load', () => win.querySelector('.window-body').classList.remove('loading'));
  wireWin(win);
  focusWin(key);
  return true;
}

function closeWin(key) {
  const win = document.getElementById('win-' + key);
  if (!win) return;
  const wasFocused = win.classList.contains('focused');
  win.remove();
  if (!wasFocused) return;
  let top = null;
  document.querySelectorAll('.wb-window').forEach(w => {
    if (!top || (+w.style.zIndex || 0) > (+top.style.zIndex || 0)) top = w;
  });
  if (top) focusWin(top.dataset.key);
  else {
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(a => a.classList.remove('active'));
    const t = document.querySelector('.topbar-title');
    if (t) t.textContent = 'Desktop';
  }
}

function toggleWinMin(key) {
  const win = document.getElementById('win-' + key);
  if (!win) return;
  const min = win.classList.toggle('minimized');
  if (!min) focusWin(key);
}

function restoreMax(win) {
  win.classList.remove('maximized');
  try {
    const r = JSON.parse(win.dataset.prev);
    win.style.left = r.left + 'px';
    win.style.top = r.top + 'px';
    win.style.width = r.width + 'px';
    win.style.height = r.height + 'px';
  } catch (e) { /* ignore */ }
  const icon = win.querySelector('[data-act="max"] i');
  if (icon) icon.className = 'fa-solid fa-maximize';
}

function toggleWinMax(key) {
  const win = document.getElementById('win-' + key);
  const ws = document.getElementById('workspace');
  if (!win || !ws) return;
  if (win.classList.contains('maximized')) {
    restoreMax(win);
  } else {
    if (!win.classList.contains('minimized')) win.dataset.prev = JSON.stringify(currentRect(win));
    win.classList.remove('minimized');
    win.classList.add('maximized');
    win.style.left = '0px';
    win.style.top = '0px';
    win.style.width = ws.clientWidth + 'px';
    win.style.height = ws.clientHeight + 'px';
    const icon = win.querySelector('[data-act="max"] i');
    if (icon) icon.className = 'fa-solid fa-minimize';
  }
  focusWin(key);
  persistWin(win);
}

function wireWin(win) {
  const key = win.dataset.key;
  const header = win.querySelector('.window-header');

  win.addEventListener('pointerdown', () => focusWin(key), true);

  win.querySelectorAll('.window-btns button').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const act = btn.dataset.act;
      if (act === 'close') closeWin(key);
      else if (act === 'min') toggleWinMin(key);
      else if (act === 'max') toggleWinMax(key);
    });
  });

  header.addEventListener('dblclick', e => {
    if (e.target.closest('button')) return;
    toggleWinMax(key);
  });

  header.addEventListener('pointerdown', e => {
    if (e.button !== 0 || e.target.closest('button')) return;
    if (win.classList.contains('minimized')) { toggleWinMin(key); return; }
    e.preventDefault();
    focusWin(key);

    const ws = document.getElementById('workspace');
    let startX = e.clientX;
    let startY = e.clientY;
    let startL = win.offsetLeft;
    let startT = win.offsetTop;

    if (win.classList.contains('maximized')) {
      restoreMax(win);
      startL = clamp(Math.round(e.clientX - win.offsetWidth / 2),
        -(win.offsetWidth - 140), Math.max(0, ws.clientWidth - 140));
      startT = 0;
      win.style.left = startL + 'px';
      win.style.top = startT + 'px';
      startX = e.clientX;
      startY = e.clientY;
    }

    header.setPointerCapture(e.pointerId);
    const onMove = ev => {
      win.style.left = clamp(startL + ev.clientX - startX, -(win.offsetWidth - 140),
        Math.max(0, ws.clientWidth - 140)) + 'px';
      win.style.top = clamp(startT + ev.clientY - startY, 0,
        Math.max(0, ws.clientHeight - 26)) + 'px';
    };
    const onUp = ev => {
      header.removeEventListener('pointermove', onMove);
      header.removeEventListener('pointerup', onUp);
      header.removeEventListener('pointercancel', onUp);
      try { header.releasePointerCapture(ev.pointerId); } catch (err) { /* ignore */ }
      persistWin(win);
    };
    header.addEventListener('pointermove', onMove);
    header.addEventListener('pointerup', onUp);
    header.addEventListener('pointercancel', onUp);
  });

  win.querySelectorAll('.rs').forEach(handle => {
    handle.addEventListener('pointerdown', e => {
      if (e.button !== 0) return;
      if (win.classList.contains('minimized') || win.classList.contains('maximized')) return;
      e.preventDefault();
      e.stopPropagation();
      focusWin(key);

      const dir = handle.dataset.dir;
      const startX = e.clientX;
      const startY = e.clientY;
      const s = { left: win.offsetLeft, top: win.offsetTop, w: win.offsetWidth, h: win.offsetHeight };
      const MIN_W = 340, MIN_H = 180;
      handle.setPointerCapture(e.pointerId);

      const onMove = ev => {
        const dx = ev.clientX - startX;
        const dy = ev.clientY - startY;
        let left = s.left, top = s.top, w = s.w, h = s.h;
        if (dir.indexOf('e') >= 0) w = Math.max(MIN_W, s.w + dx);
        if (dir.indexOf('s') >= 0) h = Math.max(MIN_H, s.h + dy);
        if (dir.indexOf('w') >= 0) { w = Math.max(MIN_W, s.w - dx); left = s.left + (s.w - w); }
        if (dir.indexOf('n') >= 0) { h = Math.max(MIN_H, s.h - dy); top = s.top + (s.h - h); }
        if (top < 0) { h += top; top = 0; }
        win.style.left = left + 'px';
        win.style.top = top + 'px';
        win.style.width = w + 'px';
        win.style.height = h + 'px';
      };
      const onUp = ev => {
        handle.removeEventListener('pointermove', onMove);
        handle.removeEventListener('pointerup', onUp);
        handle.removeEventListener('pointercancel', onUp);
        try { handle.releasePointerCapture(ev.pointerId); } catch (err) { /* ignore */ }
        persistWin(win);
      };
      handle.addEventListener('pointermove', onMove);
      handle.addEventListener('pointerup', onUp);
      handle.addEventListener('pointercancel', onUp);
    });
  });
}

function wireShellNav() {
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(a => {
    a.addEventListener('click', e => {
      if (window.innerWidth < 860) return; // small screens navigate normally
      const href = a.getAttribute('href') || '';
      const key = href.split(/[?#]/)[0].replace(/\.html$/, '');
      if (!WIN_DEFS[key]) return;
      e.preventDefault();
      openWin(key);
    });
  });
}

// Links inside a window ask the shell to open/reuse the target window
// instead of navigating the iframe away from its window.
if (document.documentElement.classList.contains('embed')) {
  document.addEventListener('click', e => {
    if (e.defaultPrevented || e.button !== 0) return;
    const a = e.target.closest('a[href]');
    if (!a || a.target === '_blank') return;
    const href = a.getAttribute('href');
    if (!href || /^(https?:|mailto:|#)/.test(href)) return;
    const file = href.split(/[?#]/)[0];
    if (!/\.html$/.test(file)) return;
    e.preventDefault();
    const key = file.replace(/^.*[\\/]/, '').replace(/\.html$/, '');
    if (window.parent && window.parent !== window && typeof window.parent.openWin === 'function') {
      window.parent.openWin(key, href);
    } else {
      location.href = href;
    }
  });
}

// Keep every frame's theme button in sync when another frame switches it.
window.addEventListener('storage', e => {
  if (e.key !== 'tg-theme') return;
  document.documentElement.classList.toggle('light', e.newValue === 'light');
  applyThemeLabel();
});

applyThemeLabel();
if (isShell()) {
  wireShellNav();
  openWin('dashboard');
}
checkAuthStatus();
loadSidebarStatus();
loadAPIKey();
if (CURRENT_PAGE !== 'dashboard' && CURRENT_PAGE !== 'login') setInterval(loadSidebarStatus, 10000);
