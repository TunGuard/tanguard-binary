const CURRENT_PAGE = document.body.dataset.page || 'dashboard';

const NAV_ITEMS = [
  { id: 'dashboard', href: 'index.html', icon: 'fa-tachometer-alt', label: 'Dashboard' },
  { id: 'peers', href: 'peers.html', icon: 'fa-network-wired', label: 'Peers' },
  { id: 'settings', href: 'settings.html', icon: 'fa-cogs', label: 'Settings' }
];

function layoutHTML() {
  const nav = NAV_ITEMS.map(p => `
    <li class="nav-item">
      <a class="nav-link ${p.id === CURRENT_PAGE ? 'active' : ''}" href="${p.href}">
        <i class="nav-icon fas ${p.icon}"></i><p>${p.label}</p>
      </a>
    </li>`).join('');
  return `
<nav class="main-header navbar navbar-expand navbar-white navbar-light">
<ul class="navbar-nav">
<li class="nav-item"><a class="nav-link" data-widget="pushmenu" href="#"><i class="fas fa-bars"></i></a></li>
<li class="nav-item d-none d-sm-inline-block"><a class="nav-link" href="index.html">Home</a></li>
</ul>
<ul class="navbar-nav ml-auto">
<li class="nav-item"><a class="nav-link" href="settings.html"><i class="fas fa-cog"></i></a></li>
<li class="nav-item"><a class="nav-link" href="#" onclick="logout()"><i class="fas fa-sign-out-alt"></i></a></li>
</ul>
</nav>

<aside class="main-sidebar sidebar-glass elevation-4">
<a href="index.html" class="brand-link"><span class="brand-text font-weight-bold">TunGuard</span></a>
<div class="sidebar">
<nav class="mt-2">
<ul class="nav nav-pills nav-sidebar flex-column">
${nav}
</ul>
</nav>
<div class="sidebar-logout"><a href="#" onclick="logout()">Logout</a></div>
</div>
</aside>

<div id="change-creds-screen">
<div class="chart-card" style="max-width:420px;width:100%;border-radius:14px;border:none;box-shadow:0 10px 40px rgba(0,0,0,.15)">
<div class="p-4">
<h5 style="font-weight:800;color:#1a1a2e;">Set your dashboard login</h5>
<p class="text-muted" style="font-size:.9rem;">For security you must change the default <code>admin</code> / <code>tanguard</code> login before using the dashboard.</p>
<form class="web-login-form" onsubmit="changeCredentials(event)">
<input class="form-control mb-2" name="username" placeholder="New username" required>
<input class="form-control mb-2" name="password" type="password" placeholder="New password (min 8 chars)" required>
<input class="form-control mb-3" name="confirm_password" type="password" placeholder="Confirm password" required>
<button type="submit" class="btn btn-primary btn-block">Save &amp; Log In</button>
</form>
</div>
</div>
</div>

<div id="toast"></div>
`;
}

document.querySelector('.wrapper').insertAdjacentHTML('afterbegin', layoutHTML());

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderLeft = '4px solid ' + (type === 'error' ? '#ef4444' : type === 'success' ? '#28a745' : '#007bff');
  t.className = 'show';
  setTimeout(() => t.className = '', 3000);
}

function logout() {
  showToast('The dashboard uses HTTP Basic Auth. Close the browser or open a private window to sign out.', 'info');
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

function hexToBase64(hex) {
  const b = new Uint8Array(hex.match(/.{1,2}/g).map(x => parseInt(x, 16)));
  return btoa(Array.from(b).map(x => String.fromCharCode(x)).join(''));
}

async function fetchAPI(path, opts) {
  try {
    const r = await fetch(path, opts);
    return await r.json();
  } catch (e) {
    showToast('API error: ' + e.message, 'error');
    return null;
  }
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

checkAuthStatus();
