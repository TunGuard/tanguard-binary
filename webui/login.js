// The sign-in page replaces the browser's native HTTP Basic popup. It posts the
// credentials to /api/login once, which hands back a session cookie, and every
// request after that rides the cookie. On a server still on the shipped
// admin/tanguard login, signing in with the defaults lands on the same "set
// your login" step the page has always shown, now with no popup in front of it.

function showSignIn() {
  document.getElementById('signin-panel').style.display = '';
  document.getElementById('setup-panel').style.display = 'none';
  document.title = 'TunGuard - Sign in';
  const u = document.querySelector('#signin-panel input[name=username]');
  if (u) u.focus();
}

function showSetup() {
  document.getElementById('signin-panel').style.display = 'none';
  document.getElementById('setup-panel').style.display = '';
  document.title = 'TunGuard - Set your dashboard login';
  const u = document.querySelector('#setup-panel input[name=username]');
  if (u) u.focus();
  loadLoginVersion();
}

// A caller with a live session either owes a credential change (first login)
// or belongs on the dashboard; everyone else gets the sign-in form.
async function initLogin() {
  const s = await fetchAPI('/api/auth/status');
  if (!s) {
    showSignIn();
    return;
  }
  if (s.must_change) {
    showSetup();
    return;
  }
  location.replace('/index.html');
}

async function signIn(e) {
  e.preventDefault();
  const f = e.target;
  const btn = f.querySelector('button[type=submit]');
  btn.disabled = true;
  let r;
  try {
    r = await postJSON('/api/login', { username: f.username.value, password: f.password.value });
  } catch (err) {
    btn.disabled = false;
    showToast(err.message, 'error');
    return;
  }
  btn.disabled = false;
  if (r.must_change) {
    showSetup();
  } else {
    location.replace('/index.html');
  }
}

async function setupLogin(e) {
  e.preventDefault();
  const f = e.target;
  if (f.password.value !== f.confirm_password.value) {
    showToast('Passwords do not match', 'error');
    return;
  }
  const btn = f.querySelector('button[type=submit]');
  btn.disabled = true;
  try {
    await postJSON('/api/web/credentials', {
      username: f.username.value,
      password: f.password.value,
      confirm_password: f.confirm_password.value
    });
  } catch (err) {
    btn.disabled = false;
    showToast('Failed to set the login: ' + err.message, 'error');
    return;
  }
  showToast('Dashboard login set. Welcome.', 'success');
  setTimeout(() => location.replace('/index.html'), 800);
}

// The footer states the build the user is actually running, and says so when
// GitHub has a newer release: the same facts the dashboard badge shows. It is
// loaded only once a session exists (the first-login step), because /api/version
// itself sits behind the dashboard login.
async function loadLoginVersion() {
  const meta = document.getElementById('login-version-meta');
  const label = document.getElementById('login-version');
  if (!meta || !label) return;
  const data = await fetchAPI('/api/version');
  if (!data || !data.current_version) return;
  label.textContent = 'v' + data.current_version;
  meta.style.display = '';
  const hint = document.getElementById('login-update');
  if (hint && data.update_available && data.latest_version) {
    const latest = document.getElementById('login-latest');
    if (latest) latest.textContent = 'v' + data.latest_version;
    hint.style.display = '';
  }
}

initLogin();
