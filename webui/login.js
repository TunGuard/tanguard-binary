// First-login page: it exists only while the shipped admin/tanguard login is
// still in place, so it doubles as the "already set up?" check. Anyone who
// reaches it with a changed login belongs on the dashboard, not here.
async function redirectIfAlreadySet() {
  const r = await fetchAPI('/api/auth/status');
  if (r && !r.must_change) location.replace('index.html');
}

// The footer states the build the user is actually running, and says so when
// GitHub has a newer release — the same facts the dashboard badge shows.
async function loadLoginVersion() {
  const label = document.getElementById('login-version');
  if (!label) return;
  const data = await fetchAPI('/api/version');
  if (!data) {
    label.textContent = 'unknown';
    return;
  }
  label.textContent = 'v' + (data.current_version || 'unknown');
  const hint = document.getElementById('login-update');
  if (hint && data.update_available && data.latest_version) {
    const latest = document.getElementById('login-latest');
    if (latest) latest.textContent = 'v' + data.latest_version;
    hint.style.display = '';
  }
}

redirectIfAlreadySet();
loadLoginVersion();
