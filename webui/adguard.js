function setChip(state, text) {
  const chip = document.getElementById('adguard-state-chip');
  const label = document.getElementById('adguard-state-text');
  if (label) label.textContent = text;
  if (chip) {
    chip.classList.remove('info', 'active', 'inactive', 'warn');
    chip.classList.add(state);
  }
}

async function loadStatus() {
  const d = await fetchAPI('/api/adguard');
  const text = document.getElementById('status-text');
  if (!d) {
    if (text) text.textContent = 'Unavailable';
    setChip('warn', 'unavailable');
    return;
  }
  if (d.running) {
    if (text) text.textContent = 'Running';
    setChip('active', 'running');
  } else if (d.enabled) {
    if (text) text.textContent = 'Enabled (stopped)';
    setChip('info', 'stopped');
  } else {
    if (text) text.textContent = 'Not enabled';
    setChip('inactive', 'disabled');
  }
}

async function loadConfig() {
  const d = await fetchAPI('/api/adguard/config');
  if (!d) return;
  document.getElementById('dns').value = d.dns || '';
  document.getElementById('web').value = d.web || '';
  document.getElementById('upstream').value = d.upstream || '';
  document.getElementById('adult').checked = !!d.adult;
}

async function startAG() {
  try {
    await postJSON('/api/adguard/start');
    showToast('AdGuard started', 'success');
  } catch (e) {
    showToast(e.message, 'error');
  }
  loadStatus();
}

async function stopAG() {
  try {
    await postJSON('/api/adguard/stop');
    showToast('AdGuard stopped', 'success');
  } catch (e) {
    showToast(e.message, 'error');
  }
  loadStatus();
}

// The AdGuard admin UI is proxied through this dashboard's own login at
// /adguard-ui/, so open that rather than the loopback-only AdGuard port.
function openUI() {
  window.open('/adguard-ui/', '_blank', 'noopener');
}

loadStatus();
loadConfig();
