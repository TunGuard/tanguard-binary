async function loadStatus() {
  try {
    const r = await fetch('/api/adguard');
    const d = await r.json();
    document.getElementById('status-text').textContent = d.running ? 'Running' : (d.enabled ? 'Enabled (stopped)' : 'Not enabled');
  } catch(e) { document.getElementById('status-text').textContent = 'Error'; }
}
async function loadConfig() {
  try {
    const r = await fetch('/api/adguard/config');
    const d = await r.json();
    document.getElementById('dns').value = d.dns || '';
    document.getElementById('web').value = d.web || '';
    document.getElementById('upstream').value = d.upstream || '';
    document.getElementById('adult').checked = !!d.adult;
  } catch(e) {}
}
async function startAG() {
  await fetch('/api/adguard/start', {method:'POST'});
  setTimeout(loadStatus, 500);
}
async function stopAG() {
  await fetch('/api/adguard/stop', {method:'POST'});
  setTimeout(loadStatus, 500);
}
function openUI() {
  const v = document.getElementById('web').value;
  if (v) window.open('http://' + v, '_blank');
}
loadStatus(); loadConfig();
