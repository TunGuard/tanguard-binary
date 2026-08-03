async function loadDashboard() {
  const status = await fetchAPI('/api/status');
  if (!status) return;
  document.getElementById('pubkey').textContent = status.server_public_key ? status.server_public_key.substring(0, 20) + '...' : '—';
  document.getElementById('port').textContent = status.listen_port || '—';
  document.getElementById('subnet').textContent = status.subnet || '—';
  document.getElementById('peer-count').textContent = (status.peers || []).length;

  const last = document.getElementById('lastUpdated');
  if (last) last.textContent = 'Last updated: ' + new Date().toLocaleTimeString();

  let tx = 0, rx = 0;
  (status.peers || []).forEach(p => { tx += p.tx_bytes || 0; rx += p.rx_bytes || 0; });
  document.getElementById('total-tx').textContent = formatBytes(tx);
  document.getElementById('total-rx').textContent = formatBytes(rx);
}

loadDashboard();
setInterval(loadDashboard, 10000);
