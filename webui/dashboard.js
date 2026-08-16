let lastNet = {};
let lastNetTime = 0;

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

function meterRow(label, value, percent, state) {
  const cls = state || (percent >= 90 ? 'crit' : percent >= 70 ? 'warn' : 'ok');
  return `<div class="sys-row">
    <div class="sys-row-head">
      <span class="sys-row-label">${escapeHtml(label)}</span>
      <span class="sys-row-value">${escapeHtml(value)}</span>
    </div>
    <div class="sys-bar"><div class="sys-bar-fill ${cls}" style="width:${Math.max(0, Math.min(100, percent))}%"></div></div>
  </div>`;
}

function formatUptime(sec) {
  sec = Math.floor(sec || 0);
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  const parts = [];
  if (d) parts.push(d + 'd');
  if (h) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}

function fmtLoad(load) {
  if (!load || !load.length) return '—';
  return load.map(v => v.toFixed(2)).join(' / ');
}

async function loadSystemStats() {
  const s = await fetchAPI('/api/system');
  const lastUpd = document.getElementById('sys-last-updated');
  if (!s || (!s.hostname && !s.memory)) {
    if (lastUpd) lastUpd.textContent = 'Unavailable';
    return;
  }
  if (lastUpd) lastUpd.textContent = 'Updated ' + new Date().toLocaleTimeString();

  document.getElementById('sys-meter-cpu').innerHTML =
    meterRow('CPU (' + (s.cpu_cores || '?') + ' cores)', (s.cpu_percent != null ? s.cpu_percent.toFixed(1) : '—') + '%', s.cpu_percent || 0);

  const mem = s.memory || {};
  document.getElementById('sys-meter-mem').innerHTML =
    meterRow('Memory', formatBytes(mem.used) + ' / ' + formatBytes(mem.total) + ' (' + (mem.percent != null ? mem.percent.toFixed(1) : '—') + '%)', mem.percent || 0);

  const disk = s.disk || {};
  document.getElementById('sys-meter-disk').innerHTML =
    meterRow('Disk' + (disk.path ? ' (' + escapeHtml(disk.path) + ')' : ''), formatBytes(disk.used) + ' / ' + formatBytes(disk.total) + ' (' + (disk.percent != null ? disk.percent.toFixed(1) : '—') + '%)', disk.percent || 0);

  const procs = s.processes || {};
  document.getElementById('sys-info').innerHTML = [
    ['Hostname', s.hostname || '—'],
    ['OS', s.os || '—'],
    ['Kernel', s.kernel || '—'],
    ['Uptime', formatUptime(s.uptime)],
    ['Load', fmtLoad(s.load)],
    ['Processes', (procs.running || 0) + ' running / ' + (procs.total || 0) + ' total']
  ].map(([k, v]) => `<span class="sys-info-key">${k}</span><span class="sys-info-val">${escapeHtml(v)}</span>`).join('');

  renderNetwork(s.network || []);
}

function renderNetwork(nets) {
  const el = document.getElementById('sys-network');
  if (!nets.length) {
    el.innerHTML = '<span style="font-size:12px;color:var(--on-surface-med)">No interfaces</span>';
    lastNet = {};
    lastNetTime = 0;
    return;
  }
  const now = Date.now();
  const interval = lastNetTime ? (now - lastNetTime) / 1000 : 0;
  let rows = '';
  nets.forEach(n => {
    let rxRate = '—', txRate = '—';
    if (interval > 0 && lastNet[n.iface]) {
      rxRate = formatRate((n.rx_bytes - lastNet[n.iface].rx) / interval);
      txRate = formatRate((n.tx_bytes - lastNet[n.iface].tx) / interval);
    }
    rows += `<tr>
      <td class="iface">${escapeHtml(n.iface)}</td>
      <td class="rxtx">↓ ${formatBytes(n.rx_bytes)} <span style="color:var(--on-surface-low)">(${rxRate}/s)</span></td>
      <td class="rxtx">↑ ${formatBytes(n.tx_bytes)} <span style="color:var(--on-surface-low)">(${txRate}/s)</span></td>
    </tr>`;
  });
  lastNet = {};
  nets.forEach(n => { lastNet[n.iface] = { rx: n.rx_bytes, tx: n.tx_bytes }; });
  lastNetTime = now;
  el.innerHTML = `<table class="sys-net-table">${rows}</table>`;
}

function formatRate(bps) {
  if (bps < 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bps || 0) / Math.log(1024));
  if (!bps) return '0 B';
  return (bps / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
}

loadDashboard();
loadSystemStats();
setInterval(loadDashboard, 10000);
setInterval(loadSystemStats, 10000);
