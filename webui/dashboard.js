let lastNet = {};
let lastNetTime = 0;

const ALLOWED_IFACES = ['tun0', 'wgo', 'eth0'];
const MAX_CHART_POINTS = 60;
const netHistory = { labels: [], tun0rx: [], tun0tx: [], wgorx: [], wgotx: [], eth0rx: [], eth0tx: [] };
let netChart = null;

function initNetChart() {
  const ctx = document.getElementById('net-chart');
  if (!ctx || netChart || typeof Chart === 'undefined') return;
  netChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'tun0 RX', data: [], borderColor: '#4285F4', backgroundColor: 'rgba(66,133,244,.12)', borderWidth: 1.5, tension: .3, pointRadius: 0, fill: true },
        { label: 'tun0 TX', data: [], borderColor: '#34A853', backgroundColor: 'rgba(52,168,83,.12)', borderWidth: 1.5, tension: .3, pointRadius: 0, fill: true },
        { label: 'wgo RX',  data: [], borderColor: '#FA7B17', backgroundColor: 'rgba(250,123,23,.12)', borderWidth: 1.5, tension: .3, pointRadius: 0, fill: true },
        { label: 'wgo TX',  data: [], borderColor: '#EA4335', backgroundColor: 'rgba(234,67,53,.12)',  borderWidth: 1.5, tension: .3, pointRadius: 0, fill: true },
        { label: 'eth0 RX', data: [], borderColor: '#00ACC1', backgroundColor: 'rgba(0,172,193,.12)',  borderWidth: 1.5, tension: .3, pointRadius: 0, fill: true },
        { label: 'eth0 TX', data: [], borderColor: '#FBBC04', backgroundColor: 'rgba(251,188,4,.12)',  borderWidth: 1.5, tension: .3, pointRadius: 0, fill: true }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: { display: true, position: 'bottom', labels: { boxWidth: 10, padding: 8, font: { size: 10 } } },
        tooltip: { callbacks: { label: function(c) { return c.dataset.label + ': ' + formatRate(c.parsed.y || 0); } } }
      },
      scales: {
        x: { display: true, ticks: { maxTicksLimit: 8, font: { size: 10 } }, grid: { display: false } },
        y: { display: true, beginAtZero: true, ticks: { callback: function(v) { return formatRate(v); }, font: { size: 10 } }, grid: { color: 'rgba(0,0,0,.06)' } }
      }
    }
  });
}

function updateNetChart(rates) {
  if (!netChart) return;
  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  netHistory.labels.push(now);
  netHistory.tun0rx.push(rates['tun0'] || 0);
  netHistory.tun0tx.push(rates['tun0_tx'] || 0);
  netHistory.wgorx.push(rates['wgo'] || 0);
  netHistory.wgotx.push(rates['wgo_tx'] || 0);
  netHistory.eth0rx.push(rates['eth0'] || 0);
  netHistory.eth0tx.push(rates['eth0_tx'] || 0);

  if (netHistory.labels.length > MAX_CHART_POINTS) {
    netHistory.labels.shift();
    netHistory.tun0rx.shift(); netHistory.tun0tx.shift();
    netHistory.wgorx.shift();  netHistory.wgotx.shift();
    netHistory.eth0rx.shift(); netHistory.eth0tx.shift();
  }

  netChart.data.labels = netHistory.labels.slice();
  const ds = netChart.data.datasets;
  ds[0].data = netHistory.tun0rx.slice();
  ds[1].data = netHistory.tun0tx.slice();
  ds[2].data = netHistory.wgorx.slice();
  ds[3].data = netHistory.wgotx.slice();
  ds[4].data = netHistory.eth0rx.slice();
  ds[5].data = netHistory.eth0tx.slice();
  netChart.update();
}

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
  initNetChart();

  const filtered = nets.filter(n => ALLOWED_IFACES.includes(n.iface));

  if (!filtered.length) {
    el.innerHTML = '<span style="font-size:12px;color:var(--on-surface-med)">No active interfaces (tun0, wgo, eth0)</span>';
    lastNet = {};
    lastNetTime = 0;
    return;
  }

  const now = Date.now();
  const interval = lastNetTime ? (now - lastNetTime) / 1000 : 0;
  const rates = {};
  let rows = '';

  filtered.forEach(n => {
    let rxRate = '—', txRate = '—', rxVal = 0, txVal = 0;
    if (interval > 0 && lastNet[n.iface]) {
      rxVal = Math.max(0, (n.rx_bytes - lastNet[n.iface].rx) / interval);
      txVal = Math.max(0, (n.tx_bytes - lastNet[n.iface].tx) / interval);
      rxRate = formatRate(rxVal);
      txRate = formatRate(txVal);
    }
    rates[n.iface] = rxVal;
    rates[n.iface + '_tx'] = txVal;

    const color = n.iface === 'tun0' ? '#4285F4' : n.iface === 'wgo' ? '#FA7B17' : '#00ACC1';
    rows += `<tr>
      <td class="iface"><span class="iface-dot" style="background:${color}"></span>${escapeHtml(n.iface)}</td>
      <td class="rxtx">↓ ${formatBytes(n.rx_bytes)} <span style="color:var(--on-surface-low)">(${rxRate}/s)</span></td>
      <td class="rxtx">↑ ${formatBytes(n.tx_bytes)} <span style="color:var(--on-surface-low)">(${txRate}/s)</span></td>
    </tr>`;
  });

  lastNet = {};
  filtered.forEach(n => { lastNet[n.iface] = { rx: n.rx_bytes, tx: n.tx_bytes }; });
  lastNetTime = now;
  el.innerHTML = `<table class="sys-net-table">${rows}</table>`;

  updateNetChart(rates);
}

function formatRate(bps) {
  if (bps < 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bps || 0) / Math.log(1024));
  if (!bps) return '0 B';
  return (bps / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
}

loadDashboard();
loadSystemStats();
checkVersion();
setInterval(loadDashboard, 10000);
setInterval(loadSystemStats, 10000);
setInterval(checkVersion, 3600000);

let pendingDownloadURL = '';

async function checkVersion() {
  const data = await fetchAPI('/api/version');
  if (!data) return;
  const badge = document.getElementById('version-badge');
  const label = document.getElementById('version-label');
  const dot = document.getElementById('version-dot');
  if (!badge || !label) return;
  badge.style.display = '';
  label.textContent = 'v' + (data.current_version || '—');
  if (data.update_available && data.download_url) {
    dot.style.display = '';
    pendingDownloadURL = data.download_url;
  } else {
    dot.style.display = 'none';
    pendingDownloadURL = '';
  }
}

async function openUpdateModal() {
  const modal = document.getElementById('update-modal');
  const content = document.getElementById('update-content');
  const footer = document.getElementById('update-footer');
  if (!modal) return;
  modal.classList.add('open');
  footer.style.display = 'none';
  content.innerHTML = '<div style="text-align:center;padding:20px 0"><div class="spinner"></div><p style="color:var(--on-surface-med);margin-top:12px;font-size:13px">Checking for updates...</p></div>';

  const data = await fetchAPI('/api/version');
  if (!data) {
    content.innerHTML = '<div class="alert alert-danger">Failed to check for updates.</div>';
    return;
  }

  if (!data.update_available) {
    content.innerHTML = `
      <div style="text-align:center;padding:20px 0">
        <div style="font-size:40px;margin-bottom:12px">&#10003;</div>
        <div style="font-family:var(--mono);font-size:16px;font-weight:700;margin-bottom:4px">v${escapeHtml(data.current_version)}</div>
        <div style="font-size:13px;color:var(--on-surface-med)">You're running the latest version.</div>
      </div>`;
    footer.style.display = 'none';
    return;
  }

  const notes = escapeHtml(data.release_notes || '').replace(/\n/g, '<br>');
  content.innerHTML = `
    <div style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <span class="chip info"><span class="chip-dot"></span>Update available</span>
        <span style="font-family:var(--mono);font-size:13px;font-weight:600">v${escapeHtml(data.current_version)} → v${escapeHtml(data.latest_version)}</span>
      </div>
      ${data.release_url ? '<a href="' + escapeHtml(data.release_url) + '" target="_blank" rel="noopener" style="font-size:12px;color:var(--blue-500)">View release on GitHub →</a>' : ''}
    </div>
    <div style="font-size:12px;font-weight:500;color:var(--on-surface-med);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">Release Notes</div>
    <div style="font-size:13px;color:var(--on-surface);max-height:200px;overflow-y:auto;border:1px solid var(--surface-4);border-radius:var(--radius-md);padding:12px;line-height:1.6">${notes || '<em>No release notes</em>'}</div>
  `;
  pendingDownloadURL = data.download_url || '';
  footer.style.display = '';
}

function closeUpdateModal() {
  const modal = document.getElementById('update-modal');
  if (modal) modal.classList.remove('open');
}

async function installUpdate() {
  if (!pendingDownloadURL) return;
  const btn = document.getElementById('update-btn');
  const footer = document.getElementById('update-footer');
  const content = document.getElementById('update-content');
  if (btn) { btn.disabled = true; btn.textContent = 'Installing...'; }
  if (footer) footer.style.display = 'none';

  content.innerHTML = '<div style="text-align:center;padding:20px 0"><div class="spinner"></div><p style="color:var(--on-surface-med);margin-top:12px;font-size:13px">Downloading and installing update... The server will restart automatically.</p></div>';

  const r = await fetchAPI('/api/update', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ download_url: pendingDownloadURL })
  });

  if (r && r.success) {
    content.innerHTML = '<div style="text-align:center;padding:20px 0"><div style="font-size:40px;margin-bottom:12px">&#10003;</div><p style="font-size:13px;color:var(--on-surface-med)">Update installed. Server is restarting...</p></div>';
    setTimeout(() => { location.reload(); }, 5000);
  } else {
    content.innerHTML = '<div class="alert alert-danger">Update failed: ' + escapeHtml((r && r.error) || 'unknown error') + '</div>';
    if (btn) { btn.disabled = false; btn.textContent = 'Retry Install'; }
  }
}
