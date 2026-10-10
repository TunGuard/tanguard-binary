// Domains page: maps a public domain name onto a local service — either an
// existing TRP port mapping or a service reachable over the WireGuard tunnel.
// TLS is automatic (Let's Encrypt), so the page mostly manages the routing
// table and shows how the server is currently serving it.

let domainData = { domains: [], status: {} };
let domainProxyOptions = [];
let editId = null;

function fmtAgo(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 0) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function setText(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

async function loadDomains() {
  const data = await fetchAPI('/api/domains');
  if (!data) {
    const mode = document.getElementById('domain-mode');
    if (mode) mode.textContent = 'disabled';
    const chip = document.getElementById('domain-mode-chip');
    if (chip) chip.className = 'chip inactive';
    const tbody = document.getElementById('domain-tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">
      <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M12 2L1 21h22L12 2zm0 16a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm1-6h-2v-5h2v5z"/></svg></div>
      <h3>Domain reverse proxy is disabled</h3>
      <p>Set DOMAIN_ENABLED=true on the server and restart to map domains.</p>
    </div></td></tr>`;
    return;
  }
  domainData = data;
  renderStatus();
  renderRows();
  renderProxyPicker();
}

function renderStatus() {
  const st = domainData.status || {};
  const chip = document.getElementById('domain-mode-chip');
  const label = document.getElementById('domain-mode');
  const badge = document.getElementById('nav-domain-count');
  const count = (domainData.domains || []).length;
  if (badge) { badge.textContent = count; badge.style.display = count ? '' : 'none'; }

  if (!label) return;
  if (st.mode === 'external') {
    label.textContent = 'via ' + (st.webserver || 'webserver');
    if (chip) chip.className = 'chip active';
  } else if (st.mode === 'builtin') {
    label.textContent = 'built-in proxy';
    if (chip) chip.className = 'chip active';
  } else if (st.mode === 'blocked') {
    label.textContent = 'blocked';
    if (chip) chip.className = 'chip inactive';
    if (chip) chip.title = st.error || '';
  } else {
    label.textContent = st.mode || 'idle';
  }
}

function renderRows() {
  const tbody = document.getElementById('domain-tbody');
  if (!tbody) return;
  const domains = domainData.domains || [];

  if (!domains.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">
      <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M20 6h-2.18c.07-.44.18-.88.18-1.35 0-2.58-2.09-4.65-4.67-4.65-1.49 0-2.81.7-3.7 1.79L9 3l-.63-.21C7.48 1.7 6.16 1 4.67 1 2.09 1 0 3.07 0 5.65c0 .47.11.91.18 1.35H0v14h20V6zm-7.62-3.27c.55-.68 1.38-1.08 2.28-1.08 1.56 0 2.82 1.25 2.82 2.8 0 .48-.13.91-.31 1.31L13 5.76l-.62-.03V2.73zM1.85 5.65c0-1.55 1.26-2.8 2.82-2.8.9 0 1.73.4 2.28 1.08v3l-.62.03L4.16 7.76c-.18-.4-.31-.83-.31-1.31zM18 18H2V8h16v10z"/></svg></div>
      <h3>No domain mappings</h3>
      <p>Add a domain to expose a TRP mapping or a tunneled service over HTTPS.</p>
    </div></td></tr>`;
    return;
  }

  tbody.innerHTML = domains.map(d => {
    const state = d.enabled
      ? '<span class="chip active"><span class="chip-dot"></span>enabled</span>'
      : '<span class="chip inactive"><span class="chip-dot"></span>disabled</span>';
    let target = d.target;
    if (!target && d.target_note) target = targetNoteOrLabel(d);
    if (!target) target = '<span style="color:var(--danger)">unresolved</span>';
    return `<tr>
      <td><span class="td-label mono">${escapeHtml(d.domain)}</span>
          <div class="td-sub mono">${escapeHtml(d.id)}</div></td>
      <td><span class="chip"><span class="chip-dot"></span>${escapeHtml(d.backend)}</span></td>
      <td class="mono">${target}</td>
      <td>${state}</td>
      <td class="td-sub">${fmtAgo(d.created_at)}</td>
      <td>
        <button class="btn btn-sm btn-secondary" onclick="editDomain('${escapeHtml(d.id)}')">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="removeDomain('${escapeHtml(d.id)}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function targetNoteOrLabel(d) {
  if (d.backend === 'trp' && d.proxy_ref) return '← ' + escapeHtml(d.proxy_ref);
  if (d.backend === 'wg') return escapeHtml(d.target_ip || '') + ':' + escapeHtml(d.target_port || '');
  return escapeHtml(d.target_note);
}

// Populate the TRP picker in the add dialog from /api/trp/proxies.
async function renderProxyPicker() {
  const sel = document.getElementById('dm-proxy');
  if (!sel) return;
  const proxies = await fetchAPI('/api/trp/proxies');
  domainProxyOptions = (proxies && proxies.proxies) || [];
  const prev = sel.value;
  if (!domainProxyOptions.length) {
    sel.innerHTML = '<option value="">no port mappings (create one on the TRP page)</option>';
    return;
  }
  sel.innerHTML = '';
  domainProxyOptions.forEach(p => {
    const o = document.createElement('option');
    o.value = p.id;
    o.textContent = p.node_name + ' — :' + p.bind_port + ' → ' + (p.target_ip || '127.0.0.1') + ':' + p.target_port;
    sel.appendChild(o);
  });
  if (prev) sel.value = prev;
}

function toggleBackendFields() {
  const backend = document.getElementById('dm-backend').value;
  document.getElementById('dm-trp-row').style.display = backend === 'trp' ? '' : 'none';
  document.getElementById('dm-wg-row').style.display = backend === 'wg' ? '' : 'none';
}

function showDomainError(msg) {
  const box = document.getElementById('domain-error');
  const text = document.getElementById('domain-error-text');
  if (!box || !text) return;
  text.textContent = msg;
  box.style.display = msg ? '' : 'none';
}

function openDomain() {
  editId = null;
  showDomainError('');
  document.getElementById('domain-modal-title').textContent = 'Add domain mapping';
  document.getElementById('domain-submit').textContent = 'Create mapping';
  document.getElementById('dm-domain').value = '';
  document.getElementById('dm-backend').value = 'trp';
  document.getElementById('dm-target-ip').value = '';
  document.getElementById('dm-target-port').value = '80';
  document.getElementById('dm-enabled').checked = true;
  toggleBackendFields();
  renderProxyPicker();
  document.getElementById('domain-modal').classList.add('open');
}

function editDomain(id) {
  const d = (domainData.domains || []).find(x => x.id === id);
  if (!d) return;
  editId = id;
  showDomainError('');
  document.getElementById('domain-modal-title').textContent = 'Edit domain mapping';
  document.getElementById('domain-submit').textContent = 'Save';
  document.getElementById('dm-domain').value = d.domain;
  document.getElementById('dm-backend').value = d.backend === 'wg' ? 'wg' : 'trp';
  document.getElementById('dm-target-ip').value = d.target_ip || '';
  document.getElementById('dm-target-port').value = d.target_port || '80';
  document.getElementById('dm-enabled').checked = !!d.enabled;
  toggleBackendFields();
  renderProxyPicker().then(() => {
    if (d.proxy_ref) document.getElementById('dm-proxy').value = d.proxy_ref;
  });
  document.getElementById('domain-modal').classList.add('open');
}

function closeDomain() {
  document.getElementById('domain-modal').classList.remove('open');
}

async function submitDomain() {
  showDomainError('');

  const domain = document.getElementById('dm-domain').value.trim().toLowerCase();
  if (!domain) { showDomainError('Enter a domain name.'); return; }

  const backend = document.getElementById('dm-backend').value;
  const enabled = document.getElementById('dm-enabled').checked;
  let body;
  if (backend === 'trp') {
    const ref = document.getElementById('dm-proxy').value;
    if (!ref) { showDomainError('Pick a TRP mapping (create one on the TRP page first).'); return; }
    body = { domain, backend, proxy_ref: ref, enabled };
  } else {
    const ip = document.getElementById('dm-target-ip').value.trim();
    const port = parseInt(document.getElementById('dm-target-port').value, 10);
    if (!ip) { showDomainError('Enter the IP address of the service (reachable via the tunnel).'); return; }
    if (!port || port < 1 || port > 65535) { showDomainError('Port must be between 1 and 65535.'); return; }
    body = { domain, backend, target_ip: ip, target_port: port, enabled };
  }

  const btn = document.getElementById('domain-submit');
  btn.disabled = true;
  try {
    if (editId) await postJSON('/api/domain/update', Object.assign({ id: editId }, body));
    else await postJSON('/api/domain/add', body);
    closeDomain();
    showToast((editId || '') ? 'Domain mapping saved' : 'Domain mapped: https://' + domain, 'success');
    editId = null;
    loadDomains();
  } catch (e) {
    showDomainError(e.message);
  } finally {
    btn.disabled = false;
  }
}

async function removeDomain(id) {
  if (!confirm('Remove this domain mapping? It stops answering immediately.')) return;
  try {
    await postJSON('/api/domain/remove', { id });
    showToast('Domain mapping removed', 'success');
    loadDomains();
  } catch (e) {
    showToast('Could not remove mapping: ' + e.message, 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadDomains();
  setInterval(loadDomains, 10000);
});