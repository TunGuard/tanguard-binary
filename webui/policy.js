// Policy Groups page: an administrative filter over connections that already
// exist. Creating a group, setting its rules and moving devices into it never
// touches a device's configuration or its connection, so nothing here can
// disconnect anybody.
//
// Data comes from /api/policy/groups, which returns every group with its
// members plus the full peer list, so one call is enough to render the cards
// and to offer the full device list in the "add device" dialog.

let policyGroups = [];
let policyPeers = [];
let editingGroupID = null;   // null while creating
let deviceTargetID = null;   // group receiving devices in the device dialog

// RULES drives both the create/edit modal and the per-group rule switches, so
// the four switches cannot drift apart between the two places they appear.
const RULES = [
  { field: 'allow_inter_device', el: 'rule-inter', label: 'Inter-device traffic' },
  { field: 'allow_p2p_mesh',     el: 'rule-p2p',  label: 'P2P mesh' },
  { field: 'allow_trp',          el: 'rule-trp',   label: 'TRP port mapping' },
  { field: 'allow_wg_access',    el: 'rule-wg',    label: 'WireGuard internet' }
];

function deviceLabel(p) {
  if (p.device_name) return p.device_name;
  return (p.public_key || '').slice(0, 8) + '…';
}

function deviceMeta(p) {
  const bits = [];
  if (p.allowed_ip) bits.push(p.allowed_ip);
  if (p.device_id) bits.push('id ' + p.device_id);
  return bits.join('  ·  ');
}

// ruleSwitch renders one toggle. The change is saved immediately against the
// group's own id, which is what makes a rule editable straight from the card.
// The built-in group renders a static badge instead: it is the always-open
// escape hatch and the server refuses to edit it.
function ruleSwitch(rule, enabled, groupID, builtin) {
  if (builtin) {
    return '<span class="chip active"><span class="chip-dot"></span>always on</span>';
  }
  return `<label class="policy-switch" title="${escapeHtml(rule.label)}">
    <input type="checkbox" ${enabled ? 'checked' : ''}
           onchange="saveRule('${groupID}', '${rule.field}', this.checked)">
    <span class="slider"></span>
  </label>`;
}

async function loadPolicy() {
  const data = await fetchAPI('/api/policy/groups');
  if (!data) {
    showToast('Could not load policy groups', 'error');
    return;
  }
  policyGroups = data.groups || [];
  policyPeers = data.peers || [];
  renderStats(data.drop_count || {});
  renderGroups();
}

// renderStats surfaces the two things an operator needs to confirm: that no
// policy is in force, and that a policy is actually blocking something.
function renderStats(drops) {
  const custom = policyGroups.filter(g => g.id !== 'default');
  const grouped = custom.reduce((n, g) => n + ((g.devices || []).length), 0);
  const blocked = (drops.inter_device || 0) + (drops.internet || 0);

  setText('stat-groups', policyGroups.length);
  setText('stat-grouped', grouped);
  setText('stat-dropped', blocked.toLocaleString());
  setText('stat-default', policyPeers.length - grouped);

  // A custom group that nobody is in changes nothing yet, so the header says
  // so rather than implying traffic is being filtered.
  const active = custom.some(g => (g.devices || []).length > 0);
  setText('policy-status', active
    ? custom.length + ' group' + (custom.length === 1 ? '' : 's') + ' active'
    : 'No restrictions');

  const badge = document.getElementById('nav-policy-count');
  if (badge) {
    badge.textContent = custom.length;
    badge.style.display = custom.length ? '' : 'none';
  }
}

function setText(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

function renderGroups() {
  const host = document.getElementById('policy-groups');
  if (!host) return;

  if (!policyGroups.length) {
    host.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">
      <div class="empty-state-icon"><svg viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg></div>
      <h3>No policy groups yet</h3>
      <p>Every device is in the Default Global Group and behaves exactly as it does now. Create a group to start restricting things.</p>
    </div></div></div>`;
    return;
  }

  host.innerHTML = policyGroups.map(renderGroupCard).join('');
}

function renderGroupCard(g) {
  const builtin = !!g.builtin;
  const devices = g.devices || [];

  const rules = RULES.map(r => `
    <div class="policy-rule">
      <div>
        <div class="policy-rule-label">${escapeHtml(r.label)}</div>
      </div>
      ${ruleSwitch(r, g[r.field], g.id, builtin)}
    </div>`).join('');

  const deviceRows = devices.length ? devices.map(d => `
    <div class="policy-device">
      <div>
        <div class="policy-device-name">${escapeHtml(deviceLabel(d))}</div>
        <div class="policy-device-meta">${escapeHtml(deviceMeta(d))}</div>
      </div>
      ${builtin ? '' : `<button class="btn btn-sm btn-outline" onclick="removeDevice('${g.id}', '${d.public_key}')">Remove</button>`}
    </div>`).join('')
    : `<div class="policy-device-meta" style="padding:8px 0">No devices in this group.</div>`;

  const actions = builtin ? '' : `
    <div class="card-footer" style="display:flex;justify-content:space-between;gap:8px">
      <button class="btn btn-sm btn-primary" onclick="openDevices('${g.id}')">+ Add Device${devices.length === 1 ? '' : 's'}</button>
      <button class="btn btn-sm btn-danger" onclick="deleteGroup('${g.id}')">Delete</button>
    </div>`;

  return `<div class="card">
    <div class="card-header">
      <div class="policy-group-head">
        <div>
          <div class="card-title">${escapeHtml(g.name)}</div>
          <div class="card-subtitle">${builtin ? 'Every device not moved elsewhere' : devices.length + ' device' + (devices.length === 1 ? '' : 's')}</div>
        </div>
        ${builtin ? '<span class="chip active"><span class="chip-dot"></span>built-in</span>' : ''}
      </div>
    </div>
    <div class="card-body">
      <div class="policy-rule-list">${rules}</div>
      <div style="margin-top:18px">
        <div class="form-label" style="margin-bottom:6px">Devices in this group</div>
        ${deviceRows}
      </div>
    </div>
    ${actions}
  </div>`;
}

// saveRule applies one switch directly from the card.
async function saveRule(groupID, field, enabled) {
  try {
    // Only the one field is sent: the server keeps every rule the caller did
    // not mention, so flipping one switch never disturbs the others.
    await postJSON('/api/policy/group/update', { id: groupID, [field]: enabled });
    showToast('Policy updated', 'success');
    await loadPolicy();
  } catch (e) {
    showToast(e.message, 'error');
    await loadPolicy();
  }
}

// ---- create / edit dialog -------------------------------------------------

function openCreate() {
  editingGroupID = null;
  document.getElementById('policy-modal-title').textContent = 'Create Policy Group';
  document.getElementById('policy-submit').textContent = 'Create group';
  document.getElementById('policy-name').value = '';
  // A new group starts with every rule off: creating one is always a
  // restricting action.
  RULES.forEach(r => { document.getElementById(r.el).checked = false; });
  hideError('policy-error');
  document.getElementById('policy-modal').classList.add('open');
  document.getElementById('policy-name').focus();
}

function closeModal() {
  document.getElementById('policy-modal').classList.remove('open');
}

async function submitGroup() {
  const name = document.getElementById('policy-name').value.trim();
  if (!name) {
    showError('policy-error', 'Give the group a name');
    return;
  }
  const body = { name };
  RULES.forEach(r => { body[r.field] = document.getElementById(r.el).checked; });

  const btn = document.getElementById('policy-submit');
  btn.disabled = true;
  try {
    await postJSON('/api/policy/group/create', body);
    closeModal();
    showToast('Policy group created', 'success');
    await loadPolicy();
  } catch (e) {
    showError('policy-error', e.message);
  } finally {
    btn.disabled = false;
  }
}

async function deleteGroup(groupID) {
  const g = policyGroups.find(x => x.id === groupID);
  if (!g) return;
  if ((g.devices || []).length > 0) {
    showToast('Move the devices out of this group before deleting it', 'error');
    return;
  }
  if (!confirm('Delete the policy group "' + g.name + '"?')) return;
  try {
    await postJSON('/api/policy/group/delete', { id: groupID });
    showToast('Policy group deleted', 'success');
    await loadPolicy();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

// ---- add devices dialog ---------------------------------------------------

function openDevices(groupID) {
  deviceTargetID = groupID;
  const g = policyGroups.find(x => x.id === groupID);
  document.getElementById('device-modal-title').textContent =
    'Add Devices to ' + (g ? g.name : 'group');
  hideError('device-error');

  const inGroup = new Set((g && g.devices || []).map(d => d.public_key));
  const picker = document.getElementById('device-picker');

  if (!policyPeers.length) {
    picker.innerHTML = '<div class="policy-device-meta" style="padding:12px 0">No devices exist yet. Add a peer first.</div>';
  } else {
    picker.innerHTML = policyPeers.map(p => {
      const here = inGroup.has(p.public_key);
      // A device already in this group cannot be re-added; one in another
      // group can, which moves it here.
      const where = here ? 'already in this group' : (p.group_name || 'Default Global Group');
      return `<label class="policy-picker-row${here ? ' disabled' : ''}">
        <input type="checkbox" value="${escapeHtml(p.public_key)}" ${here ? 'disabled' : ''}>
        <span style="flex:1">
          <span class="policy-device-name">${escapeHtml(deviceLabel(p))}</span>
          <span class="policy-device-meta" style="display:block">${escapeHtml(deviceMeta(p))}  ·  ${escapeHtml(where)}</span>
        </span>
      </label>`;
    }).join('');
  }
  document.getElementById('device-modal').classList.add('open');
}

function closeDeviceModal() {
  document.getElementById('device-modal').classList.remove('open');
}

async function submitDevices() {
  const boxes = document.querySelectorAll('#device-picker input[type=checkbox]:checked');
  const devices = Array.from(boxes).map(b => b.value);
  if (!devices.length) {
    showError('device-error', 'Select at least one device');
    return;
  }
  const btn = document.getElementById('device-submit');
  btn.disabled = true;
  try {
    await postJSON('/api/policy/group/assign', { id: deviceTargetID, devices });
    closeDeviceModal();
    showToast('Moved ' + devices.length + ' device' + (devices.length === 1 ? '' : 's') + ' into the group', 'success');
    await loadPolicy();
  } catch (e) {
    showError('device-error', e.message);
  } finally {
    btn.disabled = false;
  }
}

async function removeDevice(groupID, publicKey) {
  try {
    await postJSON('/api/policy/group/unassign', { id: groupID, devices: [publicKey] });
    showToast('Device returned to the Default Global Group', 'success');
    await loadPolicy();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

function showError(id, msg) {
  const box = document.getElementById(id);
  document.getElementById(id + '-text').textContent = msg;
  box.style.display = 'flex';
}

function hideError(id) {
  document.getElementById(id).style.display = 'none';
}

document.addEventListener('DOMContentLoaded', () => {
  loadPolicy();
  loadSidebarStatus();
});