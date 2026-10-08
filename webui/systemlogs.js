'use strict';

// System Logs: tails the server's in-memory log ring over /api/logs the same
// way `tail -f` follows a file. The raw entries stay in an array; the filter
// box is a grep over them, so toggling it never refetches.

const LOG_CAP = 5000;   // rows kept in the DOM
const LOG_POLL = 1000;  // ms

let logEntries = [];    // {id, ts, line} — newest last
let logLatest = 0;      // last id the server has given us
let logTimer = null;
let logFetching = false;

const logBody = document.getElementById('logBody');
const logFilter = document.getElementById('logFilter');
const logFollow = document.getElementById('logFollow');
const logState = document.getElementById('logState');
const logCount = document.getElementById('logCount');
const logClearBtn = document.getElementById('logClearBtn');

function logSetState(state, label) {
  logState.className = 'term-state ' + (state === 'online' ? '' : state === 'connecting' ? 'connecting' : 'down');
  logState.textContent = label || state;
}

function logLevelClass(line) {
  if (line.indexOf('ERROR') >= 0 || line.indexOf('error:') >= 0) return 'log-err';
  if (line.indexOf('WARN') >= 0) return 'log-warn';
  return '';
}

function logFormatTime(ts) {
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function logMatches(entry) {
  const q = logFilter.value;
  if (!q) return true;
  return entry.line.toLowerCase().indexOf(q.toLowerCase()) >= 0;
}

function logRow(entry) {
  const row = document.createElement('div');
  row.className = 'log-row ' + logLevelClass(entry.line);
  const ts = document.createElement('span');
  ts.className = 'log-ts';
  ts.textContent = logFormatTime(entry.ts);
  const msg = document.createElement('span');
  msg.className = 'log-msg';
  msg.textContent = entry.line;
  row.appendChild(ts);
  row.appendChild(msg);
  return row;
}

function logAtBottom() {
  return logBody.scrollHeight - logBody.scrollTop - logBody.clientHeight < 40;
}

// Full render — used for filter changes, clear and fresh loads. Appends only
// add rows when nothing changed behind us.
function logRender() {
  const shown = logEntries.filter(logMatches);
  const frag = document.createDocumentFragment();
  for (const e of shown.slice(-LOG_CAP)) frag.appendChild(logRow(e));
  logBody.textContent = '';
  if (shown.length === 0) {
    const hint = document.createElement('div');
    hint.className = 'log-empty';
    hint.textContent = logEntries.length === 0
      ? 'Waiting for log output…'
      : 'No lines match "' + logFilter.value + '"';
    logBody.appendChild(hint);
  } else {
    logBody.appendChild(frag);
  }
  logCount.textContent = shown.length === logEntries.length
    ? logEntries.length + ' lines'
    : shown.length + ' of ' + logEntries.length + ' lines';
  if (logFollow.checked) logScrollDown();
}

function logAppend(entries) {
  const wasAtBottom = logAtBottom();
  const frag = document.createDocumentFragment();
  let added = 0;
  for (const e of entries) {
    logEntries.push(e);
    if (logMatches(e)) {
      frag.appendChild(logRow(e));
      added++;
    }
  }
  if (logEntries.length > LOG_CAP) logEntries = logEntries.slice(-LOG_CAP);
  if (added > 0) {
    const empty = logBody.querySelector('.log-empty');
    if (empty) empty.remove();
    logBody.appendChild(frag);
  }
  logCount.textContent = logFilter.value
    ? logBody.querySelectorAll('.log-row').length + ' of ' + logEntries.length + ' lines'
    : logEntries.length + ' lines';
  // Follow keeps the view pinned unless the user scrolled up to read.
  if (logFollow.checked && (wasAtBottom || added > 0)) logScrollDown();
}

function logScrollDown() {
  logBody.scrollTop = logBody.scrollHeight;
}

async function logPoll() {
  if (logFetching || document.hidden) return;
  logFetching = true;
  try {
    const r = await fetchAPI('/api/logs?since=' + logLatest + '&limit=1000');
    if (r && Array.isArray(r.entries)) {
      logSetState('online', 'live');
      if (r.entries.length > 0 && r.entries[0].id > logLatest + 1) {
        // Lines were missed (slow poll or a full ring): reload instead of
        // showing a gap as if nothing had happened.
        await logReload();
      } else if (r.entries.length > 0) {
        logLatest = r.latest;
        logAppend(r.entries);
      } else {
        logLatest = r.latest;
      }
    } else {
      logSetState('down', 'no data');
    }
  } catch (e) {
    logSetState('down', 'reconnecting…');
  } finally {
    logFetching = false;
  }
}

// Full reload from the beginning of the buffer — start, Clear, or a gap.
async function logReload() {
  try {
    const r = await fetchAPI('/api/logs?since=0&limit=2000');
    if (!r || !Array.isArray(r.entries)) {
      logSetState('down', 'reconnecting…');
      return;
    }
    logSetState('online', 'live');
    logEntries = r.entries;
    logLatest = r.latest;
    logRender();
  } catch (e) {
    logSetState('down', 'reconnecting…');
  }
}

logFilter.addEventListener('input', logRender);

// Scrolling away from the bottom means the user is reading: stop following.
// Scrolling back re-arms it — the same gesture as tail -f in a pager.
logBody.addEventListener('scroll', () => {
  if (!logAtBottom() && logFollow.checked) logFollow.checked = false;
  else if (logAtBottom() && !logFollow.checked) logFollow.checked = true;
});
logFollow.addEventListener('change', () => { if (logFollow.checked) logScrollDown(); });

logClearBtn.addEventListener('click', async () => {
  try {
    await fetchAPI('/api/logs/clear', { method: 'POST', body: '{}' });
  } catch (e) { /* the clear below still resets the view */ }
  await logReload();
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) logPoll();
});

logReload().then(() => {
  logTimer = setInterval(logPoll, LOG_POLL);
});
