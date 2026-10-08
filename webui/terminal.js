'use strict';

// The dashboard's Terminal window: one xterm.js screen wired to the server's
// CLI over /api/ws/console. Same session the ssh gateway runs — line editing,
// history and completion all happen server-side, this file only moves bytes.

let term = null;
let fitAddon = null;
let ws = null;
let state = 'connecting';
let attempts = 0;
let reconnectTimer = null;

const stateEl = document.getElementById('termState');

function setState(next, label) {
  state = next;
  if (!stateEl) return;
  stateEl.className = 'term-state ' + (next === 'online' ? '' : next === 'connecting' || next === 'ended' ? 'connecting' : 'down');
  stateEl.textContent = label || next;
}

function fit() {
  if (!fitAddon) return;
  try { fitAddon.fit(); } catch (e) { /* layout not ready yet */ }
}

function send(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function onData(data) {
  if (state === 'ended') {
    // The session is over; any Enter starts a fresh one, like reconnecting
    // to a dropped ssh connection by hand.
    if (data.indexOf('\r') >= 0 || data.indexOf('\n') >= 0) connect();
    return;
  }
  if (state === 'connecting' || state === 'down') return;
  send({ type: 'input', data });
}

function connect() {
  clearTimeout(reconnectTimer);
  if (ws) {
    const old = ws;
    ws = null;
    try { old.close(); } catch (e) { /* already gone */ }
  }

  setState('connecting');
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const sock = new WebSocket(proto + '//' + location.host + '/api/ws/console');
  ws = sock;

  sock.onopen = () => {
    if (ws !== sock) return;
    attempts = 0;
    setState('online', 'connected');
    fit();
    send({ type: 'resize', cols: term.cols, rows: term.rows });
    term.focus();
  };

  sock.onmessage = e => {
    if (ws !== sock) return;
    let msg;
    try { msg = JSON.parse(e.data); } catch (err) { term.write(e.data); return; }
    if (msg.type === 'output') {
      term.write(msg.data);
    } else if (msg.type === 'closed') {
      setState('ended', 'session ended');
      term.write('\r\n\x1b[2mSession ended — press Enter to start a new one.\x1b[0m\r\n');
    }
  };

  sock.onclose = () => {
    if (ws !== sock) return; // superseded by a manual reconnect
    ws = null;
    if (state === 'ended') return; // server said goodbye; Enter restarts
    attempts += 1;
    setState('down', 'reconnecting…');
    term.write('\r\n\x1b[2m[disconnected — reconnecting]\x1b[0m\r\n');
    reconnectTimer = setTimeout(connect, Math.min(1000 * attempts, 10000));
  };

  sock.onerror = () => { /* onclose follows and handles it */ };
}

function initTerminal() {
  term = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    fontFamily: 'Menlo, Monaco, Consolas, "DejaVu Sans Mono", monospace',
    scrollback: 5000,
    theme: {
      background: '#0e141b',
      foreground: '#e4e6f0',
      cursor: '#3fd07f',
      selectionBackground: 'rgba(63, 208, 127, .3)'
    }
  });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('term'));
  fit();
  term.onData(onData);
  term.onResize(size => send({ type: 'resize', cols: size.cols, rows: size.rows }));

  // Track the panel, not just the window: the WinBox frame is draggable and
  // resizable, and that does not fire window.resize inside the iframe.
  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(() => fit()).observe(document.getElementById('term'));
  }
  window.addEventListener('resize', fit);
}

initTerminal();
setState('connecting');
connect();
