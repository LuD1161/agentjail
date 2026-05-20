// agentjail Track C hook — works under Node (NODE_OPTIONS=--require) AND
// under Bun (BUN_OPTIONS=--preload). Verified May 2026 that BUN_OPTIONS=--preload
// fires inside compiled Bun single-file executables like Claude Code.
//
// Scope: log to the daemon (best-effort, fire-and-forget) for
//   - child_process.{spawn,spawnSync,exec,execSync,execFile,execFileSync,fork}
//   - worker_threads.Worker  (and propagate hook into the worker; Node only)
//   - http.request / https.request
//   - undici.fetch / undici.request  (Node only; via Module._load)
//   - globalThis.fetch  (Node 18+ and Bun)
//   - tls.connect  (SNI-only, for non-HTTP TLS)
//   - fs / fs.promises mutation methods
//   - Bun.write, Bun.spawn, Bun.spawnSync  (Bun only)
//
// No policy decisions yet — Phase 2 wires OPA-WASM here.

'use strict';

const IS_BUN = typeof globalThis.Bun !== 'undefined' && typeof globalThis.Bun.version === 'string';
const RUNTIME = IS_BUN ? 'bun' : 'node';

const net = require('net');
const fs = require('fs');
const crypto = require('crypto');

const SID = process.env.AGENTJAIL_SESSION_ID || '';
const SOCK = process.env.AGENTJAIL_SOCK || '';
const ENFORCE = process.env.AGENTJAIL_ENFORCE === '1';
const HOOK_PATH = typeof __filename !== 'undefined' ? __filename : '';

// Sync RPC budget. The daemon's own write deadline is 50ms; we add headroom
// for spawn overhead + socket connect. Anything past this and we fail-closed.
const SYNC_RPC_BUDGET_MS = 150;

if (!SID || !SOCK) {
  // Not running under agentjail; do nothing.
  return;
}

// ---------------------------------------------------------------------------
// Fire-and-forget event emitter
//
// The async path writes events through a long-lived Unix socket that we
// `unref()` so it never holds the event loop open. Problem: a short-lived
// driver that does `spawnSync(...); process.exit(0)` exits before Node's
// event loop drains the pending connect + write. Without a synchronous
// safety net those events are silently lost (see adversarial fixture findings).
//
// Mitigation: every emitted line is also queued in `pendingLines`. We
// optimistically drop lines from the queue once a `write()` callback
// confirms they hit the kernel buffer. On `process.on('exit')` — the
// last synchronous hook before Node tears down — anything still pending
// is drained via a SYNCHRONOUS spawnSync of a small node helper that
// connects, writes, and exits. The wire shape is unchanged (one JSON
// line per event); only the delivery path differs.
// ---------------------------------------------------------------------------

let sock = null;
let connecting = false;
let backlog = [];
const MAX_BACKLOG = 1024;
// Lines emitted but not yet confirmed flushed. Populated for EVERY emit
// (including ones we just `sock.write()`'d) and drained when the write
// callback fires. On exit, whatever is left here gets a sync flush.
const pendingLines = [];
const MAX_PENDING = MAX_BACKLOG;
// Wall budget for the sync exit-flush. 300ms wall ceiling: the inner
// helper's own deadline is 250ms, leaving 50ms headroom for spawn cost.
// Tight enough that a wedged daemon will not visibly hang shutdown, loose
// enough to absorb node v18's slower socket-close path on cold/busy
// machines (observed up to ~100ms in repro runs).
const EXIT_FLUSH_BUDGET_MS = 300;

function trackPending(line) {
  if (pendingLines.length < MAX_PENDING) pendingLines.push(line);
}
function ackPending(line) {
  // O(n) but n is tiny in steady state (writes ack within microseconds);
  // the cost only matters if the daemon is wedged, in which case the
  // backlog cap dominates anyway.
  const i = pendingLines.indexOf(line);
  if (i >= 0) pendingLines.splice(i, 1);
}

function ensureConn() {
  if (sock || connecting) return;
  connecting = true;
  const c = net.createConnection(SOCK);
  c.on('connect', () => {
    sock = c;
    connecting = false;
    const flush = backlog;
    backlog = [];
    for (const line of flush) {
      try { sock.write(line, () => ackPending(line)); } catch (_) { /* swallow */ }
    }
  });
  c.on('error', () => { sock = null; connecting = false; });
  c.on('close', () => { sock = null; });
  c.unref();
}

function emit(frame) {
  frame.pid = process.pid;
  frame.ppid = process.ppid;
  frame.track = 'node';
  const line = JSON.stringify(frame) + '\n';
  trackPending(line);
  if (sock) {
    try { sock.write(line, () => ackPending(line)); return; } catch (_) { /* fallthrough */ }
  }
  if (backlog.length < MAX_BACKLOG) backlog.push(line);
  ensureConn();
}
function safeEmit(frame) { try { emit(frame); } catch (_) { /* never throw from a hook */ } }

ensureConn();

// ---------------------------------------------------------------------------
// child_process
// ---------------------------------------------------------------------------

const child_process = require('child_process');

// Capture originals BEFORE we patch them so the sync RPC path (which uses
// spawnSync of a small inline JS one-liner) does not recurse through our own
// wrappers. The same instance is reused by patchFsObject's sync deny path.
const ORIG_SPAWN_SYNC = child_process.spawnSync;

// ---------------------------------------------------------------------------
// Sync decision RPC (Phase 2.5)
//
// When ENFORCE is on, before a captured fs mutation or exec call we send the
// frame with a fresh req_id and block on exactly one JSON line back. The
// daemon serializes responses under a per-connection write mutex, so we open
// a fresh short-lived unix socket per call rather than multiplex on the
// long-lived event socket — this mirrors the C shim approach and removes
// any cross-request head-of-line blocking risk.
//
// Returns { action, rule_id, reason } on success, or null on hard failure.
// On null, callers in ENFORCE mode MUST fail-closed (write+exec are
// fail_closed per TODO.md Phase 2.5).
// ---------------------------------------------------------------------------

function newReqID() { return crypto.randomBytes(6).toString('hex'); }

// Inline helper that runs as `node -e <script> -- <sock> <frame>`:
// opens unix socket, writes one frame line, reads one JSON line, prints it.
// Bounded internally by a 100ms timeout so the outer spawnSync wall budget
// of SYNC_RPC_BUDGET_MS has headroom for spawn cost.
// NB: With \`node -e SCRIPT -- a b\` argv is [execPath, 'a', 'b'] — there is
// NO synthetic '[eval]' entry inserted. So sock = argv[1], frame = argv[2].
const SYNC_RPC_HELPER = `
const net = require('net');
const sock = process.argv[1];
const frame = process.argv[2];
const c = net.createConnection(sock);
let buf = '';
let done = false;
const finish = (out, code) => {
  if (done) return; done = true;
  try { c.destroy(); } catch (_) {}
  if (out) process.stdout.write(out);
  process.exit(code);
};
const t = setTimeout(() => finish('', 2), 100);
c.on('connect', () => { try { c.write(frame); } catch (e) { clearTimeout(t); finish('', 3); } });
c.on('data', (d) => {
  buf += d.toString('utf8');
  const nl = buf.indexOf('\\n');
  if (nl >= 0) { clearTimeout(t); finish(buf.slice(0, nl + 1), 0); }
});
c.on('error', () => { clearTimeout(t); finish('', 4); });
c.on('end', () => { clearTimeout(t); finish('', 5); });
`;

function syncDecide(frame) {
  if (!ENFORCE) return null; // never block when not enforcing
  // Suppress any nested emit/sync-check that our helper's spawnSync would
  // otherwise trigger. Under Bun, ORIG_SPAWN_SYNC delegates to B.spawnSync,
  // and we patched that too — the counter tells the Bun patch to skip.
  __aw_inCpExec++;
  try {
    const reqId = newReqID();
    const body = JSON.stringify({
      ...frame,
      pid: process.pid,
      ppid: process.ppid,
      track: 'node',
      req_id: reqId,
    }) + '\n';
    const r = ORIG_SPAWN_SYNC.call(child_process, process.execPath, [
      '-e', SYNC_RPC_HELPER, '--', SOCK, body,
    ], {
      encoding: 'utf8',
      timeout: SYNC_RPC_BUDGET_MS,
      windowsHide: true,
      // Inherit a minimal env — the helper only needs PATH-less node, but
      // pass through so dynamic loaders still work.
      env: process.env,
    });
    if (r.error || r.status !== 0 || !r.stdout) return null;
    let resp;
    try { resp = JSON.parse(r.stdout.trim()); } catch (_) { return null; }
    if (!resp || typeof resp.action !== 'string') return null;
    if (resp.req_id && resp.req_id !== reqId) return null; // mismatched response
    return resp;
  } catch (_) {
    return null;
  } finally {
    __aw_inCpExec--;
  }
}

// Build a Node-style EACCES error for fs.* deny. Mirrors libuv's shape so
// callers that branch on `err.code === 'EACCES'` behave correctly.
function makeFsDenyError(method, path, rule_id, reason) {
  const tag = rule_id ? ' [agentjail ' + rule_id + ']' : ' [agentjail]';
  const msg = "EACCES: permission denied, " + method + " '" + (path || '') + "'" + tag +
              (reason ? ' (' + reason + ')' : '');
  const e = new Error(msg);
  e.code = 'EACCES';
  e.errno = -13;
  e.syscall = method;
  if (path != null) e.path = path;
  return e;
}

function makeExecDenyError(op, program, rule_id, reason) {
  const msg = 'agentjail: ' + op + ' blocked by policy' +
              (rule_id ? ' [' + rule_id + ']' : '') +
              (program ? " for '" + program + "'" : '') +
              (reason ? ': ' + reason : '');
  const e = new Error(msg);
  e.code = 'EACCES';
  e.errno = -13;
  e.syscall = op;
  return e;
}

function describeSpawn(cmd, args, opts) {
  return {
    program: String(cmd),
    argv: [String(cmd), ...(Array.isArray(args) ? args.map(String) : [])],
    cwd: (opts && opts.cwd) || process.cwd(),
  };
}

const cpPatches = {
  spawn: (cmd, args, opts) => ({ op: 'spawn', attrs: describeSpawn(cmd, args, opts) }),
  spawnSync: (cmd, args, opts) => ({ op: 'spawnSync', attrs: describeSpawn(cmd, args, opts) }),
  exec: (cmd, opts) => ({ op: 'exec', attrs: { command: String(cmd), cwd: (opts && opts.cwd) || process.cwd() } }),
  execSync: (cmd, opts) => ({ op: 'execSync', attrs: { command: String(cmd), cwd: (opts && opts.cwd) || process.cwd() } }),
  execFile: (file, args, opts) => ({ op: 'execFile', attrs: describeSpawn(file, args, opts) }),
  execFileSync: (file, args, opts) => ({ op: 'execFileSync', attrs: describeSpawn(file, args, opts) }),
  fork: (modulePath, args) => ({ op: 'fork', attrs: { module: String(modulePath), argv: Array.isArray(args) ? args.map(String) : [] } }),
};

// Re-entrancy guard for Bun: under Bun, node:child_process.spawnSync delegates
// to Bun.spawnSync, so without this both patches fire for one logical call.
// Strategy chosen: in-process re-entrancy flag flipped around the outer
// child_process patch; the Bun.spawn* patches below check it and skip emit.
// Simpler than per-call nonces and works because both patches run on the
// same single JS thread (sync) or microtask boundary (async kickoff).
let __aw_inCpExec = 0;

for (const [name, describe] of Object.entries(cpPatches)) {
  const orig = child_process[name];
  if (typeof orig !== 'function') continue;
  child_process[name] = function (...args) {
    const ev = describe(...args);
    safeEmit({ hook: 'exec', op: ev.op, attrs: ev.attrs });
    // Bump the re-entrancy counter BEFORE the sync RPC so the helper's own
    // ORIG_SPAWN_SYNC call (and any Bun.spawn delegation underneath) is
    // recognized as a nested agentjail call and short-circuits both emit
    // and sync-check.
    __aw_inCpExec++;
    try {
      if (ENFORCE) {
        const resp = syncDecide({ hook: 'exec', op: ev.op, attrs: ev.attrs });
        const decision = resp && resp.action;
        if (!resp || decision === 'deny' || decision === 'ask') {
          const ruleId = resp ? resp.rule_id : '';
          const reason = resp ? (resp.reason || '') :
            'sync RPC failed; fail-closed (exec)';
          const askNote = decision === 'ask' ? 'ask-mode not implemented; treated as deny' : reason;
          throw makeExecDenyError(ev.op, ev.attrs && ev.attrs.program, ruleId, askNote);
        }
      }
      return orig.apply(this, args);
    } finally {
      __aw_inCpExec--;
    }
  };
}

// ---------------------------------------------------------------------------
// worker_threads.Worker — wrap constructor to propagate hook into the worker
// ---------------------------------------------------------------------------

try {
  const wt = require('worker_threads');
  const OrigWorker = wt.Worker;
  class AgentjailWorker extends OrigWorker {
    constructor(filename, options) {
      const opts = options ? { ...options } : {};
      const flag = IS_BUN ? '--preload' : '--require';
      const execArgv = Array.isArray(opts.execArgv) ? [...opts.execArgv] : [...process.execArgv];
      const alreadyInjected = execArgv.some((a, i) =>
        a === flag && execArgv[i + 1] === HOOK_PATH
      );
      if (HOOK_PATH && !alreadyInjected) {
        execArgv.push(flag, HOOK_PATH);
      }
      opts.execArgv = execArgv;
      if (!opts.env) opts.env = process.env;
      safeEmit({ hook: 'exec', op: 'worker', attrs: { filename: String(filename) } });
      super(filename, opts);
    }
  }
  wt.Worker = AgentjailWorker;
} catch (_) { /* worker_threads may not exist in extremely old Node */ }

// ---------------------------------------------------------------------------
// http / https.request  (already in Phase 0; kept here)
// ---------------------------------------------------------------------------

const http = require('http');
const https = require('https');

function describeHttpRequest(scheme, arg0, arg1) {
  let url, opts;
  if (typeof arg0 === 'string' || arg0 instanceof URL) {
    url = arg0;
    opts = (typeof arg1 === 'object' && arg1 !== null && typeof arg1 !== 'function') ? arg1 : {};
  } else {
    opts = arg0 || {};
  }
  let host, port, path, method;
  if (url) {
    const u = typeof url === 'string' ? new URL(url) : url;
    host = u.hostname; port = u.port || (u.protocol === 'https:' ? 443 : 80);
    path = u.pathname + u.search;
  }
  host = host || opts.hostname || opts.host || 'localhost';
  port = port || opts.port || (scheme === 'https' ? 443 : 80);
  path = path || opts.path || '/';
  method = (opts.method || 'GET').toUpperCase();
  return {
    method, scheme, host, port: Number(port), path,
    client_lib: scheme,
    header_names: opts.headers ? Object.keys(opts.headers).map((h) => String(h).toLowerCase()) : [],
  };
}

const origHttpReq = http.request;
http.request = function (...args) {
  safeEmit({ hook: 'http', op: 'request', attrs: describeHttpRequest('http', args[0], args[1]) });
  return origHttpReq.apply(this, args);
};
const origHttpsReq = https.request;
https.request = function (...args) {
  safeEmit({ hook: 'http', op: 'request', attrs: describeHttpRequest('https', args[0], args[1]) });
  return origHttpsReq.apply(this, args);
};

// ---------------------------------------------------------------------------
// global fetch  (Node 18+ — backed by undici internally)
// ---------------------------------------------------------------------------

function describeFetchCall(input, init) {
  let url;
  if (typeof input === 'string') url = input;
  else if (input instanceof URL) url = input.href;
  else if (input && typeof input.url === 'string') url = input.url; // Request object
  else url = String(input);
  let u;
  try { u = new URL(url); } catch (_) { return { client_lib: 'fetch', url }; }
  const method = (init && init.method) || (input && input.method) || 'GET';
  const headers = (init && init.headers) || (input && input.headers) || null;
  let header_names = [];
  if (headers) {
    if (typeof headers.forEach === 'function' && !Array.isArray(headers)) {
      // Headers instance
      try { headers.forEach((_, k) => header_names.push(String(k).toLowerCase())); } catch (_) {}
    } else if (Array.isArray(headers)) {
      header_names = headers.map(([k]) => String(k).toLowerCase());
    } else if (typeof headers === 'object') {
      header_names = Object.keys(headers).map((k) => String(k).toLowerCase());
    }
  }
  return {
    method: String(method).toUpperCase(),
    scheme: u.protocol.replace(':', ''),
    host: u.hostname,
    port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)),
    path: u.pathname + u.search,
    client_lib: 'fetch',
    header_names,
  };
}

if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = function (input, init) {
    safeEmit({ hook: 'http', op: 'fetch', attrs: describeFetchCall(input, init) });
    return origFetch.apply(this, arguments);
  };
}

// ---------------------------------------------------------------------------
// undici  (require('undici') — used by some libs explicitly)
// Node-only: Bun doesn't expose Module._load and uses its own resolver.
// ---------------------------------------------------------------------------

if (!IS_BUN) try { (() => {
const Module = require('module');
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const ret = origLoad.apply(this, arguments);
  if (request === 'undici' && ret && !ret.__agentjail_wrapped) {
    try {
      if (typeof ret.fetch === 'function') {
        const orig = ret.fetch;
        ret.fetch = function (...args) {
          safeEmit({ hook: 'http', op: 'fetch', attrs: { ...describeFetchCall(args[0], args[1]), client_lib: 'undici' } });
          return orig.apply(this, args);
        };
      }
      if (typeof ret.request === 'function') {
        const orig = ret.request;
        ret.request = function (...args) {
          const url = args[0];
          let attrs;
          if (typeof url === 'string' || url instanceof URL) {
            attrs = describeFetchCall(url, args[1]);
            attrs.client_lib = 'undici';
          } else {
            attrs = { client_lib: 'undici', method: 'GET' };
          }
          safeEmit({ hook: 'http', op: 'request', attrs });
          return orig.apply(this, args);
        };
      }
      ret.__agentjail_wrapped = true;
    } catch (_) { /* never throw from a hook */ }
  }
  return ret;
};
})(); } catch (_) { /* Bun or other runtime without Module._load */ }

// ---------------------------------------------------------------------------
// tls.connect — best-effort; emits SNI host + port only.
// ---------------------------------------------------------------------------

try {
  const tls = require('tls');
  const origConnect = tls.connect;
  tls.connect = function (...args) {
    let host, port, servername;
    if (typeof args[0] === 'object' && args[0] !== null) {
      const o = args[0];
      host = o.host || o.hostname; port = o.port; servername = o.servername;
    } else {
      port = args[0];
      const a1 = args[1];
      if (typeof a1 === 'string') host = a1;
      else if (a1 && typeof a1 === 'object') { host = a1.host || a1.hostname; servername = a1.servername; }
    }
    safeEmit({ hook: 'tls', op: 'connect', attrs: { host: host || null, port: port ? Number(port) : null, servername: servername || null } });
    return origConnect.apply(this, args);
  };
} catch (_) { /* tls always exists; guard anyway */ }

// ---------------------------------------------------------------------------
// fs.*  and  fs.promises.*  mutation methods
// ---------------------------------------------------------------------------

const FS_MUTATION_METHODS = [
  'writeFile', 'writeFileSync',
  'appendFile', 'appendFileSync',
  'open', 'openSync',                     // logged for all flags; policy will filter on flag bits later
  'unlink', 'unlinkSync',
  'rename', 'renameSync',
  'rmdir', 'rmdirSync',
  'mkdir', 'mkdirSync',
  'chmod', 'chmodSync',
  'chown', 'chownSync',
  'symlink', 'symlinkSync',
  'link', 'linkSync',
  'truncate', 'truncateSync',
  'cp', 'cpSync',
  'rm', 'rmSync',
  'copyFile', 'copyFileSync',
];

// writeFile/appendFile (sync + async) accept either a path or an open file
// descriptor (integer) as first arg. We need to surface fd writes as a
// distinct op so the policy layer doesn't try to match an integer as a path.
const FS_FD_CAPABLE = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync']);

function describeFsCall(method, args) {
  // Most methods: path is args[0]; rename/cp/link/copyFile/symlink: (src, dst)
  const a0 = args[0];
  const a1 = args[1];
  const dual = method.startsWith('rename') || method.startsWith('cp') ||
               method.startsWith('link') || method.startsWith('copyFile') ||
               method.startsWith('symlink');
  // Fd-form: writeFile/appendFile with numeric first arg targets an open fd,
  // not a path. Emit as a separate op shape.
  if (FS_FD_CAPABLE.has(method) && typeof a0 === 'number') {
    const isAppend = method.startsWith('append');
    const attrs = { op: isAppend ? 'appendFd' : 'writeFd', fd: a0 };
    const data = a1;
    if (typeof data === 'string') attrs.size = Buffer.byteLength(data);
    else if (Buffer.isBuffer(data)) attrs.size = data.length;
    else if (data && typeof data.byteLength === 'number') attrs.size = data.byteLength;
    return attrs;
  }
  const attrs = { op: method };
  attrs.path = pathStr(a0);
  if (dual) attrs.dst = pathStr(a1);
  // For open/openSync, capture flags
  if (method === 'open' || method === 'openSync') {
    const flags = a1;
    if (flags !== undefined) attrs.flags = String(flags);
  }
  return attrs;
}
function pathStr(p) {
  if (p == null) return null;
  if (typeof p === 'string') return p;
  if (p instanceof URL) return p.href;
  if (Buffer.isBuffer(p)) return p.toString();
  return String(p);
}

function patchFsObject(obj, isPromises) {
  for (const m of FS_MUTATION_METHODS) {
    const orig = obj[m];
    if (typeof orig !== 'function') continue;
    const isSync = m.endsWith('Sync');
    obj[m] = function (...args) {
      const attrs = describeFsCall(m, args);
      // attrs.op may differ from the method name (e.g. writeFd for fd-form
      // writeFileSync). Prefer it so consumers see the semantic op.
      const op = attrs.op || m;
      safeEmit({ hook: 'file', op, attrs });
      if (ENFORCE) {
        const resp = syncDecide({ hook: 'file', op, attrs });
        const decision = resp && resp.action;
        if (!resp || decision === 'deny' || decision === 'ask') {
          const ruleId = resp ? resp.rule_id : '';
          const reason = resp ? (resp.reason || '') :
            'sync RPC failed; fail-closed (write)';
          const askNote = decision === 'ask' ? 'ask-mode not implemented; treated as deny' : reason;
          const err = makeFsDenyError(m, attrs.path, ruleId, askNote);
          if (isSync) throw err;
          if (isPromises) return Promise.reject(err);
          // Callback-style async: last arg might be a callback. If so, call
          // it asynchronously with the error and DO NOT invoke the original.
          const last = args[args.length - 1];
          if (typeof last === 'function') {
            process.nextTick(last, err);
            return undefined;
          }
          // No callback supplied — Node usually throws ERR_INVALID_CALLBACK,
          // but for safety we throw the deny synchronously here so the call
          // does not silently succeed.
          throw err;
        }
      }
      return orig.apply(this, args);
    };
  }
}
patchFsObject(fs, false);
if (fs.promises) patchFsObject(fs.promises, true);

// ---------------------------------------------------------------------------
// Bun-native APIs (only when running under Bun)
// ---------------------------------------------------------------------------

if (IS_BUN) {
  const B = globalThis.Bun;

  // Bun.write(destPathOrBunFile, data, opts?) — primary file-write API in Bun.
  if (typeof B.write === 'function') {
    const orig = B.write;
    B.write = function (dest, data) {
      let path = null;
      if (typeof dest === 'string') path = dest;
      else if (dest && typeof dest === 'object') {
        // BunFile has a `name` getter; FileBlob has `name` too. Fall back to toString.
        if (typeof dest.name === 'string') path = dest.name;
      }
      safeEmit({ hook: 'file', op: 'Bun.write', attrs: { path: path } });
      return orig.apply(this, arguments);
    };
  }

  // Bun.file(path) returns a BunFile; if a downstream `.writer()` or `.write()`
  // is used directly off the BunFile, the path is still observable on the
  // returned object. We don't intercept BunFile prototype here — Bun.write
  // is the canonical path and catches >95% of writes. Document as a gap.

  // Bun.spawn(cmdArrOrOpts, opts?) and Bun.spawnSync — Bun-native subprocess.
  function describeBunSpawn(args) {
    let argv = null, cwd = null;
    const a0 = args[0];
    if (Array.isArray(a0)) {
      argv = a0;
    } else if (a0 && typeof a0 === 'object') {
      if (Array.isArray(a0.cmd)) argv = a0.cmd;
      if (typeof a0.cwd === 'string') cwd = a0.cwd;
    }
    return {
      program: argv && argv.length ? String(argv[0]) : null,
      argv: argv ? argv.map(String) : null,
      cwd: cwd || process.cwd(),
    };
  }
  if (typeof B.spawn === 'function') {
    const orig = B.spawn;
    B.spawn = function () {
      // Dedupe: if called as the inner delegate of node:child_process under Bun,
      // the outer cp patch already emitted AND already ran the sync check;
      // skip both, forward only.
      if (__aw_inCpExec === 0) {
        const attrs = describeBunSpawn(arguments);
        safeEmit({ hook: 'exec', op: 'Bun.spawn', attrs });
        if (ENFORCE) {
          const resp = syncDecide({ hook: 'exec', op: 'Bun.spawn', attrs });
          const decision = resp && resp.action;
          if (!resp || decision === 'deny' || decision === 'ask') {
            const ruleId = resp ? resp.rule_id : '';
            const reason = resp ? (resp.reason || '') :
              'sync RPC failed; fail-closed (exec)';
            const askNote = decision === 'ask' ? 'ask-mode not implemented; treated as deny' : reason;
            throw makeExecDenyError('Bun.spawn', attrs.program, ruleId, askNote);
          }
        }
      }
      return orig.apply(this, arguments);
    };
  }
  if (typeof B.spawnSync === 'function') {
    const orig = B.spawnSync;
    B.spawnSync = function () {
      if (__aw_inCpExec === 0) {
        const attrs = describeBunSpawn(arguments);
        safeEmit({ hook: 'exec', op: 'Bun.spawnSync', attrs });
        if (ENFORCE) {
          const resp = syncDecide({ hook: 'exec', op: 'Bun.spawnSync', attrs });
          const decision = resp && resp.action;
          if (!resp || decision === 'deny' || decision === 'ask') {
            const ruleId = resp ? resp.rule_id : '';
            const reason = resp ? (resp.reason || '') :
              'sync RPC failed; fail-closed (exec)';
            const askNote = decision === 'ask' ? 'ask-mode not implemented; treated as deny' : reason;
            throw makeExecDenyError('Bun.spawnSync', attrs.program, ruleId, askNote);
          }
        }
      }
      return orig.apply(this, arguments);
    };
  }
}

// ---------------------------------------------------------------------------
// startup ping
// ---------------------------------------------------------------------------

safeEmit({
  hook: 'ping',
  op: 'hook_loaded',
  attrs: {
    runtime: RUNTIME,
    runtime_version: IS_BUN ? globalThis.Bun.version : process.version,
    argv0: process.argv0,
    has_global_fetch: typeof globalThis.fetch === 'function',
  },
});

// ---------------------------------------------------------------------------
// Synchronous flush on process exit
//
// `process.on('exit')` is the last synchronous callback Node runs before
// teardown. The async unix socket is gone by then, but spawnSync is still
// available. We shell out to a tiny node one-liner that drains whatever
// remains in `pendingLines`. Bounded by EXIT_FLUSH_BUDGET_MS so a wedged
// daemon never visibly hangs the parent.
//
// Skipped under Bun: `Bun.spawnSync` is patched (above) and the exit-event
// timing on Bun differs; the cooperative path is sufficient there for now
// and Bun's compiled-binary surface is what the threat-model targets, not
// short-lived spawn-and-exit drivers. Documented gap, not a regression.
// ---------------------------------------------------------------------------

const EXIT_FLUSH_HELPER = `
const net = require('net');
const sock = process.argv[1];
const payload = process.argv[2];
if (!payload) process.exit(0);
const c = net.createConnection(sock);
let done = false;
const finish = (code) => {
  if (done) return; done = true;
  process.exit(code);
};
// Inner deadline kept just under the outer spawnSync budget so a wedged
// daemon does not leave us hung. Outer = EXIT_FLUSH_BUDGET_MS (in the
// parent); inner here is set generously to most of that window because
// on slower runs (cold cache, busy laptop) node v18's connect + write
// has been observed to take ~100ms.
const t = setTimeout(() => finish(2), 250);
// Wait until the kernel has acknowledged the FIN on the read side
// before exiting. On node v18, writing payload then immediately exiting
// can drop the queued bytes; \`end(payload, cb)\` waits for the writable
// side to flush but the peer may not have read yet — listening for
// 'close' is the cheapest cross-version "kernel saw it" signal.
const exitWhenDone = () => { clearTimeout(t); finish(0); };
c.on('connect', () => {
  try {
    c.end(payload);
    c.on('close', exitWhenDone);
    c.on('finish', exitWhenDone);
  } catch (_) { clearTimeout(t); finish(3); }
});
c.on('error', () => { clearTimeout(t); finish(4); });
`;

let __aw_exitFlushed = false;
function flushOnExitSync() {
  if (IS_BUN) return; // see header note
  if (__aw_exitFlushed) return;
  __aw_exitFlushed = true;
  // Anything still in `backlog` (never connected) plus anything in
  // `pendingLines` (write submitted but not confirmed) is at risk. We
  // union them and dedupe, since a backlogged line is also in pending.
  const lines = [];
  const seen = new Set();
  for (const l of backlog) { if (!seen.has(l)) { seen.add(l); lines.push(l); } }
  for (const l of pendingLines) { if (!seen.has(l)) { seen.add(l); lines.push(l); } }
  if (lines.length === 0) return;
  const payload = lines.join('');
  // Scrub NODE_OPTIONS / BUN_OPTIONS from the helper's env. Without this
  // the helper would itself preload hook.js (because the parent's NODE_OPTIONS
  // includes --require=hook.js) and re-emit a `ping` of its own, plus
  // exercise an exit-flush recursively. Drop them; the helper is a leaf
  // process whose only job is to drain `payload` on this socket.
  const childEnv = {};
  for (const k of Object.keys(process.env)) {
    if (k === 'NODE_OPTIONS' || k === 'BUN_OPTIONS') continue;
    childEnv[k] = process.env[k];
  }
  try {
    ORIG_SPAWN_SYNC.call(child_process, process.execPath, [
      '-e', EXIT_FLUSH_HELPER, '--', SOCK, payload,
    ], {
      timeout: EXIT_FLUSH_BUDGET_MS,
      windowsHide: true,
      stdio: 'ignore',
      env: childEnv,
    });
  } catch (_) { /* never throw from a hook */ }
}

try { process.on('exit', flushOnExitSync); } catch (_) {}
