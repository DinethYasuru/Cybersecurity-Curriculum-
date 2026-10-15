/*
  Cyber Security class attendance server on Cloudflare (Workers free plan).

  The same server logic as attendance-server.js (AttendanceCore) runs here, with a Durable Object's
  SQLite database instead of the Google Sheet. One Durable Object holds the whole class, so requests
  run one at a time and never collide, like the Sheet's lock.

  Setup: see attendance-worker/README.md. The secret SETUP_KEY (Settings > Variables and Secrets)
  lets the attendance page set the main password, unlock sign-in and copy data in from the Sheet.
*/
import { DurableObject } from 'cloudflare:workers';
import server from '../../attendance-server.js';

const { AttendanceCore, TABLES } = server;
const BACKUPS_KEPT = 30;
const MAX_BODY = 300000, MAX_IMPORT = 25000000;  // copying data in carries photos, so it may be bigger

/* ---------- SHA-256 and HMAC, synchronous like Apps Script's (the core is synchronous) ---------- */
const SHA = (() => {
  const K = [], H0 = []; let n = 2, c = 0; const fr = x => (x - Math.floor(x)) * 4294967296 | 0;
  while (c < 64) { let p = true; for (let i = 2; i * i <= n; i++) if (n % i === 0) { p = false; break; } if (p) { if (c < 8) H0[c] = fr(Math.pow(n, 1 / 2)); K[c] = fr(Math.pow(n, 1 / 3)); c++; } n++; }
  const ror = (x, r) => (x >>> r) | (x << (32 - r));
  function hash(bytes) {
    const b = Array.from(bytes), l = b.length * 8; b.push(128); while (b.length % 64 !== 56) b.push(0);
    for (let i = 7; i >= 0; i--) b.push(i >= 4 ? 0 : (l >>> (i * 8)) & 255);
    let H = H0.slice(); const w = new Array(64);
    for (let j = 0; j < b.length; j += 64) {
      for (let i = 0; i < 16; i++) w[i] = (b[j + 4 * i] << 24) | (b[j + 4 * i + 1] << 16) | (b[j + 4 * i + 2] << 8) | b[j + 4 * i + 3];
      for (let i = 16; i < 64; i++) { const x = w[i - 15], y = w[i - 2]; w[i] = (w[i - 16] + (ror(x, 7) ^ ror(x, 18) ^ (x >>> 3)) + w[i - 7] + (ror(y, 17) ^ ror(y, 19) ^ (y >>> 10))) | 0; }
      let [a, bb, cc, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) { const t1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0, t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & bb) ^ (a & cc) ^ (bb & cc))) | 0; h = g; g = f; f = e; e = (d + t1) | 0; d = cc; cc = bb; bb = a; a = (t1 + t2) | 0; }
      H = [H[0] + a | 0, H[1] + bb | 0, H[2] + cc | 0, H[3] + d | 0, H[4] + e | 0, H[5] + f | 0, H[6] + g | 0, H[7] + h | 0];
    }
    const out = []; H.forEach(v => out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255)); return out;
  }
  const utf8 = s => Array.from(new TextEncoder().encode(s));
  function hmac(key, msg) {
    let k = utf8(key); if (k.length > 64) k = hash(k); while (k.length < 64) k.push(0);
    return hash(k.map(x => x ^ 0x5c).concat(hash(k.map(x => x ^ 0x36).concat(utf8(msg)))));
  }
  return { hmac, hex: s => hash(utf8(s)).map(x => ('0' + x.toString(16)).slice(-2)).join('') };
})();
const randHex = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a, x => ('0' + x.toString(16)).slice(-2)).join(''); };
function sameText(a, b) {
  a = String(a || ''); b = String(b || '');
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '86400' };
const json = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, CORS) });

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (request.method !== 'GET' && request.method !== 'POST') return json({ ok: false, reason: 'input', message: 'Bad request.' }, 405);
    // pass on where the request came from (the Durable Object doesn't see it); a client can't set this header
    const cf = request.cf || {}, h = new Headers(request.headers);
    h.set('x-att-net', JSON.stringify({ ip: request.headers.get('cf-connecting-ip') || '', asn: cf.asn || '', org: String(cf.asOrganization || '').slice(0, 60), city: String(cf.city || '').slice(0, 40) }));
    return env.CLASS.get(env.CLASS.idFromName('class')).fetch(new Request(request, { headers: h }));
  },
  async scheduled(event, env) {
    await env.CLASS.get(env.CLASS.idFromName('class')).fetch('https://class/cron', { method: 'POST', headers: { 'x-cron': '1' } });
  }
};

export class ClassRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.tabs = {};   // each table kept in memory after the first read; only this object writes, so it stays right
    this.sql.exec('CREATE TABLE IF NOT EXISTS props (k TEXT PRIMARY KEY, v TEXT)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp INTEGER)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, why TEXT, data TEXT)');
    for (const t of Object.keys(TABLES)) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS t_${t} (${TABLES[t].map(c => `"${c}" TEXT`).join(', ')})`);
      const have = this.sql.exec(`PRAGMA table_info(t_${t})`).toArray().map(r => r.name);
      for (const c of TABLES[t]) if (!have.includes(c)) this.sql.exec(`ALTER TABLE t_${t} ADD COLUMN "${c}" TEXT`);
    }
    this.env_ = this.makeEnv();
  }

  makeEnv() {
    const sql = this.sql, self = this;
    const row = (t, o) => TABLES[t].map(c => (o[c] == null ? '' : String(o[c])));
    const insert = (t, o) => sql.exec(`INSERT INTO t_${t} VALUES (${TABLES[t].map(() => '?').join(',')})`, ...row(t, o));
    const readAll = t => {
      if (!self.tabs[t]) self.tabs[t] = sql.exec(`SELECT rowid AS _r, * FROM t_${t} ORDER BY rowid`).toArray().map(r => {
        const o = { _r: r._r }; TABLES[t].forEach(c => { o[c] = r[c] == null ? '' : String(r[c]); }); return o;
      });
      return self.tabs[t];
    };
    const plain = r => { const o = {}; for (const k in r) if (k !== '_r') o[k] = r[k]; return o; };
    return {
      now: () => Date.now(),
      net: () => self.net,
      read: t => (t === 'log' ? sql.exec(`SELECT * FROM t_log ORDER BY rowid`).toArray().map(r => { const o = {}; TABLES.log.forEach(c => { o[c] = r[c] == null ? '' : String(r[c]); }); return o; }) : readAll(t).map(plain)),
      readTail: (t, max) => sql.exec(`SELECT * FROM t_${t} ORDER BY rowid DESC LIMIT ?`, max).toArray().reverse().map(r => { const o = {}; TABLES[t].forEach(c => { o[c] = r[c] == null ? '' : String(r[c]); }); return o; }),
      append: (t, o) => {
        insert(t, o);
        if (self.tabs[t]) { const r = {}; TABLES[t].forEach(c => { r[c] = o[c] == null ? '' : String(o[c]); }); r._r = sql.exec('SELECT last_insert_rowid() AS r').one().r; self.tabs[t].push(r); }
      },
      // the core writes whole tables; only the rows that really changed are touched (the free plan counts written rows)
      write: (t, rows) => {
        const key = o => JSON.stringify(row(t, o));
        const have = new Map();
        readAll(t).forEach(r => { const k = key(r); if (!have.has(k)) have.set(k, []); have.get(k).push(r._r); });
        const add = [];
        rows.forEach(o => { const k = key(o), list = have.get(k); if (list && list.length) list.shift(); else add.push(o); });
        self.ctx.storage.transactionSync(() => {
          for (const list of have.values()) for (const r of list) sql.exec(`DELETE FROM t_${t} WHERE rowid = ?`, r);
          add.forEach(o => insert(t, o));
        });
        delete self.tabs[t];
      },
      getProp: k => { const r = sql.exec('SELECT v FROM props WHERE k = ?', k).toArray()[0]; return r ? r.v : null; },
      setProp: (k, v) => { sql.exec('INSERT INTO props (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, String(v)); },
      cacheGet: k => { const r = sql.exec('SELECT v, exp FROM kv WHERE k = ?', k).toArray()[0]; return r && r.exp > Date.now() ? r.v : null; },
      cachePut: (k, v, s) => { sql.exec('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp', k, String(v), Date.now() + (s || 600) * 1000); },
      cacheDel: k => { sql.exec('DELETE FROM kv WHERE k = ?', k); },
      hmac: (key, msg) => SHA.hmac(key, msg),
      sha256: s => SHA.hex(s),
      random: () => randHex(20),
      // requests already run one at a time here
      lock: fn => fn(),
      backup: why => self.backupNow(why),
      backupAuto: on => { const info = self.backupInfo(); info.auto = !!on; self.env_.setProp('backup', JSON.stringify(info)); }
    };
  }

  core() { return AttendanceCore(this.env_); }
  backupInfo() { try { return JSON.parse(this.env_.getProp('backup') || 'null') || { auto: false }; } catch (e) { return { auto: false }; } }
  snapshot() {
    const all = { kind: 'attendance-server-copy', at: Date.now(), tables: {}, props: {} };
    for (const t of Object.keys(TABLES)) all.tables[t] = this.env_.read(t);
    this.sql.exec('SELECT k, v FROM props').toArray().forEach(r => { all.props[r.k] = r.v; });
    return all;
  }
  backupNow(why) {
    const at = Date.now(), name = 'Backup ' + new Date(at + 330 * 60000).toISOString().slice(0, 16).replace('T', ' ');
    this.sql.exec('INSERT INTO backups (at, why, data) VALUES (?, ?, ?)', at, why || '', JSON.stringify(this.snapshot()));
    this.sql.exec('DELETE FROM backups WHERE id NOT IN (SELECT id FROM backups ORDER BY id DESC LIMIT ?)', BACKUPS_KEPT);
    const info = this.backupInfo();
    Object.assign(info, { last: at, name, url: '', folder: '', count: this.sql.exec('SELECT COUNT(*) AS n FROM backups').one().n, why: why || '', error: '' });
    this.env_.setProp('backup', JSON.stringify(info));
    return info;
  }

  // Setup on the page, with the SETUP_KEY secret: set the main password, unlock, sign out everywhere, copy data in
  maint(req) {
    const key = this.env.SETUP_KEY || '';
    if (key.length < 12) return { ok: false, reason: 'nokey', message: 'Set the SETUP_KEY secret (12+ characters) on the Worker first: Cloudflare > the Worker > Settings > Variables and Secrets.' };
    const fails = Number(this.env_.cacheGet('maintfail') || 0);
    if (fails >= 10) return { ok: false, reason: 'locked', message: 'Too many wrong server keys. Wait 15 minutes.' };
    if (!sameText(req.key, key)) { this.env_.cachePut('maintfail', String(fails + 1), 900); return { ok: false, reason: 'key', message: 'Wrong server key.' }; }
    const core = this.core(), op = req.op;
    if (op === 'check') {
      const n = t => this.sql.exec(`SELECT COUNT(*) AS n FROM t_${t}`).one().n;
      return { ok: true, configured: !!this.env_.getProp('adminHash'), students: n('students'), attendance: n('attendance'), days: n('days') };
    }
    if (op === 'setPassword') { try { core.setPassword(req.password); } catch (e) { return { ok: false, reason: 'input', message: e.message }; } return { ok: true }; }
    if (op === 'unlock') { core.unlockLogin(); this.env_.cacheDel('maintfail'); return { ok: true }; }
    if (op === 'reset') { core.resetSecurity(); return { ok: true }; }
    if (op === 'import') {
      const d = req.data;
      if (!d || d.kind !== 'attendance-backup' || typeof d !== 'object') return { ok: false, reason: 'input', message: 'That is not an attendance download.' };
      const hasData = this.sql.exec('SELECT COUNT(*) AS n FROM t_students').one().n + this.sql.exec('SELECT COUNT(*) AS n FROM t_attendance').one().n;
      if (hasData && !req.replace) return { ok: false, reason: 'notempty', message: 'This server already has students or attendance. Tick "replace" to overwrite them.' };
      if (hasData) this.backupNow('before copying data in');
      const counts = {};
      this.ctx.storage.transactionSync(() => {
        for (const t of Object.keys(TABLES)) {
          const rows = Array.isArray(d[t]) ? d[t].filter(r => r && typeof r === 'object') : [];
          this.sql.exec(`DELETE FROM t_${t}`);
          const keep = t === 'staff' ? rows.map(r => Object.assign({}, r, { salt: '', hash: '' })) : rows;
          keep.forEach(o => this.sql.exec(`INSERT INTO t_${t} VALUES (${TABLES[t].map(() => '?').join(',')})`, ...TABLES[t].map(c => (o[c] == null ? '' : String(o[c])).slice(0, 200000))));
          counts[t] = keep.length;
        }
        if (d.settings && typeof d.settings === 'object') this.env_.setProp('settings', JSON.stringify(d.settings));
        // next student ID: after the highest one already given
        const nums = (Array.isArray(d.students) ? d.students : []).map(r => Number(String(r.id || '').replace(/\D/g, '')) || 0);
        if (nums.length) this.env_.setProp('idNext', String(Math.max(...nums) + 1));
      });
      this.tabs = {};
      return { ok: true, counts };
    }
    return { ok: false, reason: 'action', message: 'Unknown setup step.' };
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/cron' && request.headers.get('x-cron') === '1' && request.method === 'POST') {
      if (this.backupInfo().auto) { try { this.backupNow('daily'); } catch (e) { const i = this.backupInfo(); i.error = String(e.message || e); i.errorAt = Date.now(); this.env_.setProp('backup', JSON.stringify(i)); } }
      this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now());
      return json({ ok: true });
    }
    try { this.net = JSON.parse(request.headers.get('x-att-net') || 'null'); } catch (e) { this.net = null; }
    if (request.method === 'GET') return json(this.core().handle({ action: 'status' }));
    const body = await request.text();
    if (body.length > MAX_IMPORT) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    let req;
    try { req = JSON.parse(body); } catch (e) { return json({ ok: false, reason: 'input', message: 'Bad request.' }); }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return json({ ok: false, reason: 'input', message: 'Bad request.' });
    if (body.length > MAX_BODY && !(req.action === 'maint' && req.op === 'import')) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    if (req.action === 'maint') return json(this.maint(req));
    return json(this.core().handle(req));
  }
}
