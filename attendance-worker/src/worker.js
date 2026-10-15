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

/* ---------- the front door: every class at the American Corner ----------
   One Durable Object per class (its own database, the same AttendanceCore as before) and one "Corner"
   object for what classes share: the class list, people, instructor accounts and their roles.
   The Cyber Security class keeps its original database (named 'class'). */
const STUDENT = { status: 1, lookup: 1, register: 1, checkin: 1, me: 1, profile: 1, keyRequest: 1, keySignIn: 1, profileSave: 1 };
const HUB_ADMIN = { corner: 1, classSave: 1, people: 1, staffSave: 1, myAccount: 1 };
const SYNC_AFTER = { register: 1, profileSave: 1, student: 1, bulk: 1, dayDelete: 1 };
const doName = k => (k === 'cyber' ? 'class' : 'class:' + k);
let INITED = false;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (request.method !== 'GET' && request.method !== 'POST') return json({ ok: false, reason: 'input', message: 'Bad request.' }, 405);
    // where the request came from (a Durable Object doesn't see it); a client can't set this
    const cf = request.cf || {};
    const net = JSON.stringify({ ip: request.headers.get('cf-connecting-ip') || '', asn: cf.asn || '', org: String(cf.asOrganization || '').slice(0, 60), city: String(cf.city || '').slice(0, 40) });
    const hubStub = env.CORNER.get(env.CORNER.idFromName('corner'));
    const H = async (op, data) => (await hubStub.fetch('https://hub/op', { method: 'POST', body: JSON.stringify(Object.assign({ op }, data || {})) })).json();
    const C = async (k, req, staff) => (await env.CLASS.get(env.CLASS.idFromName(doName(k))).fetch('https://class/', { method: 'POST', headers: { 'x-att-net': net, 'x-att-staff': staff ? JSON.stringify(staff) : '' }, body: JSON.stringify(req) })).json();
    const I = async (k, req) => (await env.CLASS.get(env.CLASS.idFromName(doName(k))).fetch('https://class/int', { method: 'POST', body: JSON.stringify(req) })).json();
    // first request after the update: the Corner learns the Cyber Security class, its instructors and students
    if (!INITED) {
      const st = await H('inited');
      if (!st.inited) await H('init', { seed: await I('cyber', { op: 'seed' }) });
      INITED = true;
    }
    // a class's students changed: the Corner updates its people, and a new name or number reaches the person's other classes
    const sync = async k => {
      const r = await H('syncClass', { k, students: (await I(k, { op: 'students' })).students });
      for (const p of (r.pushes || [])) await I(p.k, { op: 'applyPerson', sid: p.sid, name: p.name, phone: p.phone });
    };
    const classes = (await H('classes')).classes;
    const pub = classes.filter(c => c.active !== 'no');
    const known = k => pub.some(c => c.id === k);
    const nameOf = k => (classes.find(c => c.id === k) || {}).name || '';

    if (request.method === 'GET') {
      const r = await C(pub[0] ? pub[0].id : 'cyber', { action: 'status' });
      return json(Object.assign(r, { multi: true, classes: pub.map(c => ({ id: c.id, name: c.name })) }));
    }
    const body = await request.text();
    if (body.length > MAX_IMPORT) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    let req;
    try { req = JSON.parse(body); } catch (e) { return json({ ok: false, reason: 'input', message: 'Bad request.' }); }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return json({ ok: false, reason: 'input', message: 'Bad request.' });
    if (body.length > MAX_BODY && !(req.action === 'maint' && req.op === 'import')) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    const a = String(req.action || '');
    let k = known(String(req.k || '')) ? String(req.k) : '';

    if (a === 'login' || a === 'logout') return json(await H(a, { req }));
    if (a === 'maint') {
      k = k || 'cyber';
      const r = await C(k, req);
      // the class checked the server key; sign-in lives in the Corner, so these steps happen there too
      if (r.ok && (req.op === 'setPassword' || req.op === 'unlock' || req.op === 'reset')) await H('maint', { req });
      if (r.ok && req.op === 'import') await sync(k);
      return json(r);
    }

    if (STUDENT[a]) {
      // which class: the QR link says (k); otherwise the only class open now, or the open class whose code was typed
      let opened = null;
      if (!k) {
        const st = await Promise.all(pub.map(async c => ({ c, s: await C(c.id, { action: 'status' }) })));
        opened = st.filter(x => x.s.open).map(x => x.c.id);
        if (opened.length === 1) k = opened[0];
        else if (opened.length > 1 && req.code && (a === 'lookup' || a === 'register' || a === 'checkin')) {
          for (const id of opened) if ((await C(id, { action: 'codeCheck', code: req.code })).match) { k = id; break; }
        }
        if (a === 'status') {
          const r = await C(k || (pub[0] ? pub[0].id : 'cyber'), { action: 'status' });
          return json(Object.assign(r, { multi: true, k: k || '', className: k ? nameOf(k) : '', classes: st.map(x => ({ id: x.c.id, name: x.c.name, open: !!x.s.open })), pick: !k && opened.length > 1 }));
        }
        if (!k && a !== 'me') {
          if (opened.length > 1) return json({ ok: false, reason: 'pick', message: 'Pick your class first.', classes: pub.filter(c => opened.includes(c.id)).map(c => ({ id: c.id, name: c.name })) });
          k = pub[0] ? pub[0].id : 'cyber';
        }
      }
      if (a === 'status') { const r = await C(k, req); return json(Object.assign(r, { multi: true, k, className: nameOf(k), classes: pub.map(c => ({ id: c.id, name: c.name })) })); }
      // My attendance across every class the person attends
      if (a === 'me' && req.all) {
        const en = (await H('enrolOf', { phone: req.phone })).enrol || [];
        const out = [];
        for (const e of en) if (known(e.k)) { const r = await C(e.k, { action: 'me', phone: req.phone, name: req.name, device: req.device }); if (r.ok) out.push(Object.assign(r, { k: e.k, className: nameOf(e.k) })); }
        if (!out.length) return json({ ok: false, reason: 'notfound', message: 'No record for this number and name yet.' });
        return json({ ok: true, all: true, classes: out, name: out[0].name, phone: out[0].phone });
      }
      k = k || 'cyber';
      if (a === 'register') {
        const p = await H('person', { phone: req.phone });
        if (p.staff) return json({ ok: false, reason: 'unknown', message: 'That number belongs to an instructor. Students use their own number.' });
        // one person across the Corner: joining another class keeps the name they already have
        if (p.person) req.name = p.person.name;
      }
      const r = await C(k, req);
      if (a === 'lookup' && r.ok && !r.found) {
        const p = await H('person', { phone: req.phone });
        if (p.person) { r.known = true; r.person = { name: p.person.masked }; }
      }
      if (r.ok && SYNC_AFTER[a]) await sync(k);
      return json(Object.assign(r, { k, className: nameOf(k) }));
    }

    // instructors: the Corner checks the sign-in and the role in this class
    const who = await H('who', { token: req.token });
    if (!who.ok) return json({ ok: false, reason: 'auth', message: 'Please log in again.' });
    if (HUB_ADMIN[a]) {
      if (a === 'corner') {
        // today in every class, for the Corner admin
        if (!who.admin) return json({ ok: false, reason: 'input', message: 'Only the Corner admin can see this.' });
        const owner = { id: who.me ? who.me.id : '', name: who.me ? who.me.name : 'Main password', role: 'owner' };
        const today = await Promise.all(classes.map(async c => {
          const r = c.active === 'no' ? null : await C(c.id, { action: 'today' }, owner);
          return { id: c.id, name: c.name, room: c.room, color: c.color, active: c.active !== 'no', status: r && r.status, present: r && r.ok ? r.present.length : 0, alerts: r && r.alerts ? r.alerts.length : 0 };
        }));
        const pp = await H('people', { who });
        return json({ ok: true, classes: today, people: pp.people || [], staff: pp.staff || [] });
      }
      const r = await H(a, { req, who });
      // a new class starts with its own student ID prefix, like ENG-0001
      if (a === 'classSave' && r.ok && r.created) await I(r.class.id, { op: 'newClass', prefix: r.class.id.replace(/[^a-z]/g, '').slice(0, 3).toUpperCase() + '-' });
      return json(r);
    }
    if (!k) k = who.classes[0] ? who.classes[0].id : '';
    const role = who.admin ? 'owner' : (who.classes.find(c => c.id === k) || {}).role;
    if (!k || !role) return json({ ok: false, reason: 'noclass', message: 'You are not an instructor in this class.', corner: who });
    const staff = { id: who.me ? who.me.id : '', name: who.me ? who.me.name : 'Main password', phone: who.me ? who.me.phone : '', role };
    // instructor numbers live in the Corner now, so the class can't see them; keep them out of student lists
    const staffPhones = (await H('staffPhones')).phones || [];
    if (a === 'student' && !req.remove && staffPhones.includes(cleanPh(req.phone))) return json(fail('input', 'That number belongs to an instructor.'));
    let skipped = [];
    if (a === 'bulk' && Array.isArray(req.list)) req.list = req.list.filter(x => staffPhones.includes(cleanPh(x.phone)) ? (skipped.push(String(x.phone || '') + ', ' + String(x.name || '') + ' (an instructor number)'), false) : true);
    const r = await C(k, req, staff);
    if (skipped.length && r.ok) r.bad = (r.bad || []).concat(skipped);
    if (r.ok && a === 'data') {
      const t = await H('staffFor', { k });
      r.staff = t.staff; r.me = who.me ? Object.assign({}, who.me, { role }) : null; r.owner = role === 'owner';
      r.corner = { admin: who.admin, classes: who.classes, k, className: nameOf(k) };
    }
    if (r.ok && a === 'photos') Object.assign(r.photos, (await H('staffPhotos')).photos || {});
    if (r.ok && SYNC_AFTER[a]) await sync(k);
    return json(r);
  },
  async scheduled(event, env) {
    const hub = env.CORNER.get(env.CORNER.idFromName('corner'));
    const list = (await (await hub.fetch('https://hub/op', { method: 'POST', body: JSON.stringify({ op: 'classes' }) })).json()).classes || [{ id: 'cyber' }];
    for (const c of list) await env.CLASS.get(env.CLASS.idFromName(doName(c.id))).fetch('https://class/cron', { method: 'POST', headers: { 'x-cron': '1' } });
    await hub.fetch('https://hub/cron', { method: 'POST' });
  }
};

/* ---------- the Corner: classes, people, instructors and roles ---------- */
const HUB_SQL = [
  'CREATE TABLE IF NOT EXISTS props (k TEXT PRIMARY KEY, v TEXT)',
  'CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp INTEGER)',
  "CREATE TABLE IF NOT EXISTS classes (id TEXT PRIMARY KEY, name TEXT, room TEXT, color TEXT, active TEXT, added TEXT, ord INTEGER)",
  'CREATE TABLE IF NOT EXISTS people (phone TEXT PRIMARY KEY, name TEXT, updated INTEGER)',
  'CREATE TABLE IF NOT EXISTS enrol (k TEXT, sid TEXT, phone TEXT, name TEXT, active TEXT, PRIMARY KEY (k, sid))',
  'CREATE TABLE IF NOT EXISTS staff (id TEXT PRIMARY KEY, name TEXT, phone TEXT, salt TEXT, hash TEXT, active TEXT, admin TEXT, added TEXT, photo TEXT)',
  'CREATE TABLE IF NOT EXISTS roles (sid TEXT, k TEXT, role TEXT, PRIMARY KEY (sid, k))'
];
const cleanPh = v => { let d = String(v || '').replace(/\D/g, ''); if (d.length === 11 && d.startsWith('94')) d = '0' + d.slice(2); if (d.length === 9 && d[0] !== '0') d = '0' + d; return /^0\d{9}$/.test(d) ? d : ''; };
const cleanNm = v => String(v || '').trim().replace(/\s+/g, ' ');
const okName = n => n.length >= 2 && n.length <= 60 && /^[\p{L}\p{M} .'-]+$/u.test(n);
const mask = n => cleanNm(n).split(' ').map(w => w.slice(0, 2) + (w.length > 2 ? '*'.repeat(w.length - 2) : '')).join(' ');
const hashPw = (pw, salt) => { let h = salt + ':' + pw; for (let i = 0; i < 300; i++) h = SHA.hex(salt + h); return h; };
const fail = (reason, message) => ({ ok: false, reason, message });
const okPhoto = p => typeof p === 'string' && p.length <= 40000 && /^data:image\/jpeg;base64,\/9j\/[A-Za-z0-9+\/]+=*$/.test(p);

export class Corner extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    HUB_SQL.forEach(q => this.sql.exec(q));
  }
  all(q, ...a) { return this.sql.exec(q, ...a).toArray(); }
  one(q, ...a) { return this.all(q, ...a)[0] || null; }
  prop(k, v) { if (v === undefined) { const r = this.one('SELECT v FROM props WHERE k = ?', k); return r ? r.v : null; } this.sql.exec('INSERT INTO props (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, String(v)); }
  kvGet(k) { const r = this.one('SELECT v, exp FROM kv WHERE k = ?', k); return r && r.exp > Date.now() ? r.v : null; }
  kvPut(k, v, s) { this.sql.exec('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp', k, String(v), Date.now() + s * 1000); }
  epoch() { return this.prop('epoch') || '1'; }
  staffOut(r) { return r ? { id: r.id, name: r.name, phone: r.phone, active: r.active !== 'no', admin: r.admin === 'yes', added: r.added } : null; }
  classesOf(st) {
    const cls = this.all("SELECT id, name, color FROM classes WHERE active != 'no' ORDER BY ord, name");
    if (!st || st.admin === 'yes') return cls.map(c => Object.assign(c, { role: 'owner' }));
    const roles = {}; this.all('SELECT k, role FROM roles WHERE sid = ?', st.id).forEach(r => { roles[r.k] = r.role; });
    return cls.filter(c => roles[c.id]).map(c => Object.assign(c, { role: roles[c.id] }));
  }

  init(seed) {
    if (this.prop('inited')) return { ok: true };
    seed = seed || {};
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT OR IGNORE INTO classes VALUES ('cyber', 'Cyber Security', '', '#002868', 'yes', ?, 0)", new Date().toISOString().slice(0, 10));
      if (seed.adminHash) { this.prop('adminHash', seed.adminHash); this.prop('adminSalt', seed.adminSalt); }
      (seed.staff || []).forEach(r => {
        this.sql.exec("INSERT OR REPLACE INTO staff VALUES (?, ?, ?, ?, ?, ?, 'no', ?, ?)", r.id, r.name, r.phone, r.salt || '', r.hash || '', r.active === 'no' ? 'no' : 'yes', r.added || '', r.photo || '');
        this.sql.exec('INSERT OR REPLACE INTO roles VALUES (?, ?, ?)', r.id, 'cyber', r.role === 'owner' ? 'owner' : 'instructor');
      });
      this.syncClass('cyber', seed.students || []);
      this.prop('inited', '1');
    });
    return { ok: true };
  }

  // the class list of students is the truth for that class; people follow it, and changes reach the person's other classes
  syncClass(k, students) {
    const pushes = [], now = Date.now();
    const had = {}; this.all('SELECT sid, phone, name FROM enrol WHERE k = ?', k).forEach(r => { had[r.sid] = r; });
    const seen = {};
    (students || []).forEach(s => {
      const phone = cleanPh(s.phone), name = cleanNm(s.name); seen[s.id] = 1;
      if (!phone) return;
      const old = had[s.id], person = this.one('SELECT * FROM people WHERE phone = ?', phone);
      const changed = old && (old.phone !== phone || old.name !== name);
      if (changed) {
        // this class changed the student's name or number: the person changes, and so do their other classes
        if (old.phone !== phone) { this.sql.exec('DELETE FROM people WHERE phone = ? AND NOT EXISTS (SELECT 1 FROM enrol WHERE phone = ? AND NOT (k = ? AND sid = ?))', old.phone, old.phone, k, s.id); }
        this.sql.exec('INSERT INTO people VALUES (?, ?, ?) ON CONFLICT(phone) DO UPDATE SET name = excluded.name, updated = excluded.updated', phone, name, now);
        this.all('SELECT k, sid FROM enrol WHERE phone = ? AND k != ?', old.phone, k).forEach(e => { pushes.push({ k: e.k, sid: e.sid, name, phone }); this.sql.exec('UPDATE enrol SET phone = ?, name = ? WHERE k = ? AND sid = ?', phone, name, e.k, e.sid); });
      } else if (!person) this.sql.exec('INSERT INTO people VALUES (?, ?, ?)', phone, name, now);
      this.sql.exec('INSERT INTO enrol VALUES (?, ?, ?, ?, ?) ON CONFLICT(k, sid) DO UPDATE SET phone = excluded.phone, name = excluded.name, active = excluded.active', k, s.id, phone, name, s.active === 'no' ? 'no' : 'yes');
    });
    Object.keys(had).forEach(sid => { if (!seen[sid]) this.sql.exec('DELETE FROM enrol WHERE k = ? AND sid = ?', k, sid); });
    this.sql.exec('DELETE FROM people WHERE phone NOT IN (SELECT phone FROM enrol)');
    return { ok: true, pushes };
  }

  login(req) {
    const now = Date.now(), fails = Number(this.kvGet('loginfail') || 0);
    if (fails >= 20) return fail('locked', 'Too many wrong passwords. Wait 15 minutes, or unlock sign-in in Setup › Cloudflare server tools.');
    const bad = m => { this.kvPut('loginfail', fails + 1, 900); return fail('password', m); };
    let st = null;
    if (req.phone) {
      st = this.one('SELECT * FROM staff WHERE phone = ?', cleanPh(req.phone));
      if (!st || st.active === 'no' || !st.hash || hashPw(String(req.password || ''), st.salt) !== st.hash) return bad('Wrong number or password.');
      if (!this.classesOf(st).length) return fail('noclass', 'You are not an instructor in any class yet. Ask the Corner admin.');
    } else {
      if (!this.prop('adminHash')) return fail('nopass', 'No main password yet. Set it in Setup › Cloudflare server tools.');
      if (hashPw(String(req.password || ''), this.prop('adminSalt')) !== this.prop('adminHash')) return bad('Wrong password.');
    }
    const token = randHex(20);
    this.kvPut('tok:' + token, JSON.stringify({ sid: st ? st.id : '', ep: this.epoch(), s8: st ? String(st.salt).slice(0, 8) : '' }), 21600);
    return { ok: true, token, now, hours: 6, me: this.staffOut(st), corner: { admin: !st || st.admin === 'yes', classes: this.classesOf(st) } };
  }
  who(token) {
    if (!/^[a-f0-9]{16,64}$/.test(String(token || ''))) return { ok: false };
    let t = null; try { t = JSON.parse(this.kvGet('tok:' + token) || 'null'); } catch (e) {}
    if (!t || t.ep !== this.epoch()) return { ok: false };
    let st = null;
    if (t.sid) { st = this.one('SELECT * FROM staff WHERE id = ?', t.sid); if (!st || st.active === 'no' || String(st.salt).slice(0, 8) !== t.s8) return { ok: false }; }
    return { ok: true, me: this.staffOut(st), admin: !st || st.admin === 'yes', classes: this.classesOf(st) };
  }
  staffFor(k) {
    return this.all("SELECT s.*, r.role FROM staff s LEFT JOIN roles r ON r.sid = s.id AND r.k = ? ORDER BY s.name", k)
      .filter(r => r.role || r.admin === 'yes').map(r => Object.assign(this.staffOut(r), { role: r.admin === 'yes' ? 'owner' : r.role }));
  }

  // add or change an instructor (Corner admin), or your own account (anyone)
  staffSave(req, who, mine) {
    const sid = mine ? (who.me ? who.me.id : '') : String(req.sid || '');
    if (mine && !sid) return fail('input', 'You signed in with the main password. Add yourself under Instructors, then sign in with your number.');
    const k = String(req.k || '');
    const myRole = who.admin ? 'owner' : (who.classes.find(c => c.id === k) || {}).role;
    if (!mine && myRole !== 'owner') return fail('input', 'Only a class owner or the Corner admin can change instructors.');
    let cur = sid ? this.one('SELECT * FROM staff WHERE id = ?', sid) : null;
    if (sid && !cur) return fail('input', 'That instructor is gone.');
    // an owner who isn't the Corner admin may only manage people in their own class, and never the admin's account
    if (!mine && !who.admin && cur && cur.admin === 'yes') return fail('input', 'Only the Corner admin can change that account.');
    if (!mine && req.remove) {
      if (who.me && who.me.id === sid) return fail('input', 'You cannot remove yourself.');
      if (!who.admin) { this.sql.exec('DELETE FROM roles WHERE sid = ? AND k = ?', sid, k); return { ok: true }; }
      this.sql.exec('DELETE FROM staff WHERE id = ?', sid); this.sql.exec('DELETE FROM roles WHERE sid = ?', sid);
      return { ok: true };
    }
    const name = req.name == null && cur ? cur.name : cleanNm(req.name), phone = req.phone == null && cur ? cur.phone : cleanPh(req.phone);
    if (!okName(name)) return fail('input', 'Type a name with letters only.');
    if (!phone) return fail('input', 'Type a mobile number like 0771234567.');
    const clash = this.one('SELECT name FROM staff WHERE phone = ? AND id != ?', phone, sid);
    if (clash) return fail('input', 'That number already belongs to instructor ' + clash.name + '.');
    const stu = this.one('SELECT name FROM people WHERE phone = ?', phone);
    if (stu) return fail('input', 'That number belongs to student ' + stu.name + '. An instructor needs a number of their own.');
    if (req.photo != null && req.photo !== '' && !okPhoto(req.photo)) return fail('input', 'That photo could not be used. Try another one.');
    const pw = req.password == null ? '' : String(req.password);
    if (pw && pw.length < 8) return fail('input', 'The password needs at least 8 characters.');
    if (!cur && !pw) return fail('input', 'Give the new instructor a password (8 or more characters).');
    if (mine && pw && hashPw(String(req.oldPassword || ''), cur.salt) !== cur.hash) return fail('input', 'Your current password is not right.');
    if (!cur) { cur = { id: 'S' + randHex(4), added: new Date().toISOString().slice(0, 10), salt: '', hash: '', admin: 'no', photo: '' }; }
    cur.name = name; cur.phone = phone;
    if (!mine && req.active != null) { if (who.me && who.me.id === sid && req.active === false) return fail('input', 'You cannot switch yourself off.'); cur.active = req.active === false ? 'no' : 'yes'; }
    cur.active = cur.active || 'yes';
    if (!mine && who.admin && req.admin != null) { if (who.me && who.me.id === sid && !req.admin) return fail('input', 'You cannot remove your own Corner admin role.'); cur.admin = req.admin ? 'yes' : 'no'; }
    if (req.photo != null) cur.photo = req.photo || '';
    if (pw) { cur.salt = randHex(20); cur.hash = hashPw(pw, cur.salt); }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('INSERT OR REPLACE INTO staff VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', cur.id, cur.name, cur.phone, cur.salt, cur.hash, cur.active, cur.admin || 'no', cur.added, cur.photo || '');
      // the role in the class being looked at: owner, instructor, or '' (not in this class)
      if (!mine && k && req.role != null) {
        if (req.role === 'owner' || req.role === 'instructor') this.sql.exec('INSERT OR REPLACE INTO roles VALUES (?, ?, ?)', cur.id, k, req.role);
        else this.sql.exec('DELETE FROM roles WHERE sid = ? AND k = ?', cur.id, k);
      }
    });
    return { ok: true, staff: Object.assign(this.staffOut(cur), { role: (this.one('SELECT role FROM roles WHERE sid = ? AND k = ?', cur.id, k) || {}).role || '' }) };
  }

  classSave(req, who) {
    if (!who.admin) return fail('input', 'Only the Corner admin can add or change classes.');
    let id = String(req.id || '').toLowerCase().trim();
    const cur = id ? this.one('SELECT * FROM classes WHERE id = ?', id) : null;
    const name = cleanNm(req.name == null && cur ? cur.name : req.name);
    if (name.length < 2 || name.length > 40) return fail('input', 'Give the class a name (2 to 40 letters).');
    if (!cur) {
      id = id || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 20);
      if (!/^[a-z0-9][a-z0-9-]{1,19}$/.test(id)) return fail('input', 'Short name: 2 to 20 letters, numbers or -.');
      if (this.one('SELECT id FROM classes WHERE id = ?', id)) return fail('input', 'There is already a class called ' + id + '.');
    }
    const room = String(req.room == null && cur ? cur.room : req.room || '').slice(0, 40);
    const color = /^#[0-9a-fA-F]{6}$/.test(req.color || '') ? req.color : cur ? cur.color : '#002868';
    const active = req.active == null && cur ? cur.active : req.active === false ? 'no' : 'yes';
    const ord = cur ? cur.ord : (this.one('SELECT MAX(ord) AS m FROM classes') || {}).m + 1 || 1;
    this.sql.exec('INSERT OR REPLACE INTO classes VALUES (?, ?, ?, ?, ?, ?, ?)', id, name, room, color, active, cur ? cur.added : new Date().toISOString().slice(0, 10), ord);
    return { ok: true, created: !cur, class: this.one('SELECT * FROM classes WHERE id = ?', id) };
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/cron') { this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now()); return json({ ok: true }); }
    const q = await request.json(), req = q.req || {}, who = q.who;
    switch (q.op) {
      case 'inited': return json({ inited: !!this.prop('inited') });
      case 'init': return json(this.init(q.seed));
      case 'classes': return json({ classes: this.all('SELECT * FROM classes ORDER BY ord, name') });
      case 'syncClass': { let r; this.ctx.storage.transactionSync(() => { r = this.syncClass(q.k, q.students); }); return json(r); }
      case 'person': {
        const ph = cleanPh(q.phone), p = ph ? this.one('SELECT * FROM people WHERE phone = ?', ph) : null;
        return json({ person: p ? { name: p.name, masked: mask(p.name) } : null, staff: !!(ph && this.one('SELECT id FROM staff WHERE phone = ?', ph)) });
      }
      case 'enrolOf': return json({ enrol: this.all("SELECT k, sid FROM enrol WHERE phone = ? AND active != 'no'", cleanPh(q.phone)) });
      case 'login': return json(this.login(req));
      case 'logout': this.sql.exec('DELETE FROM kv WHERE k = ?', 'tok:' + String(req.token || '')); return json({ ok: true });
      case 'who': return json(this.who(q.token));
      case 'staffPhones': return json({ phones: this.all('SELECT phone FROM staff').map(r => r.phone) });
      case 'staffFor': return json({ staff: this.staffFor(q.k) });
      case 'staffPhotos': { const p = {}; this.all("SELECT id, photo FROM staff WHERE photo != ''").forEach(r => { p[r.id] = r.photo; }); return json({ photos: p }); }
      case 'staffSave': return json(this.staffSave(req, who, false));
      case 'myAccount': return json(this.staffSave(req, who, true));
      case 'classSave': return json(this.classSave(req, who));
      case 'people': {
        if (!who.admin) return json(fail('input', 'Only the Corner admin can see everyone.'));
        const en = {}; this.all('SELECT phone, k, sid FROM enrol').forEach(e => { (en[e.phone] = en[e.phone] || []).push({ k: e.k, sid: e.sid }); });
        const roles = {}; this.all('SELECT sid, k, role FROM roles').forEach(r => { (roles[r.sid] = roles[r.sid] || []).push({ k: r.k, role: r.role }); });
        return json({ ok: true, people: this.all('SELECT phone, name FROM people ORDER BY name').map(p => Object.assign(p, { classes: en[p.phone] || [] })),
          staff: this.all('SELECT * FROM staff ORDER BY name').map(s => Object.assign(this.staffOut(s), { roles: roles[s.id] || [] })) });
      }
      case 'maint':
        if (req.op === 'setPassword') { const salt = randHex(20); this.prop('adminSalt', salt); this.prop('adminHash', hashPw(String(req.password || ''), salt)); this.prop('epoch', Number(this.epoch()) + 1); }
        if (req.op === 'unlock') this.sql.exec("DELETE FROM kv WHERE k = 'loginfail'");
        if (req.op === 'reset') { this.prop('epoch', Number(this.epoch()) + 1); this.sql.exec("DELETE FROM kv WHERE k = 'loginfail'"); }
        return json({ ok: true });
    }
    return json(fail('action', 'Unknown step.'));
  }
}

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
      routedStaff: () => self.staff,
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

  // asked by the front door only (clients can't reach these paths)
  internal(q) {
    const E = this.env_;
    if (q.op === 'students') return { students: E.read('students').map(r => ({ id: r.id, name: r.name, phone: r.phone, active: r.active })) };
    if (q.op === 'seed') {
      const photos = {}; E.read('profiles').forEach(r => { photos[r.id] = r.photo; });
      return { adminHash: E.getProp('adminHash'), adminSalt: E.getProp('adminSalt'), staff: E.read('staff').map(r => Object.assign({}, r, { photo: photos[r.id] || '' })),
        students: E.read('students').map(r => ({ id: r.id, name: r.name, phone: r.phone, active: r.active })) };
    }
    if (q.op === 'newClass') { if (!E.getProp('settings')) E.setProp('settings', JSON.stringify({ idPrefix: q.prefix })); return { ok: true }; }
    if (q.op === 'applyPerson') {
      // the same person changed their name or number in another class
      const rows = E.read('students'), st = rows.find(r => r.id === q.sid);
      if (!st || rows.some(r => r.phone === q.phone && r.id !== q.sid)) return { ok: false };
      const nameChanged = st.name !== q.name;
      st.name = q.name; st.phone = q.phone; E.write('students', rows);
      if (nameChanged) E.write('attendance', E.read('attendance').map(r => { if (r.id === q.sid) r.name = q.name; return r; }));
      return { ok: true };
    }
    return { ok: false };
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/cron' && request.headers.get('x-cron') === '1' && request.method === 'POST') {
      if (this.backupInfo().auto) { try { this.backupNow('daily'); } catch (e) { const i = this.backupInfo(); i.error = String(e.message || e); i.errorAt = Date.now(); this.env_.setProp('backup', JSON.stringify(i)); } }
      this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now());
      return json({ ok: true });
    }
    if (url.pathname === '/int') return json(this.internal(await request.json()));
    try { this.net = JSON.parse(request.headers.get('x-att-net') || 'null'); } catch (e) { this.net = null; }
    try { this.staff = JSON.parse(request.headers.get('x-att-staff') || 'null'); } catch (e) { this.staff = null; }
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
