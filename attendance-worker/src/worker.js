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
   object for what classes share: the class list, people, facilitator accounts and their roles.
   The Cyber Security class keeps its original database (named 'class'). */
const STUDENT = { status: 1, lookup: 1, register: 1, checkin: 1, me: 1, profile: 1, keyRequest: 1, keySignIn: 1, profileSave: 1 };
const HUB_ADMIN = { corner: 1, classSave: 1, classDelete: 1, people: 1, staffSave: 1, myAccount: 1, adminPassword: 1, branchSave: 1 };
// what a coordinator account may do inside a class: look, never change (and never get the QR key)
const COORD_READ = { data: 1, today: 1, photos: 1, export: 1 };
// one request may call only so many other objects on Cloudflare (50 on the free plan): today's numbers come in pages
const CORNER_STATS = 20;
const SYNC_AFTER = { register: 1, profileSave: 1, student: 1, bulk: 1, dayDelete: 1 };
// steps that can change when a class is open: the Corner keeps a copy of its hours, so a student's first screen asks only the classes that may be open
const SCHED_AFTER = { settings: 1, extra: 1, day: 1, dayDelete: 1, absentRest: 1 };
// the class list changes rarely: each copy of the Worker keeps it for a minute (a class it doesn't know yet makes it ask again)
const CLASS_TTL = 60000;
let CLASS_CACHE = null;
// the branch: its name and logo, set by the admin. Every branch runs this same code with its own Worker.
const BRANCH_DEFAULT = { name: 'American Corner Matara', logo: '' };
const okLogo = p => p === '' || (typeof p === 'string' && p.length <= 120000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/]+=*$/.test(p));
const doName = k => (k === 'cyber' ? 'class' : 'class:' + k);
// student ID prefix for a new class: initials of a long name (Graphic Designing Foundations: GDF-), else its first letters (English: ENG-)
const prefixFor = name => {
  const w = String(name || '').toUpperCase().split(/[^A-Z]+/).filter(Boolean);
  const p = w.length >= 2 ? w.map(x => x[0]).join('').slice(0, 3) : (w[0] || '').slice(0, 3);
  return (p.length >= 2 ? p : 'CLS') + '-';
};
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
    const I = async (k, req) => (await env.CLASS.get(env.CLASS.idFromName(doName(k))).fetch('https://class/int', { method: 'POST', headers: req.op === 'wipe' ? { 'x-wipe': '1' } : {}, body: JSON.stringify(req) })).json();
    // first request after the update: the Corner learns the Cyber Security class, its facilitators and students
    if (!INITED) {
      const st = await H('inited');
      if (!st.inited) await H('init', { seed: await I('cyber', { op: 'seed' }) });
      INITED = true;
    }
    // a class's students changed: the Corner updates its people, and a new name or number reaches the person's other classes
    // (the list carries a version, so an older list that arrives late can't undo a newer one; the person's other
    // classes are changed first, and the Corner records each change only once that class accepted it)
    const sync = async k => {
      const s = await I(k, { op: 'students' });
      const r = await H('syncClass', { k, ver: s.ver, students: s.students });
      for (const p of (r.pushes || [])) if ((await I(p.k, { op: 'applyPerson', sid: p.sid, name: p.name, phone: p.phone })).ok) await H('enrolApplied', p);
    };
    const saveSched = async k => { const sc = await I(k, { op: 'sched' }); if (sc.ok) await H('schedSave', { k, sched: sc.sched }); };
    const ip = JSON.parse(net).ip;
    const loadClasses = async () => { const r = await H('classes'); CLASS_CACHE = { at: Date.now(), list: r.classes, branch: r.branch || BRANCH_DEFAULT }; return CLASS_CACHE; };
    let fresh = !(CLASS_CACHE && Date.now() - CLASS_CACHE.at < CLASS_TTL);
    let cc = fresh ? await loadClasses() : CLASS_CACHE;
    let classes = cc.list;
    let pub = classes.filter(c => c.active !== 'no');
    const branch = cc.branch;
    // something changed the class list (or the branch): the next request in this copy reads it again
    const dropClasses = () => { CLASS_CACHE = null; };
    const known = k => pub.some(c => c.id === k);
    const nameOf = k => (classes.find(c => c.id === k) || {}).name || '';

    if (request.method === 'GET') {
      const r = await C(pub[0] ? pub[0].id : 'cyber', { action: 'status' });
      return json(Object.assign(r, { multi: true, branch, classes: pub.map(c => ({ id: c.id, name: c.name })) }));
    }
    const body = await request.text();
    if (body.length > MAX_IMPORT) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    let req;
    try { req = JSON.parse(body); } catch (e) { return json({ ok: false, reason: 'input', message: 'Bad request.' }); }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return json({ ok: false, reason: 'input', message: 'Bad request.' });
    if (body.length > MAX_BODY && !(req.action === 'maint' && req.op === 'import')) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    const a = String(req.action || '');
    const rawK = String(req.k || '');
    // a class made in the last minute (by another copy of the Worker): read the list again before saying it's gone
    if (rawK && !known(rawK) && !fresh) { cc = await loadClasses(); fresh = true; classes = cc.list; pub = classes.filter(c => c.active !== 'no'); }
    let k = known(rawK) ? rawK : '';
    // a class that was archived or never existed (an old QR, or a change queued before the class was archived):
    // never fall back to another class, or the change would land in the wrong one
    const gone = rawK && !k;

    if (a === 'login') return json(await H('login', { req, ip }));
    if (a === 'logout') return json(await H('logout', { req }));
    if (a === 'maint') {
      if (gone) return json(fail('noclass', 'That class is not running any more.'));
      k = k || 'cyber';
      // wrong-key tries are counted once for the whole Corner, not once per class
      if ((await H('maintFails')).locked) return json(fail('locked', 'Too many wrong server keys. Wait 15 minutes.'));
      const r = await C(k, req);
      if (r.reason === 'key') await H('maintFail');
      // the class checked the server key; sign-in lives in the Corner, so these steps happen there too
      if (r.ok && (req.op === 'setPassword' || req.op === 'unlock' || req.op === 'reset')) await H('maint', { req });
      // sign out everywhere: sign-in lives in the Corner, so one call ends every sign-in at every class
      // (other classes' QR secrets change in the Danger zone, one class at a time, so this never hits the per-request limit)
      if (r.ok && req.op === 'import') { await sync(k); await saveSched(k); }
      return json(r);
    }

    if (STUDENT[a]) {
      if (gone) return json(fail('noclass', 'This class is not running any more. Ask your facilitator for the new QR.'));
      // a profile key goes to the class the student attends (any of them: the profile is the same person everywhere)
      if (!k && (a === 'keyRequest' || a === 'keySignIn')) {
        const en = ((await H('enrolOf', { phone: req.phone })).enrol || []).map(e => e.k).filter(known);
        if (en.length === 1) k = en[0];
        else if (en.length > 1) {
          const op = await Promise.all(en.map(async id => ((await C(id, { action: 'status' })).open ? id : '')));
          k = op.find(Boolean) || en[0];
        }
      }
      // which class: the QR link says (k); otherwise the only class open now, or the open class whose code was typed
      let opened = null;
      // the Corner knows each class's hours: only the classes that may be open now are asked (one request may call only so many)
      const g = k ? null : await H('openGuess', { now: Date.now() });
      if (!k) {
        // a student who typed their number: only their own classes that may be open now (works with hundreds of classes)
        if (req.phone && (a === 'lookup' || a === 'register' || a === 'checkin')) {
          const en = ((await H('enrolOf', { phone: req.phone })).enrol || []).map(e => e.k).filter(id => known(id) && g.maybe.includes(id));
          const st = await Promise.all([...new Set(en)].slice(0, 15).map(async id => ((await C(id, { action: 'status' })).open ? id : '')));
          const mine = st.filter(Boolean);
          // with a code, the class whose code it is (a code from none of theirs is a new class, found the usual way below)
          if (req.code) { for (const id of mine) if ((await C(id, { action: 'codeCheck', code: req.code })).match) { k = id; break; } }
          else if (mine.length === 1) k = mine[0];
          else if (mine.length > 1) return json({ ok: false, reason: 'pick', mine: true, message: 'You are in more than one class open now. Tap yours.', classes: pub.filter(c => mine.includes(c.id)).map(c => ({ id: c.id, name: c.name })) });
        }
      }
      if (!k) {
        const ask = pub.filter(c => g.maybe.includes(c.id)).slice(0, 15);
        const st = await Promise.all(ask.map(async c => ({ c, s: await C(c.id, { action: 'status' }) })));
        // a class the Corner had no hours for yet: keep them now
        const learn = pub.filter(c => g.unknown.includes(c.id)).slice(0, 3);
        for (const c of learn) { const sc = await I(c.id, { op: 'sched' }); if (sc.ok) await H('schedSave', { k: c.id, sched: sc.sched }); }
        opened = st.filter(x => x.s.open).map(x => x.c.id);
        if (opened.length === 1) k = opened[0];
        else if (opened.length > 1 && req.code && (a === 'lookup' || a === 'register' || a === 'checkin')) {
          for (const id of opened) if ((await C(id, { action: 'codeCheck', code: req.code })).match) { k = id; break; }
        }
        if (a === 'status') {
          const r = await C(k || opened[0] || (pub[0] ? pub[0].id : 'cyber'), { action: 'status' });
          // several open: a code is asked for only if one of them wants it
          if (!k && opened.length > 1) r.requireCode = st.some(x => x.s.open && x.s.requireCode);
          return json(Object.assign(r, { multi: true, branch, k: k || '', className: k ? nameOf(k) : '', classes: pub.map(c => ({ id: c.id, name: c.name, open: opened.includes(c.id) })), pick: !k && opened.length > 1 }));
        }
        if (!k && a !== 'me') {
          if (opened.length > 1) return json({ ok: false, reason: 'pick', message: 'Pick your class first.', classes: pub.filter(c => opened.includes(c.id)).map(c => ({ id: c.id, name: c.name })) });
          k = pub[0] ? pub[0].id : 'cyber';
        }
      }
      if (a === 'status') { const r = await C(k, req); return json(Object.assign(r, { multi: true, branch, k, className: nameOf(k), classes: pub.map(c => ({ id: c.id, name: c.name })) })); }
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
        if (p.staff) return json({ ok: false, reason: 'unknown', message: 'That number belongs to a facilitator. Students use their own number.' });
        // one person across the Corner: joining another class keeps the name they already have
        if (p.person) req.name = p.person.name;
      }
      // a new number must not be a facilitator's, or another person's at the Corner
      if (a === 'profileSave' && req.phone != null) {
        const pc = await H('phoneCheck', { k, sid: req.id, phone: req.phone, name: req.name });
        if (!pc.ok) return json(fail('input', pc.staff ? 'That number belongs to a facilitator.' : 'That number belongs to someone else at the American Corner.'));
      }
      const r = await C(k, req);
      if (a === 'lookup' && r.ok && !r.found) {
        const p = await H('person', { phone: req.phone });
        if (p.person) { r.known = true; r.person = { name: p.person.masked }; }
      }
      if (r.ok && SYNC_AFTER[a]) await sync(k);
      return json(Object.assign(r, { k, className: nameOf(k) }));
    }

    // facilitators: the Corner checks the sign-in and the role in this class
    const who = await H('who', { token: req.token });
    if (!who.ok) return json({ ok: false, reason: 'auth', message: 'Please log in again.' });
    // while Cloudflare swaps in new code, the Corner can still answer the older way (no coord/hub): the main password stays the admin
    who.coord = !!who.coord; who.hub = !!(who.hub || who.admin || who.coord);
    // the admin's Danger zone: prune, critical steps and the data editor. Only the main password, typed again each time.
    const danger = async () => {
      if (!who.admin) return fail('input', 'Only the admin can use the Danger zone.');
      const ck = await H('dangerCheck', { password: req.password });
      if (!ck.ok) return ck;
      const op = String(req.op || ''), db = String(req.db || 'corner');
      const cls = classes.find(c => c.id === db);
      if (db !== 'corner' && !cls) return fail('input', 'That class is gone.');
      const where = db === 'corner' ? 'American Corner' : cls.name;
      const note = what => H('audit', { db: where, what });
      if (op === 'open') {
        const a = await H('auditList');
        return { ok: true, audit: a.audit || [], classes: classes.map(c => ({ id: c.id, name: c.name, active: c.active !== 'no' })) };
      }
      if (op === 'db') {
        const d = req.q && typeof req.q === 'object' ? req.q : {};
        const r = db === 'corner' ? await H('dangerDb', { q: d }) : await I(db, { op: 'danger:db', q: d });
        const wrote = d.op === 'cell' || d.op === 'del' || d.op === 'add' || (d.op === 'sql' && r.written > 0);
        if (r.ok && wrote) {
          await note(d.op === 'sql' ? 'SQL: ' + String(d.sql).trim().slice(0, 240) + ' (' + r.written + ' rows written)'
            : d.op === 'cell' ? 'Edited ' + d.table + ' row ' + d.rowid + ', ' + d.col
            : d.op === 'del' ? 'Deleted ' + d.table + ' row ' + d.rowid : 'Added a row to ' + d.table);
          if (db !== 'corner') { await sync(db); await saveSched(db); } else dropClasses();
        }
        return r;
      }
      if (op === 'prune') {
        // one database per request: the page goes through the classes one by one
        const r = db === 'corner' ? await H('prune', { auditDays: Number(req.auditDays) || 0 }) : await I(db, { op: 'danger:prune', logDays: req.logDays, backupsKept: req.backupsKept });
        if (r.ok) { const parts = Object.keys(r.n).filter(x => r.n[x]).map(x => r.n[x] + ' ' + x); if (parts.length) await note('Pruned ' + parts.join(', ')); }
        return r;
      }
      if (op === 'rotateQr' || op === 'clearAttendance') {
        if (!cls) return fail('input', 'Pick a class.');
        if (op === 'clearAttendance' && cleanNm(req.confirm).toLowerCase() !== cleanNm(cls.name).toLowerCase()) return fail('input', 'Type the class name exactly to clear it.');
        const r = await I(db, { op: 'danger:' + op });
        if (r.ok) await note(op === 'rotateQr' ? 'New check-in codes (QR secret changed)' : 'Cleared attendance, excuses, class days and log');
        if (r.ok && op === 'clearAttendance') await saveSched(db);
        return r;
      }
      if (op === 'signOutAll') {
        if (String(req.confirm || '').trim().toUpperCase() !== 'SIGN OUT') return fail('input', 'Type SIGN OUT to confirm.');
        const r = await H('signOutAll', { req });
        if (r.ok) await note('Signed everyone out');
        return r;
      }
      if (op === 'unlockAll') { const r = await H('unlockAll'); if (r.ok) await note('Unlocked sign-in'); return r; }
      if (op === 'deleteArchived') {
        if (String(req.confirm || '').trim().toUpperCase() !== 'DELETE') return fail('input', 'Type DELETE to confirm.');
        const gone = [];
        for (const c of classes.filter(x => x.active === 'no').slice(0, CORNER_STATS)) {
          const r = await H('classDelete', { req: { id: c.id, confirm: c.name }, who });
          if (r.ok) { await I(c.id, { op: 'wipe' }); gone.push(c.name); }
        }
        if (gone.length) { await note('Deleted archived classes: ' + gone.join(', ')); dropClasses(); }
        return { ok: true, deleted: gone };
      }
      return fail('action', 'Unknown step.');
    };
    // a starter account first chooses its own password
    if (who.me && who.me.mustSetup && a !== 'myAccount') return json({ ok: false, reason: 'setup', message: 'Set up your account first.', me: who.me });
    if (a === 'danger') return json(await danger());
    if (HUB_ADMIN[a]) {
      if (a === 'corner') {
        // the class list, people and accounts come from the Corner alone; today's numbers need one call per class,
        // so they come for at most CORNER_STATS classes per request (the page asks again for others)
        if (!who.hub) return json({ ok: false, reason: 'input', message: 'Only the admin and coordinators can see this.' });
        const owner = { id: who.me ? who.me.id : '', name: who.me ? who.me.name : 'Admin', role: who.admin ? 'owner' : 'coordinator' };
        const want = Array.isArray(req.ids) ? req.ids.map(String) : req.stats === false ? [] : classes.filter(c => c.active !== 'no').slice(0, CORNER_STATS).map(c => c.id);
        const ask = new Set(classes.filter(c => c.active !== 'no' && want.includes(c.id)).slice(0, CORNER_STATS).map(c => c.id));
        const stats = {};
        await Promise.all([...ask].map(async id => { const r = await C(id, { action: 'today' }, owner); stats[id] = { status: r.status, present: r.ok ? r.present.length : 0, alerts: r.alerts ? r.alerts.length : 0 }; }));
        const list = classes.map(c => Object.assign({ id: c.id, name: c.name, room: c.room, color: c.color, active: c.active !== 'no' }, stats[c.id] || {}));
        if (Array.isArray(req.ids)) return json({ ok: true, classes: list.filter(c => stats[c.id]) });
        const pp = await H('people', { who });
        return json({ ok: true, classes: list, people: pp.people || [], staff: pp.staff || [] });
      }
      const r = await H(a, { req, who });
      // a new class starts with its own student ID prefix, like ENG-0001
      if (a === 'classSave' && r.ok && r.created) { await I(r.class.id, { op: 'newClass', prefix: prefixFor(r.class.name) }); await saveSched(r.class.id); }
      if (a === 'classDelete' && r.ok) await I(r.id, { op: 'wipe' });
      if (r.ok && (a === 'classSave' || a === 'classDelete' || a === 'branchSave')) dropClasses();
      return json(r);
    }
    if (gone) return json({ ok: false, reason: 'noclass', message: 'That class is not running any more.', corner: who });
    if (!k) k = who.classes[0] ? who.classes[0].id : '';
    // the admin (main password) has no limits; a coordinator account sees every class but changes none
    const role = who.admin ? 'owner' : who.coord ? 'coordinator' : (who.classes.find(c => c.id === k) || {}).role;
    if (!k || !role) return json({ ok: false, reason: 'noclass', message: 'You are not a facilitator in this class.', corner: who });
    if (who.coord && !COORD_READ[a]) return json(fail('readonly', 'A coordinator can see every class but not change it. Facilitators make the changes.'));
    // a coordinator never runs the Live QR, so it must not teach the class a room network either
    if (who.coord && a === 'today') delete req.live;
    // a coordinator may download a class's record (the class asks for a lead's role for that one step)
    const staff = { id: who.me ? who.me.id : '', name: who.me ? who.me.name : 'Admin', phone: who.me ? who.me.phone : '', role: who.coord && a === 'export' ? 'owner' : role };
    // facilitator numbers live in the Corner now, so the class can't see them; keep them out of student lists
    const staffPhones = (await H('staffPhones')).phones || [];
    if (a === 'student' && !req.remove && staffPhones.includes(cleanPh(req.phone))) return json(fail('input', 'That number belongs to a facilitator.'));
    if (a === 'student' && !req.remove) {
      const pc = await H('phoneCheck', { k, sid: req.id, phone: req.phone, name: req.name });
      if (!pc.ok && pc.other) return json(fail('input', 'That number belongs to ' + pc.other + ' at the American Corner. To add them to this class, type their name as ' + pc.other + '.'));
    }
    let skipped = [];
    if (a === 'bulk' && Array.isArray(req.list)) req.list = req.list.filter(x => staffPhones.includes(cleanPh(x.phone)) ? (skipped.push(String(x.phone || '') + ', ' + String(x.name || '') + ' (a facilitator number)'), false) : true);
    const r = await C(k, req, staff);
    if (skipped.length && r.ok) r.bad = (r.bad || []).concat(skipped);
    if (r.ok && a === 'data') {
      const t = await H('staffFor', { k });
      r.staff = t.staff; r.me = who.me ? Object.assign({}, who.me, { role }) : null; r.owner = role === 'owner';
      r.corner = { admin: who.admin, coordinator: who.coord, hub: who.hub, classes: who.classes, k, className: nameOf(k) };
      // the check-in codes come from this key: a coordinator can't make them
      if (who.coord) delete r.qrKey;
      // a class made while its first setup step failed still gets its own ID prefix
      if (k !== 'cyber' && r.settings && r.settings.idPrefix === 'ACM-') await I(k, { op: 'newClass', prefix: prefixFor(nameOf(k)) });
    }
    if (r.ok && a === 'photos') Object.assign(r.photos, (await H('staffPhotos')).photos || {});
    if (r.ok && a === 'data') r.corner.branch = branch;
    if (r.ok && SYNC_AFTER[a]) await sync(k);
    if (r.ok && SCHED_AFTER[a]) await saveSched(k);
    return json(r);
  },
  async scheduled(event, env) {
    const hub = env.CORNER.get(env.CORNER.idFromName('corner'));
    const list = (await (await hub.fetch('https://hub/op', { method: 'POST', body: JSON.stringify({ op: 'classes' }) })).json()).classes || [{ id: 'cyber' }];
    for (const c of list) await env.CLASS.get(env.CLASS.idFromName(doName(c.id))).fetch('https://class/cron', { method: 'POST', headers: { 'x-cron': '1' } });
    await hub.fetch('https://hub/cron', { method: 'POST' });
  }
};

/* ---------- the Corner: classes, people, facilitators and roles ---------- */
const HUB_SQL = [
  'CREATE TABLE IF NOT EXISTS props (k TEXT PRIMARY KEY, v TEXT)',
  'CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp INTEGER)',
  "CREATE TABLE IF NOT EXISTS classes (id TEXT PRIMARY KEY, name TEXT, room TEXT, color TEXT, active TEXT, added TEXT, ord INTEGER)",
  'CREATE TABLE IF NOT EXISTS people (phone TEXT PRIMARY KEY, name TEXT, updated INTEGER)',
  'CREATE TABLE IF NOT EXISTS enrol (k TEXT, sid TEXT, phone TEXT, name TEXT, active TEXT, PRIMARY KEY (k, sid))',
  'CREATE TABLE IF NOT EXISTS staff (id TEXT PRIMARY KEY, name TEXT, phone TEXT, salt TEXT, hash TEXT, active TEXT, admin TEXT, added TEXT, photo TEXT, setup TEXT)',
  'CREATE TABLE IF NOT EXISTS roles (sid TEXT, k TEXT, role TEXT, PRIMARY KEY (sid, k))',
  // what the admin changed in the Danger zone, newest kept
  'CREATE TABLE IF NOT EXISTS audit (at INTEGER, db TEXT, what TEXT)'
];
const cleanPh = v => { let d = String(v || '').replace(/\D/g, ''); if (d.length === 11 && d.startsWith('94')) d = '0' + d.slice(2); if (d.length === 9 && d[0] !== '0') d = '0' + d; return /^0\d{9}$/.test(d) ? d : ''; };
const cleanNm = v => String(v || '').trim().replace(/\s+/g, ' ');
const okName = n => n.length >= 2 && n.length <= 60 && /^[\p{L}\p{M} .'-]+$/u.test(n);
const mask = n => cleanNm(n).split(' ').map(w => w.slice(0, 2) + (w.length > 2 ? '*'.repeat(w.length - 2) : '')).join(' ');
const hashPw = (pw, salt) => { let h = salt + ':' + pw; for (let i = 0; i < 300; i++) h = SHA.hex(salt + h); return h; };
const fail = (reason, message) => ({ ok: false, reason, message });
// the admin's Danger zone: look at any table, change a cell, delete or add a row, or run SQL.
// Long values (photos, backups) are cut for the screen and can't be edited from there.
const DB_SKIP = /^(_cf_|sqlite_|__)/;  // Cloudflare's own tables (and the local test server's)
const SHOW_MAX = 300;
const dbCell = v => (v instanceof ArrayBuffer ? '[' + v.byteLength + ' bytes]' : typeof v === 'string' && v.length > SHOW_MAX ? v.slice(0, SHOW_MAX) : v);
const dbRow = r => { const o = {}, cut = []; for (const c in r) { o[c] = dbCell(r[c]); if (typeof r[c] === 'string' && r[c].length > SHOW_MAX) cut.push(c); } if (cut.length) o._cut = cut; return o; };
const READ_SQL = /^\s*(select|pragma|explain)\b/i;
function dbTool(sql, tx, q) {
  const all = (s, ...a) => sql.exec(s, ...a).toArray();
  const tables = all("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").map(r => r.name).filter(n => !DB_SKIP.test(n));
  const op = String(q.op || '');
  try {
    if (op === 'tables') return { ok: true, tables: tables.map(t => ({ name: t, rows: all(`SELECT COUNT(*) AS n FROM "${t}"`)[0].n })) };
    if (op === 'sql') {
      const text = String(q.sql || '').trim();
      if (!text) return fail('input', 'Type a query.');
      if (text.length > 20000) return fail('input', 'That query is too long.');
      const out = { ok: true, cols: [], rows: [], more: false, read: 0, written: 0 };
      tx(() => {
        const cur = sql.exec(text);
        for (const r of cur) { if (out.rows.length >= 500) { out.more = true; break; } out.rows.push(dbRow(r)); }
        out.cols = cur.columnNames || []; out.read = cur.rowsRead; out.written = cur.rowsWritten;
      });
      return out;
    }
    const t = String(q.table || '');
    if (!tables.includes(t)) return fail('input', 'Pick a table.');
    const cols = all(`PRAGMA table_info("${t}")`).map(c => c.name);
    const rid = Number(q.rowid);
    if (op === 'rows') {
      const lim = Math.min(Math.max(Number(q.limit) || 50, 1), 200), off = Math.max(Number(q.offset) || 0, 0);
      const f = String(q.find || '').trim().slice(0, 100);
      const where = f ? ' WHERE ' + cols.map(c => `CAST("${c}" AS TEXT) LIKE ?`).join(' OR ') : '';
      const args = f ? cols.map(() => '%' + f + '%') : [];
      const total = all(`SELECT COUNT(*) AS n FROM "${t}"${where}`, ...args)[0].n;
      return { ok: true, table: t, cols, total, offset: off, limit: lim, rows: all(`SELECT rowid AS _rowid, * FROM "${t}"${where} ORDER BY rowid DESC LIMIT ? OFFSET ?`, ...args, lim, off).map(dbRow) };
    }
    if (op === 'cell') {
      if (!cols.includes(q.col)) return fail('input', 'Pick a column.');
      const v = q.value === null ? null : String(q.value == null ? '' : q.value);
      let n = 0; tx(() => { n = sql.exec(`UPDATE "${t}" SET "${q.col}" = ? WHERE rowid = ?`, v, rid).rowsWritten; });
      return n ? { ok: true, row: dbRow(all(`SELECT rowid AS _rowid, * FROM "${t}" WHERE rowid = ?`, rid)[0] || {}) } : fail('input', 'That row is gone. Reload the table.');
    }
    if (op === 'del') {
      let n = 0; tx(() => { n = sql.exec(`DELETE FROM "${t}" WHERE rowid = ?`, rid).rowsWritten; });
      return n ? { ok: true } : fail('input', 'That row is gone. Reload the table.');
    }
    if (op === 'add') {
      const v = q.values && typeof q.values === 'object' ? q.values : {};
      const use = cols.filter(c => v[c] != null && v[c] !== '');
      if (!use.length) return fail('input', 'Fill in at least one column.');
      let id = 0; tx(() => { id = sql.exec(`INSERT INTO "${t}" (${use.map(c => `"${c}"`).join(', ')}) VALUES (${use.map(() => '?').join(', ')}) RETURNING rowid AS r`, ...use.map(c => String(v[c]))).one().r; });
      return { ok: true, rowid: id };
    }
  } catch (e) { return fail('input', 'The database said: ' + String(e && e.message || e).replace(/^Error:\s*/, '')); }
  return fail('action', 'Unknown step.');
}
const okPhoto = p => typeof p === 'string' && p.length <= 40000 && /^data:image\/jpeg;base64,\/9j\/[A-Za-z0-9+\/]+=*$/.test(p);

export class Corner extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    HUB_SQL.forEach(q => this.sql.exec(q));
    // setup = 'no': a starter account that has not chosen its own password yet
    if (!this.all('PRAGMA table_info(staff)').some(c => c.name === 'setup')) this.sql.exec("ALTER TABLE staff ADD COLUMN setup TEXT DEFAULT 'yes'");
  }
  all(q, ...a) { return this.sql.exec(q, ...a).toArray(); }
  one(q, ...a) { return this.all(q, ...a)[0] || null; }
  prop(k, v) { if (v === undefined) { const r = this.one('SELECT v FROM props WHERE k = ?', k); return r ? r.v : null; } this.sql.exec('INSERT INTO props (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, String(v)); }
  kvGet(k) { const r = this.one('SELECT v, exp FROM kv WHERE k = ?', k); return r && r.exp > Date.now() ? r.v : null; }
  kvPut(k, v, s) { this.sql.exec('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp', k, String(v), Date.now() + s * 1000); }
  epoch() { return this.prop('epoch') || '1'; }
  branch() { try { return Object.assign({}, BRANCH_DEFAULT, JSON.parse(this.prop('branch') || '{}')); } catch (e) { return Object.assign({}, BRANCH_DEFAULT); } }
  staffOut(r) { return r ? { id: r.id, name: r.name, phone: r.phone, active: r.active !== 'no', added: r.added, mustSetup: r.setup === 'no', coord: r.admin === 'coord' } : null; }
  classesOf(st) {
    const cls = this.all("SELECT id, name, color FROM classes WHERE active != 'no' ORDER BY ord, name");
    // the admin (main password) and coordinator accounts see every class
    if (!st) return cls.map(c => Object.assign(c, { role: 'admin' }));
    if (st.admin === 'coord') return cls.map(c => Object.assign(c, { role: 'coordinator' }));
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
        this.sql.exec("INSERT OR REPLACE INTO staff (id, name, phone, salt, hash, active, admin, added, photo, setup) VALUES (?, ?, ?, ?, ?, ?, 'no', ?, ?, 'yes')", r.id, r.name, r.phone, r.salt || '', r.hash || '', r.active === 'no' ? 'no' : 'yes', r.added || '', r.photo || '');
        this.sql.exec('INSERT OR REPLACE INTO roles VALUES (?, ?, ?)', r.id, 'cyber', r.role === 'owner' ? 'owner' : 'instructor');
      });
      this.syncClass('cyber', seed.students || []);
      this.prop('inited', '1');
    });
    return { ok: true };
  }

  // the class list of students is the truth for that class; people follow it, and changes reach the person's other classes
  syncClass(k, students, ver) {
    // a list older than one already applied (two syncs crossing on the way) changes nothing
    if (ver != null) { const seen = Number(this.prop('ver:' + k) || -1); if (Number(ver) < seen) return { ok: true, pushes: [], stale: true }; this.prop('ver:' + k, ver); }
    const pushes = [], now = Date.now();
    const had = {}; this.all('SELECT sid, phone, name FROM enrol WHERE k = ?', k).forEach(r => { had[r.sid] = r; });
    const seen = {};
    (students || []).forEach(s => {
      const phone = cleanPh(s.phone), name = cleanNm(s.name); seen[s.id] = 1;
      if (!phone) return;
      const old = had[s.id], person = this.one('SELECT * FROM people WHERE phone = ?', phone);
      const changed = old && (old.phone !== phone || old.name !== name);
      // the new number already belongs to a different person (in another class): two people, nothing is copied across
      const clash = changed && old.phone !== phone && person && this.one('SELECT 1 AS x FROM enrol WHERE phone = ? AND NOT (k = ? AND sid = ?)', phone, k, s.id);
      if (changed && !clash) {
        // this class changed the student's name or number: the person changes, and so do their other classes
        // (their enrolments there change only after that class accepted it, in enrolApplied)
        this.sql.exec('INSERT INTO people VALUES (?, ?, ?) ON CONFLICT(phone) DO UPDATE SET name = excluded.name, updated = excluded.updated', phone, name, now);
        this.all('SELECT k, sid FROM enrol WHERE phone = ? AND k != ?', old.phone, k).forEach(e => pushes.push({ k: e.k, sid: e.sid, name, phone }));
      } else if (!person) this.sql.exec('INSERT INTO people VALUES (?, ?, ?)', phone, name, now);
      this.sql.exec('INSERT INTO enrol VALUES (?, ?, ?, ?, ?) ON CONFLICT(k, sid) DO UPDATE SET phone = excluded.phone, name = excluded.name, active = excluded.active', k, s.id, phone, name, s.active === 'no' ? 'no' : 'yes');
    });
    Object.keys(had).forEach(sid => { if (!seen[sid]) this.sql.exec('DELETE FROM enrol WHERE k = ? AND sid = ?', k, sid); });
    this.sql.exec('DELETE FROM people WHERE phone NOT IN (SELECT phone FROM enrol)');
    return { ok: true, pushes };
  }

  // wrong passwords are counted per number (or the main password) and per internet address, so a stranger guessing
  // can't lock everyone out; a browser that signed in before has its own count (the trusted-browser key)
  trustOk(t) { return /^[a-f0-9]{32}$/.test(String(t || '')) && !!this.kvGet('trust:' + t); }
  login(req, ip) {
    const now = Date.now(), trust = this.trustOk(req.trust);
    const fk = 'loginfail:' + (req.phone ? cleanPh(req.phone) || 'x' : 'main') + (trust ? ':t' : ''), ik = 'loginfail:ip:' + String(ip || '');
    const fails = Number(this.kvGet(fk) || 0), ipFails = Number(this.kvGet(ik) || 0);
    if (fails >= (trust ? 10 : 20) || (!trust && ipFails >= 50)) return fail('locked', 'Too many wrong passwords. Wait 15 minutes, or unlock sign-in in Setup › Cloudflare server tools.');
    const bad = m => { this.kvPut(fk, fails + 1, 900); this.kvPut(ik, ipFails + 1, 900); return fail('password', m); };
    let st = null;
    if (req.phone) {
      st = this.one('SELECT * FROM staff WHERE phone = ?', cleanPh(req.phone));
      if (!st || st.active === 'no' || !st.hash || hashPw(String(req.password || ''), st.salt) !== st.hash) return bad('Wrong number or password.');
      if (!this.classesOf(st).length) return fail('noclass', 'You are not a facilitator in any class yet. Ask the coordinator.');
    } else {
      if (!this.prop('adminHash')) return fail('nopass', 'No main password yet. Set it in Setup › Cloudflare server tools.');
      if (hashPw(String(req.password || ''), this.prop('adminSalt')) !== this.prop('adminHash')) return bad('Wrong password.');
    }
    const token = randHex(20);
    this.kvPut('tok:' + token, JSON.stringify({ sid: st ? st.id : '', ep: this.epoch(), s8: st ? String(st.salt).slice(0, 8) : '', aep: st ? '' : this.prop('aep') || '1' }), 21600);
    let tr = trust ? req.trust : randHex(16);
    this.kvPut('trust:' + tr, '1', 60 * 86400);
    const coord = !!st && st.admin === 'coord';
    return { ok: true, token, now, hours: 6, trust: tr, me: this.staffOut(st), corner: { admin: !st, coordinator: coord, hub: !st || coord, classes: this.classesOf(st) } };
  }
  who(token) {
    if (!/^[a-f0-9]{16,64}$/.test(String(token || ''))) return { ok: false };
    let t = null; try { t = JSON.parse(this.kvGet('tok:' + token) || 'null'); } catch (e) {}
    if (!t || t.ep !== this.epoch()) return { ok: false };
    let st = null;
    if (t.sid) { st = this.one('SELECT * FROM staff WHERE id = ?', t.sid); if (!st || st.active === 'no' || String(st.salt).slice(0, 8) !== t.s8) return { ok: false }; }
    // a new main password ends the other admin sign-ins only
    else if ((t.aep || '1') !== (this.prop('aep') || '1')) return { ok: false };
    // admin: the main password, no limits. coord: a coordinator account. hub: either one (classes, accounts, people)
    const coord = !!st && st.admin === 'coord';
    return { ok: true, me: this.staffOut(st), admin: !st, coord, hub: !st || coord, classes: this.classesOf(st) };
  }
  staffFor(k) {
    return this.all("SELECT s.*, r.role FROM staff s LEFT JOIN roles r ON r.sid = s.id AND r.k = ? ORDER BY s.name", k)
      .filter(r => r.role).map(r => Object.assign(this.staffOut(r), { role: r.role }));
  }

  // The admin (main password) makes coordinator accounts. The admin and coordinators make starter facilitator
  // accounts, tie them to a class, reset or delete them. Anyone with an account finishes it at first sign-in
  // (name, photo, own password) and keeps it up to date under My account.
  // A lead facilitator ('owner') changes only roles in their own class.
  staffSave(req, who, mine) {
    const sid = mine ? (who.me ? who.me.id : '') : String(req.sid || '');
    if (mine && !sid) return fail('input', 'The admin password has no account. Change it in Setup › Cloudflare server tools.');
    const k = String(req.k || '');
    let cur = sid ? this.one('SELECT * FROM staff WHERE id = ?', sid) : null;
    if (sid && !cur) return fail('input', 'That account is gone.');
    // a coordinator account is the admin's to make, change or delete
    const coordAcc = cur ? cur.admin === 'coord' : req.kind === 'coord';
    if (!mine && coordAcc && !who.admin) return fail('input', 'Only the admin can make or change coordinator accounts.');
    if (!mine && !who.hub) {
      if ((who.classes.find(c => c.id === k) || {}).role !== 'owner') return fail('input', 'Only the lead facilitator or the coordinator can change roles.');
      if (!cur) return fail('input', 'Only the coordinator can make facilitator accounts.');
      if (coordAcc || !this.one('SELECT role FROM roles WHERE sid = ? AND k = ?', sid, k)) return fail('input', 'That facilitator is not in this class. Ask the coordinator.');
      if (who.me && who.me.id === sid) return fail('input', 'You cannot change your own role. Ask the coordinator.');
      if (req.remove || req.role === '') { this.sql.exec('DELETE FROM roles WHERE sid = ? AND k = ?', sid, k); return { ok: true }; }
      if (req.role !== 'owner' && req.role !== 'instructor') return fail('input', 'Pick a role.');
      this.sql.exec('INSERT OR REPLACE INTO roles VALUES (?, ?, ?)', sid, k, req.role);
      return { ok: true, staff: Object.assign(this.staffOut(cur), { role: req.role }) };
    }
    if (!mine && req.remove) {
      this.ctx.storage.transactionSync(() => { this.sql.exec('DELETE FROM staff WHERE id = ?', sid); this.sql.exec('DELETE FROM roles WHERE sid = ?', sid); });
      return { ok: true };
    }
    const name = req.name == null && cur ? cur.name : (cleanNm(req.name) || (!mine && !cur ? (coordAcc ? 'New coordinator' : 'New facilitator') : ''));
    const phone = req.phone == null && cur ? cur.phone : cleanPh(req.phone);
    if (!okName(name)) return fail('input', 'Type a name with letters only.');
    if (!phone) return fail('input', 'Type a mobile number like 0771234567.');
    const clash = this.one('SELECT name FROM staff WHERE phone = ? AND id != ?', phone, sid);
    if (clash) return fail('input', 'That number already belongs to ' + clash.name + '.' + (cur || coordAcc ? '' : ' Add them to this class from the American Corner page.'));
    const stu = this.one('SELECT name FROM people WHERE phone = ?', phone);
    if (stu) return fail('input', 'That number belongs to student ' + stu.name + '. A facilitator needs a number of their own.');
    if (req.photo != null && req.photo !== '' && !okPhoto(req.photo)) return fail('input', 'That photo could not be used. Try another one.');
    const pw = req.password == null ? '' : String(req.password);
    const first = mine && cur.setup === 'no';
    if (mine) {
      if ((pw || first) && hashPw(String(req.oldPassword || ''), cur.salt) !== cur.hash) return fail('input', first ? 'The starter password is not right.' : 'Your current password is not right.');
      if (first && !pw) return fail('input', 'Choose your own password (8 or more characters).');
      if (pw && pw.length < 8) return fail('input', 'The password needs at least 8 characters.');
      if (first && pw === String(req.oldPassword || '')) return fail('input', 'Choose a new password, not the starter one.');
    } else {
      if (!cur && !pw) return fail('input', 'Give the starter password (6 or more characters).');
      if (pw && pw.length < 6) return fail('input', 'The starter password needs at least 6 characters.');
      if (!cur && !coordAcc && !(k && (req.role === 'owner' || req.role === 'instructor'))) return fail('input', 'Pick the class and role for this facilitator.');
    }
    if (!cur) cur = { id: 'S' + randHex(4), added: new Date().toISOString().slice(0, 10), salt: '', hash: '', admin: coordAcc ? 'coord' : 'no', photo: '', setup: 'no' };
    cur.name = name; cur.phone = phone; cur.active = cur.active || 'yes';
    if (!mine && req.active != null) cur.active = req.active === false ? 'no' : 'yes';
    if (req.photo != null) cur.photo = req.photo || '';
    if (pw) { cur.salt = randHex(20); cur.hash = hashPw(pw, cur.salt); cur.setup = mine ? 'yes' : 'no'; }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('INSERT OR REPLACE INTO staff (id, name, phone, salt, hash, active, admin, added, photo, setup) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', cur.id, cur.name, cur.phone, cur.salt, cur.hash, cur.active, cur.admin === 'coord' ? 'coord' : 'no', cur.added, cur.photo || '', cur.setup || 'yes');
      // the account is tied to a class: lead facilitator, facilitator, or '' (not in this class); a coordinator sees them all
      if (!mine && !coordAcc && k && req.role != null) {
        if (req.role === 'owner' || req.role === 'instructor') this.sql.exec('INSERT OR REPLACE INTO roles VALUES (?, ?, ?)', cur.id, k, req.role);
        else this.sql.exec('DELETE FROM roles WHERE sid = ? AND k = ?', cur.id, k);
      }
    });
    return { ok: true, staff: Object.assign(this.staffOut(cur), { role: (this.one('SELECT role FROM roles WHERE sid = ? AND k = ?', cur.id, k) || {}).role || '' }) };
  }

  // the coordinator deletes a class: it leaves the list, its roles and enrolments go; the class's own data is wiped after
  classDelete(req, who) {
    if (!who.hub) return fail('input', 'Only the admin or a coordinator can delete classes.');
    const c = this.one('SELECT * FROM classes WHERE id = ?', String(req.id || ''));
    if (!c) return fail('input', 'That class is gone.');
    if (cleanNm(req.confirm).toLowerCase() !== cleanNm(c.name).toLowerCase()) return fail('input', 'Type the class name exactly to delete it.');
    if (this.one('SELECT COUNT(*) AS n FROM classes').n < 2) return fail('input', 'Keep at least one class.');
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM classes WHERE id = ?', c.id);
      this.sql.exec('DELETE FROM roles WHERE k = ?', c.id);
      this.sql.exec('DELETE FROM enrol WHERE k = ?', c.id);
      this.sql.exec('DELETE FROM people WHERE phone NOT IN (SELECT phone FROM enrol)');
      this.sql.exec('DELETE FROM props WHERE k = ?', 'ver:' + c.id);
    });
    return { ok: true, id: c.id, name: c.name };
  }

  classSave(req, who) {
    if (!who.hub) return fail('input', 'Only the admin or a coordinator can add or change classes.');
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
      case 'classes': return json({ classes: this.all('SELECT * FROM classes ORDER BY ord, name'), branch: this.branch() });
      // each class's hours, kept here so a student's first screen asks only the classes that may be open now
      case 'schedSave': if (q.sched && typeof q.sched === 'object') this.prop('sched:' + q.k, JSON.stringify(q.sched)); return json({ ok: true });
      case 'openGuess': {
        const now = Number(q.now) || Date.now(), maybe = [], unknown = [];
        const sc = {}; this.all("SELECT k, v FROM props WHERE k LIKE 'sched:%'").forEach(r => { try { sc[r.k.slice(6)] = JSON.parse(r.v); } catch (e) {} });
        for (const c of this.all("SELECT id FROM classes WHERE active != 'no' ORDER BY ord, name")) {
          const x = sc[c.id];
          if (!x) { unknown.push(c.id); maybe.push(c.id); continue; }
          if (Number(x.extraUntil) > now) { maybe.push(c.id); continue; }
          const d = new Date(now + Number(x.tzOffset || 330) * 60000), date = d.toISOString().slice(0, 10);
          // a few minutes either side: the class's own clock decides
          const t2 = m => new Date(now + (Number(x.tzOffset || 330) + m) * 60000).toISOString().slice(11, 16);
          if (x.closedDay === date || (x.cancelled || []).includes(date)) continue;
          if ((x.days || []).includes(d.getUTCDay()) && t2(2) >= x.start && t2(-2) < x.end) maybe.push(c.id);
        }
        return json({ maybe, unknown });
      }
      case 'branchSave': {
        if (!who.admin) return json(fail('input', 'Only the admin can change the branch.'));
        const name = cleanNm(req.name);
        if (name.length < 3 || name.length > 60) return json(fail('input', 'Type the branch name (3 to 60 letters), like American Corner Matara.'));
        const logo = req.logo == null ? this.branch().logo : String(req.logo);
        if (!okLogo(logo)) return json(fail('input', 'That logo could not be used. Try a PNG or JPG under 80 KB.'));
        this.prop('branch', JSON.stringify({ name, logo }));
        return json({ ok: true, branch: this.branch() });
      }
      case 'syncClass': { let r; this.ctx.storage.transactionSync(() => { r = this.syncClass(q.k, q.students, q.ver); }); return json(r); }
      case 'enrolApplied': this.ctx.storage.transactionSync(() => {
        this.sql.exec('UPDATE enrol SET phone = ?, name = ? WHERE k = ? AND sid = ?', cleanPh(q.phone), cleanNm(q.name), q.k, q.sid);
        this.sql.exec('DELETE FROM people WHERE phone NOT IN (SELECT phone FROM enrol)');
      }); return json({ ok: true });
      case 'phoneCheck': {
        // may this student (sid in class k, or a new one) use this number?
        const ph = cleanPh(q.phone);
        if (!ph) return json({ ok: true });
        if (this.one('SELECT id FROM staff WHERE phone = ?', ph)) return json({ ok: false, staff: true });
        const me = q.sid ? this.one('SELECT phone FROM enrol WHERE k = ? AND sid = ?', q.k, String(q.sid)) : null;
        if (me && me.phone === ph) return json({ ok: true });
        const p = this.one('SELECT name FROM people WHERE phone = ?', ph);
        if (!p) return json({ ok: true });
        // the same person (same name) joining from another class is fine; a different person's number is not
        if (!me && cleanNm(q.name).toLowerCase() === cleanNm(p.name).toLowerCase()) return json({ ok: true });
        return json({ ok: false, other: p.name });
      }
      case 'maintFails': return json({ locked: Number(this.kvGet('maintfail') || 0) >= 10 });
      case 'maintFail': this.kvPut('maintfail', Number(this.kvGet('maintfail') || 0) + 1, 900); return json({ ok: true });
      case 'person': {
        const ph = cleanPh(q.phone), p = ph ? this.one('SELECT * FROM people WHERE phone = ?', ph) : null;
        return json({ person: p ? { name: p.name, masked: mask(p.name) } : null, staff: !!(ph && this.one('SELECT id FROM staff WHERE phone = ?', ph)) });
      }
      case 'enrolOf': return json({ enrol: this.all("SELECT k, sid FROM enrol WHERE phone = ? AND active != 'no'", cleanPh(q.phone)) });
      case 'login': return json(this.login(req, q.ip));
      case 'logout': this.sql.exec('DELETE FROM kv WHERE k = ?', 'tok:' + String(req.token || '')); return json({ ok: true });
      case 'who': return json(this.who(q.token));
      case 'staffPhones': return json({ phones: this.all('SELECT phone FROM staff').map(r => r.phone) });
      case 'staffFor': return json({ staff: this.staffFor(q.k) });
      case 'staffPhotos': { const p = {}; this.all("SELECT id, photo FROM staff WHERE photo != ''").forEach(r => { p[r.id] = r.photo; }); return json({ photos: p }); }
      case 'staffSave': return json(this.staffSave(req, who, false));
      case 'myAccount': {
        const r = this.staffSave(req, who, true);
        // a new password ends the other sign-ins (new salt), but keeps this one
        if (r.ok && req.password && /^[a-f0-9]{16,64}$/.test(String(req.token || ''))) {
          const st = this.one('SELECT salt FROM staff WHERE id = ?', who.me.id);
          this.kvPut('tok:' + req.token, JSON.stringify({ sid: who.me.id, ep: this.epoch(), s8: String(st.salt).slice(0, 8) }), 21600);
        }
        return json(r);
      }
      case 'adminPassword': {
        // the admin changes the main password with the current one; facilitators and coordinators stay signed in
        if (!who.admin) return json(fail('input', 'Only the admin can change the main password.'));
        const pw = String(req.password || '');
        if (hashPw(String(req.oldPassword || ''), this.prop('adminSalt')) !== this.prop('adminHash')) return json(fail('input', 'The current password is not right.'));
        if (pw.length < 8) return json(fail('input', 'The new password needs at least 8 characters.'));
        const salt = randHex(20), aep = String(Number(this.prop('aep') || '1') + 1);
        this.ctx.storage.transactionSync(() => { this.prop('adminSalt', salt); this.prop('adminHash', hashPw(pw, salt)); this.prop('aep', aep); });
        if (/^[a-f0-9]{16,64}$/.test(String(req.token || ''))) this.kvPut('tok:' + req.token, JSON.stringify({ sid: '', ep: this.epoch(), s8: '', aep }), 21600);
        return json({ ok: true });
      }
      case 'classSave': return json(this.classSave(req, who));
      case 'classDelete': return json(this.classDelete(req, who));
      case 'people': {
        if (!who.hub) return json(fail('input', 'Only the admin or a coordinator can see everyone.'));
        const en = {}; this.all('SELECT phone, k, sid FROM enrol').forEach(e => { (en[e.phone] = en[e.phone] || []).push({ k: e.k, sid: e.sid }); });
        const roles = {}; this.all('SELECT sid, k, role FROM roles').forEach(r => { (roles[r.sid] = roles[r.sid] || []).push({ k: r.k, role: r.role }); });
        return json({ ok: true, people: this.all('SELECT phone, name FROM people ORDER BY name').map(p => Object.assign(p, { classes: en[p.phone] || [] })),
          staff: this.all('SELECT * FROM staff ORDER BY name').map(s => Object.assign(this.staffOut(s), { roles: roles[s.id] || [] })) });
      }
      // the Danger zone: the main password is typed again for every step; 5 wrong tries lock it for 15 minutes
      case 'dangerCheck': {
        // each wrong password makes the next try wait longer (2, 4, 8 ... up to 60 seconds), never a long lock-out
        let f = { n: 0, at: 0 }; try { f = JSON.parse(this.kvGet('dangerfail') || 'null') || f; } catch (e) {}
        const wait = f.n ? Math.min(60, 2 ** f.n) * 1000 - (Date.now() - f.at) : 0;
        if (wait > 0) return json(fail('wait', 'Wrong password. Try again in ' + Math.ceil(wait / 1000) + ' seconds.'));
        if (!this.prop('adminHash') || hashPw(String(q.password || ''), this.prop('adminSalt')) !== this.prop('adminHash')) { this.kvPut('dangerfail', JSON.stringify({ n: f.n + 1, at: Date.now() }), 3600); return json(fail('password', 'The main password is not right.')); }
        this.sql.exec("DELETE FROM kv WHERE k = 'dangerfail'");
        return json({ ok: true });
      }
      case 'dangerDb': return json(dbTool(this.sql, fn => this.ctx.storage.transactionSync(fn), q.q || {}));
      case 'audit':
        this.sql.exec('INSERT INTO audit VALUES (?, ?, ?)', Date.now(), String(q.db || ''), String(q.what || '').slice(0, 300));
        this.sql.exec('DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY at DESC LIMIT 300)');
        return json({ ok: true });
      case 'auditList': return json({ audit: this.all('SELECT at, db, what FROM audit ORDER BY at DESC LIMIT 50') });
      case 'prune': {
        // what nothing points to any more: old sign-ins, enrolments and roles of deleted classes or accounts, people in no class
        const n = {};
        this.ctx.storage.transactionSync(() => {
          n.signins = this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now()).rowsWritten;
          n.enrolments = this.sql.exec('DELETE FROM enrol WHERE k NOT IN (SELECT id FROM classes)').rowsWritten;
          n.roles = this.sql.exec('DELETE FROM roles WHERE k NOT IN (SELECT id FROM classes) OR sid NOT IN (SELECT id FROM staff)').rowsWritten;
          n.people = this.sql.exec('DELETE FROM people WHERE phone NOT IN (SELECT phone FROM enrol)').rowsWritten;
          if (q.auditDays > 0) n.audit = this.sql.exec('DELETE FROM audit WHERE at < ?', Date.now() - q.auditDays * 86400000).rowsWritten;
        });
        return json({ ok: true, n });
      }
      case 'signOutAll': {
        // everyone signs in again, every trusted browser is forgotten; this admin's sign-in is renewed
        this.prop('epoch', Number(this.epoch()) + 1);
        this.sql.exec("DELETE FROM kv WHERE k LIKE 'tok:%' OR k LIKE 'trust:%' OR k LIKE 'loginfail%'");
        if (/^[a-f0-9]{16,64}$/.test(String(req.token || ''))) this.kvPut('tok:' + req.token, JSON.stringify({ sid: '', ep: this.epoch(), s8: '', aep: this.prop('aep') || '1' }), 21600);
        return json({ ok: true });
      }
      case 'unlockAll': return json({ ok: true, n: this.sql.exec("DELETE FROM kv WHERE k LIKE 'loginfail%' OR k = 'maintfail'").rowsWritten });
      case 'maint':
        if (req.op === 'setPassword') { const salt = randHex(20); this.prop('adminSalt', salt); this.prop('adminHash', hashPw(String(req.password || ''), salt)); this.prop('epoch', Number(this.epoch()) + 1); }
        if (req.op === 'unlock') this.sql.exec("DELETE FROM kv WHERE k LIKE 'loginfail%' OR k = 'maintfail'");
        // sign out everywhere: every token, every trusted browser
        if (req.op === 'reset') { this.prop('epoch', Number(this.epoch()) + 1); this.sql.exec("DELETE FROM kv WHERE k LIKE 'loginfail%' OR k LIKE 'trust:%' OR k LIKE 'tok:%'"); }
        return json({ ok: true });
    }
    return json(fail('action', 'Unknown step.'));
  }
}

class RolledBack extends Error { constructor(out) { super(out.message); this.out = out; } }

export class ClassRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.tabs = {};   // each table kept in memory after the first read; only this object writes, so it stays right
    this.tables();
    this.cur = { net: null, staff: null };
    this.env_ = this.makeEnv();
  }
  tables() {
    this.sql.exec('CREATE TABLE IF NOT EXISTS props (k TEXT PRIMARY KEY, v TEXT)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp INTEGER)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, why TEXT, data TEXT)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS backup_parts (bid INTEGER, n INTEGER, data TEXT, PRIMARY KEY (bid, n))');
    for (const t of Object.keys(TABLES)) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS t_${t} (${TABLES[t].map(c => `"${c}" TEXT`).join(', ')})`);
      const have = this.sql.exec(`PRAGMA table_info(t_${t})`).toArray().map(r => r.name);
      for (const c of TABLES[t]) if (!have.includes(c)) this.sql.exec(`ALTER TABLE t_${t} ADD COLUMN "${c}" TEXT`);
    }
  }

  // one request, all or nothing: its writes commit together, or (on an unexpected error) none of them do.
  // Where the request came from and who sent it are set in the same synchronous step, so two requests never mix them up.
  run(req, net, staff) {
    this.cur = { net, staff };
    let out;
    try {
      this.ctx.storage.transactionSync(() => {
        out = this.core().handle(req);
        if (out && out.ok === false && out.reason === 'error') throw new RolledBack(out);
      });
    } catch (e) {
      this.tabs = {};
      out = e instanceof RolledBack ? e.out : { ok: false, reason: 'error', message: 'Server error: ' + String(e && e.message || e) };
    } finally { this.cur = { net: null, staff: null }; }
    return out;
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
    // the class list's version: the Corner ignores an older list that arrives after a newer one
    const bumpVer = () => { const r = sql.exec("SELECT v FROM props WHERE k = 'sver'").toArray()[0]; sql.exec("INSERT INTO props (k, v) VALUES ('sver', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", String(Number(r ? r.v : 0) + 1)); };
    return {
      now: () => Date.now(),
      net: () => self.cur.net,
      routedStaff: () => self.cur.staff,
      read: t => (t === 'log' ? sql.exec(`SELECT * FROM t_log ORDER BY rowid`).toArray().map(r => { const o = {}; TABLES.log.forEach(c => { o[c] = r[c] == null ? '' : String(r[c]); }); return o; }) : readAll(t).map(plain)),
      readTail: (t, max) => sql.exec(`SELECT * FROM t_${t} ORDER BY rowid DESC LIMIT ?`, max).toArray().reverse().map(r => { const o = {}; TABLES[t].forEach(c => { o[c] = r[c] == null ? '' : String(r[c]); }); return o; }),
      append: (t, o) => {
        if (t === 'students') bumpVer();
        insert(t, o);
        if (self.tabs[t]) { const r = {}; TABLES[t].forEach(c => { r[c] = o[c] == null ? '' : String(o[c]); }); r._r = sql.exec('SELECT last_insert_rowid() AS r').one().r; self.tabs[t].push(r); }
      },
      // the core writes whole tables; only the rows that really changed are touched (the free plan counts written rows)
      write: (t, rows) => {
        if (t === 'students') bumpVer();
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
    // stored in pieces: one SQLite value can hold at most 2 MB, and a class with photos and a long log grows past that
    const text = JSON.stringify(this.snapshot()), PART = 500000;
    this.ctx.storage.transactionSync(() => {
      const bid = this.sql.exec("INSERT INTO backups (at, why, data) VALUES (?, ?, '') RETURNING id", at, why || '').one().id;
      for (let i = 0, n = 0; i < text.length; i += PART, n++) this.sql.exec('INSERT INTO backup_parts (bid, n, data) VALUES (?, ?, ?)', bid, n, text.slice(i, i + PART));
      this.sql.exec('DELETE FROM backups WHERE id NOT IN (SELECT id FROM backups ORDER BY id DESC LIMIT ?)', BACKUPS_KEPT);
      this.sql.exec('DELETE FROM backup_parts WHERE bid NOT IN (SELECT id FROM backups)');
    });
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
      if (hasData) { try { this.backupNow('before copying data in'); } catch (e) { return { ok: false, reason: 'error', message: 'Could not back up the current data first, so nothing was replaced: ' + String(e.message || e) }; } }
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

  // the admin's Danger zone in this class: a backup comes first (at most one every 10 minutes), and the cached tables are dropped after
  dangerBackup() {
    const last = Number(this.env_.getProp('dangerBak') || 0);
    if (Date.now() - last < 600000) return;
    this.backupNow('before a Danger zone change');
    this.env_.setProp('dangerBak', String(Date.now()));
  }
  danger(q) {
    const op = q.op.slice(7), E = this.env_;
    const after = r => { this.tabs = {}; return r; };
    if (op === 'db') {
      const d = q.q || {};
      const writes = d.op === 'cell' || d.op === 'del' || d.op === 'add' || (d.op === 'sql' && !READ_SQL.test(String(d.sql || '')));
      if (writes) {
        try { this.dangerBackup(); } catch (e) { return fail('error', 'Could not back up the class first, so nothing was changed: ' + String(e.message || e)); }
        // the Corner's copy of the students follows the class's list
        const r = dbTool(this.sql, fn => this.ctx.storage.transactionSync(fn), d);
        if (r.ok) { const v = Number(E.getProp('sver') || 0) + 1; E.setProp('sver', String(v)); }
        return after(r);
      }
      return dbTool(this.sql, fn => this.ctx.storage.transactionSync(fn), d);
    }
    if (op === 'prune') {
      const n = { log: 0, backups: 0, requests: 0, cache: 0 };
      const days = Math.max(Number(q.logDays) || 0, 0), keep = q.backupsKept === '' || q.backupsKept == null ? -1 : Math.floor(Number(q.backupsKept));
      this.ctx.storage.transactionSync(() => {
        if (days) n.log = this.sql.exec('DELETE FROM t_log WHERE CAST(ts AS INTEGER) < ?', Date.now() - days * 86400000).rowsWritten;
        if (keep >= 0) {
          n.backups = this.sql.exec('DELETE FROM backups WHERE id NOT IN (SELECT id FROM backups ORDER BY id DESC LIMIT ?)', keep).rowsWritten;
          this.sql.exec('DELETE FROM backup_parts WHERE bid NOT IN (SELECT id FROM backups)');
        }
        // profile key requests that were used, dismissed, or never answered in 30 days
        n.requests = this.sql.exec("DELETE FROM t_requests WHERE status IN ('used', 'dismissed') OR CAST(at AS INTEGER) < ?", Date.now() - 30 * 86400000).rowsWritten;
        n.cache = this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now()).rowsWritten;
      });
      const info = this.backupInfo(); info.count = this.sql.exec('SELECT COUNT(*) AS n FROM backups').one().n; E.setProp('backup', JSON.stringify(info));
      return after({ ok: true, n });
    }
    // new check-in codes: the QR on screen changes, and a code someone copied stops working
    if (op === 'rotateQr') { E.setProp('qrKey', E.random()); E.setProp('trusted', '{}'); return { ok: true }; }
    // a new term: the register, excuses, class days and log go; students, team and settings stay
    if (op === 'clearAttendance') {
      try { this.backupNow('before clearing attendance'); } catch (e) { return fail('error', 'Could not back up the class first, so nothing was cleared: ' + String(e.message || e)); }
      const n = {};
      this.ctx.storage.transactionSync(() => { for (const t of ['attendance', 'excuses', 'days', 'log']) n[t] = this.sql.exec(`DELETE FROM t_${t}`).rowsWritten; });
      return after({ ok: true, n });
    }
    return fail('action', 'Unknown step.');
  }

  // asked by the front door only (clients can't reach these paths)
  internal(q) {
    const E = this.env_;
    if (q.op === 'students') return { ver: Number(E.getProp('sver') || 0), students: E.read('students').map(r => ({ id: r.id, name: r.name, phone: r.phone, active: r.active })) };
    if (q.op === 'seed') {
      const photos = {}; E.read('profiles').forEach(r => { photos[r.id] = r.photo; });
      return { adminHash: E.getProp('adminHash'), adminSalt: E.getProp('adminSalt'), staff: E.read('staff').map(r => Object.assign({}, r, { photo: photos[r.id] || '' })),
        students: E.read('students').map(r => ({ id: r.id, name: r.name, phone: r.phone, active: r.active })) };
    }
    if (String(q.op || '').startsWith('danger:')) return this.danger(q);
    if (q.op === 'sched') {
      const st = this.run({ action: 'status' }, null, null);
      if (!st || !st.window) return { ok: false };
      const today = st.today;
      return { ok: true, sched: { days: st.window.days, start: st.window.start, end: st.window.end, tzOffset: st.window.tzOffset, extraUntil: st.extraUntil || 0,
        closedDay: E.getProp('closedDay') || '', cancelled: E.read('days').filter(r => r.status === 'cancelled' && r.date >= today).map(r => r.date).slice(0, 60) } };
    }
    if (q.op === 'newClass') { if (!E.getProp('settings')) E.setProp('settings', JSON.stringify({ idPrefix: q.prefix })); return { ok: true }; }
    if (q.op === 'applyPerson') {
      // the same person changed their name or number in another class (both tables change together, or neither)
      const rows = E.read('students'), st = rows.find(r => r.id === q.sid);
      if (!st || rows.some(r => r.phone === q.phone && r.id !== q.sid)) return { ok: false };
      const nameChanged = st.name !== q.name;
      try {
        this.ctx.storage.transactionSync(() => {
          st.name = q.name; st.phone = q.phone; E.write('students', rows);
          if (nameChanged) E.write('attendance', E.read('attendance').map(r => { if (r.id === q.sid) r.name = q.name; return r; }));
        });
      } catch (e) { this.tabs = {}; return { ok: false }; }
      return { ok: true };
    }
    return { ok: false };
  }

  async fetch(request) {
    const url = new URL(request.url);
    // a deleted class: everything it stored goes
    if (url.pathname === '/int' && request.headers.get('x-wipe') !== null) { await this.ctx.storage.deleteAll(); this.tabs = {}; this.tables(); return json({ ok: true }); }
    if (url.pathname === '/cron' && request.headers.get('x-cron') === '1' && request.method === 'POST') {
      if (this.backupInfo().auto) { try { this.backupNow('daily'); } catch (e) { const i = this.backupInfo(); i.error = String(e.message || e); i.errorAt = Date.now(); this.env_.setProp('backup', JSON.stringify(i)); } }
      this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now());
      return json({ ok: true });
    }
    if (url.pathname === '/int') return json(this.internal(await request.json()));
    let net = null, staff = null;
    try { net = JSON.parse(request.headers.get('x-att-net') || 'null'); } catch (e) {}
    try { staff = JSON.parse(request.headers.get('x-att-staff') || 'null'); } catch (e) {}
    if (request.method === 'GET') return json(this.run({ action: 'status' }, net, null));
    const body = await request.text();
    if (body.length > MAX_IMPORT) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    let req;
    try { req = JSON.parse(body); } catch (e) { return json({ ok: false, reason: 'input', message: 'Bad request.' }); }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return json({ ok: false, reason: 'input', message: 'Bad request.' });
    if (body.length > MAX_BODY && !(req.action === 'maint' && req.op === 'import')) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    if (req.action === 'maint') { this.cur = { net: null, staff: null }; return json(this.maint(req)); }
    return json(this.run(req, net, staff));
  }
}
