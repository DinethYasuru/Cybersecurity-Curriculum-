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

const { AttendanceCore, TABLES, SERVER_VERSION } = server;
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

/* ---------- web push: the day-before class reminders (RFC 8291 encryption, RFC 8292 VAPID) ----------
   The Corner makes its own VAPID key pair once (nothing to set up in Cloudflare). A notification goes only to
   the push services of the big browsers, never to any other address a page could hand in. */
const te = s => new TextEncoder().encode(s);
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => { s = String(s || '').replace(/-/g, '+').replace(/_/g, '/'); return Uint8Array.from(atob(s + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0)); };
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function hmacB(key, data) { const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', k, data)); }
const PUSH_HOSTS = ['fcm.googleapis.com', 'android.googleapis.com', 'push.services.mozilla.com', 'notify.windows.com', 'push.apple.com'];
function pushEndpointOk(ep, env) {
  let u; try { u = new URL(String(ep || '')); } catch (e) { return false; }
  if (String(ep).length > 600) return false;
  // the local server checks use a stand-in push service (attendance-worker/test); Cloudflare never has this variable
  const t = env && env.PUSH_TEST_URL ? String(env.PUSH_TEST_URL) : '';
  if (t && String(ep).startsWith(t)) return true;
  return u.protocol === 'https:' && !u.port && PUSH_HOSTS.some(h => u.hostname === h || u.hostname.endsWith('.' + h));
}
const pushKeysOk = sub => /^[A-Za-z0-9_-]{86,88}$/.test(String(sub.p256dh || '')) && /^[A-Za-z0-9_-]{21,24}$/.test(String(sub.auth || ''));
async function pushEncrypt(sub, text) {
  const ua = unb64u(sub.p256dh), auth = unb64u(sub.auth), EC = { name: 'ECDH', namedCurve: 'P-256' };
  const kp = await crypto.subtle.generateKey(EC, true, ['deriveBits']);
  const as = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: await crypto.subtle.importKey('raw', ua, EC, false, []) }, kp.privateKey, 256));
  const ikm = await hmacB(await hmacB(auth, shared), cat(te('WebPush: info\0'), ua, as, new Uint8Array([1])));
  const salt = crypto.getRandomValues(new Uint8Array(16)), prk = await hmacB(salt, ikm);
  const cek = (await hmacB(prk, te('Content-Encoding: aes128gcm\0\x01'))).slice(0, 16), nonce = (await hmacB(prk, te('Content-Encoding: nonce\0\x01'))).slice(0, 12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']), cat(te(text), new Uint8Array([2]))));
  const head = new Uint8Array(21); head.set(salt); new DataView(head.buffer).setUint32(16, 4096); head[20] = 65;
  return cat(head, as, ct);
}
async function vapidMake() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)), jwk: await crypto.subtle.exportKey('jwk', kp.privateKey) };
}
// one notification; the answer's status says if the browser is gone (404, 410: forget it)
async function pushSend(v, sub, payload) {
  const h = b64u(te(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))), c = b64u(te(JSON.stringify({ aud: new URL(sub.endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://dinethyasuru.github.io/Cybersecurity-Curriculum-/' })));
  const key = await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te(h + '.' + c));
  const r = await fetch(sub.endpoint, { method: 'POST', body: await pushEncrypt(sub, JSON.stringify(payload)),
    headers: { TTL: '43200', Urgency: 'normal', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', Authorization: 'vapid t=' + h + '.' + c + '.' + b64u(sig) + ', k=' + v.pub } });
  return r.status;
}
const WEEKDAY = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'], MONTH = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const niceDay = d => { const x = new Date(d + 'T00:00:00Z'); return WEEKDAY[x.getUTCDay()] + ' ' + x.getUTCDate() + ' ' + MONTH[x.getUTCMonth()]; };
// reminders go out the evening before, Sri Lanka time; a few each minute (one request may call only so many others)
const REMIND_AT = '18:00', REMIND_TZ = 330, PUSH_BATCH = 25;
/* ---------- live slides: a short code for the live class, so a laptop (no camera for the QR) joins by typing it ---------- */
const LIVE_DECK = /^Cyber_[A-Za-z0-9_]{1,60}\.html$/, LIVE_JOIN = /^[a-z2-9]{10}(\.[A-Za-z0-9_-]{40,120})?$/;
const LIVE_HOURS = 3;

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '86400' };
const json = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, CORS) });

/* ---------- the front door: every class at the American Corner ----------
   One Durable Object per class (its own database, the same AttendanceCore as before) and one "Corner"
   object for what classes share: the class list, people, facilitator accounts and their roles.
   The Cyber Security class keeps its original database (named 'class'). */
const STUDENT = { status: 1, lookup: 1, register: 1, checkin: 1, me: 1, profile: 1, keyRequest: 1, keySignIn: 1, profileSave: 1 };
// the student app: signing in (no account yet), then everything a signed-in student does
const APP_OPEN = { accRequest: 1, accActivate: 1, accLogin: 1, accFirst: 1 };
const APP = { app: 1, appFind: 1, appCheckin: 1, appExcuse: 1, appExcuseDrop: 1, appSave: 1, appLogout: 1, appHelp: 1, appPush: 1, appPushTest: 1 };
// the admin's (and coordinators') side of it: the requests inbox, keys, moving records to a new number, the on/off switch
// the live slides code: a deck asks for one (anyone may, it only points at that deck), a page turns a code into the deck's join link
const LIVE_OPEN = { liveOpen: 1, liveEnd: 1, liveFind: 1 };
const STU_ADMIN = { stuInbox: 1, stuReq: 1, stuKey: 1, stuMove: 1, stuMoveCheck: 1, stuLoginSet: 1, phoneKeySet: 1, waSave: 1 };
// the WhatsApp helper on the admin's laptop: its own key, and only these two steps (the next key to send, and "sent")
const WA_HELPER = { waNext: 1, waDone: 1 };
// steps after which the Firebase key queue looks at its slot at once
const FB_NOW = { accRequest: 1, accFirst: 1, areqIssue: 1, areqSet: 1, waSave: 1 };
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
    // who is asking (filled in as the request is checked) and the rows the classes changed: both go to the change log
    const T = { actor: { who: '', role: 'public', ip: request.headers.get('cf-connecting-ip') || '', action: '' }, rows: [] };
    const res = await serve(request, env, T);
    if (T.rows.length) {
      try { await env.CORNER.get(env.CORNER.idFromName('corner')).fetch('https://hub/op', { method: 'POST', body: JSON.stringify({ op: 'chg', rows: T.rows, _ctx: T.actor }) }); } catch (e) {}
    }
    return res;
  },
  async scheduled(event, env) {
    const hub = env.CORNER.get(env.CORNER.idFromName('corner'));
    // every minute: the Firebase queue (sends nothing unless it is set up and turned on)
    if (event.cron === '* * * * *') {
      try { await hub.fetch('https://hub/fbtick', { method: 'POST' }); } catch (e) {}
      // class reminders: once a day (the evening before) each class says its next days, then a few notifications go each minute
      const m = await (await hub.fetch('https://hub/remind', { method: 'POST', body: '{}' })).json();
      if (m.plan) {
        // only the classes where someone wants reminders (one request may call only so many others)
        const days = [];
        for (const c of (m.classes || []).slice(0, 40)) {
          try { const st = await (await env.CLASS.get(env.CLASS.idFromName(doName(c.id))).fetch('https://class/', { method: 'POST', body: JSON.stringify({ action: 'status' }) })).json(); days.push({ k: c.id, name: c.name, upcoming: st.upcoming || [] }); } catch (e) {}
        }
        await hub.fetch('https://hub/remind', { method: 'POST', body: JSON.stringify({ plan: m.plan, classes: days }) });
      }
      return;
    }
    const list = (await (await hub.fetch('https://hub/op', { method: 'POST', body: JSON.stringify({ op: 'classes' }) })).json()).classes || [{ id: 'cyber' }];
    for (const c of list) await env.CLASS.get(env.CLASS.idFromName(doName(c.id))).fetch('https://class/cron', { method: 'POST', headers: { 'x-cron': '1' } });
    await hub.fetch('https://hub/cron', { method: 'POST' });
  }
};

async function serve(request, env, T) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (request.method !== 'GET' && request.method !== 'POST') return json({ ok: false, reason: 'input', message: 'Bad request.' }, 405);
    // where the request came from (a Durable Object doesn't see it); a client can't set this
    const cf = request.cf || {};
    const net = JSON.stringify({ ip: request.headers.get('cf-connecting-ip') || '', asn: cf.asn || '', org: String(cf.asOrganization || '').slice(0, 60), city: String(cf.city || '').slice(0, 40) });
    const hubStub = env.CORNER.get(env.CORNER.idFromName('corner'));
    const H = async (op, data) => (await hubStub.fetch('https://hub/op', { method: 'POST', body: JSON.stringify(Object.assign({ op, _ctx: T.actor }, data || {})) })).json();
    // what a class changed comes back with its answer (_chg); it goes to the change log, never to the page
    const took = (k, r) => { if (r && Array.isArray(r._chg)) { let place = k; try { place = nameOf(k) || k; } catch (e) {} r._chg.forEach(x => T.rows.push(Object.assign({ place }, x))); delete r._chg; } return r; };
    const C = async (k, req, staff) => took(k, await (await env.CLASS.get(env.CLASS.idFromName(doName(k))).fetch('https://class/', { method: 'POST', headers: { 'x-att-net': net, 'x-att-staff': staff ? JSON.stringify(staff) : '' }, body: JSON.stringify(req) })).json());
    const I = async (k, req) => took(k, await (await env.CLASS.get(env.CLASS.idFromName(doName(k))).fetch('https://class/int', { method: 'POST', headers: req.op === 'wipe' ? { 'x-wipe': '1' } : {}, body: JSON.stringify(req) })).json());
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
    const loadClasses = async () => { const r = await H('classes'); CLASS_CACHE = { at: Date.now(), list: r.classes, branch: r.branch || BRANCH_DEFAULT, stuLogin: r.stuLogin !== false, phoneKey: !!r.phoneKey }; return CLASS_CACHE; };
    let fresh = !(CLASS_CACHE && Date.now() - CLASS_CACHE.at < CLASS_TTL);
    let cc = fresh ? await loadClasses() : CLASS_CACHE;
    let classes = cc.list;
    let pub = classes.filter(c => c.active !== 'no');
    const branch = cc.branch;
    // students sign in to the app before they check in (the admin can turn this off in Branch)
    let accounts = cc.stuLogin !== false;
    // the admin's switch: a number with no account yet may sign in the first time with the number itself (no WhatsApp key)
    let phoneKey = accounts && !!cc.phoneKey;
    // something changed the class list (or the branch): the next request in this copy reads it again
    const dropClasses = () => { CLASS_CACHE = null; };
    const known = k => pub.some(c => c.id === k);
    const nameOf = k => (classes.find(c => c.id === k) || {}).name || '';

    if (request.method === 'GET') {
      const r = await C(pub[0] ? pub[0].id : 'cyber', { action: 'status' });
      return json(Object.assign(r, { multi: true, branch, accounts, phoneKey, classes: pub.map(c => ({ id: c.id, name: c.name })) }));
    }
    const body = await request.text();
    if (body.length > MAX_IMPORT) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    let req;
    try { req = JSON.parse(body); } catch (e) { return json({ ok: false, reason: 'input', message: 'Bad request.' }); }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return json({ ok: false, reason: 'input', message: 'Bad request.' });
    if (body.length > MAX_BODY && !(req.action === 'maint' && req.op === 'import')) return json({ ok: false, reason: 'input', message: 'Request too big.' });
    const a = String(req.action || '');
    T.actor.action = a.slice(0, 40);
    // which server code runs and when Cloudflare deployed it (the admin's Overview compares it with the page)
    if (a === 'about') {
      const m = env.CF_VERSION_METADATA || {};
      return json({ ok: true, version: SERVER_VERSION, deploy: { id: String(m.id || ''), tag: String(m.tag || ''), at: String(m.timestamp || '') } });
    }
    if (req.phone && typeof req.phone === 'string') T.actor.who = cleanPh(req.phone) || req.phone.slice(0, 20);
    const rawK = String(req.k || '');
    // a class made in the last minute (by another copy of the Worker): read the list again before saying it's gone
    if (rawK && !known(rawK) && !fresh) { cc = await loadClasses(); fresh = true; classes = cc.list; pub = classes.filter(c => c.active !== 'no'); }
    let k = known(rawK) ? rawK : '';
    // a class that was archived or never existed (an old QR, or a change queued before the class was archived):
    // never fall back to another class, or the change would land in the wrong one
    const gone = rawK && !k;

    // a signed-in student (the token is their account's sign-in on this phone)
    const app = async a => {
      const dev = String(req.device || '').replace(/[^a-z0-9]/gi, '').slice(0, 40);
      const w = await H('accWho', { token: req.token });
      if (!w.ok) return fail('signin', 'Sign in again.');
      const me = w.me, phone = me.phone;
      T.actor.role = 'student'; T.actor.who = me.name + ' · ' + me.phone;
      const mine = async () => ((await H('enrolFull', { phone })).enrol || []).filter(e => known(e.k));
      if (a === 'app') {
        // every class they attend, with their record in each (at most CORNER_STATS classes per request)
        const all = await mine(), en = all.slice(0, CORNER_STATS);
        const classes = await Promise.all(en.map(async e => {
          const r = await I(e.k, { op: 'record', sid: e.sid });
          return { k: e.k, className: nameOf(e.k), id: e.sid, records: r.ok ? r.records : [], upcomingExcuses: r.ok ? r.upcomingExcuses : [], upcoming: r.ok ? r.upcoming || [] : [], error: r.ok ? '' : r.message };
        }));
        const x = await H('xreqMine', { phone });
        // live slides running for one of their classes (a laptop linked to that class started it), and their reminders
        const lv = await H('liveMine', { ks: all.map(e => e.k), phone, ep: req.ep });
        return { ok: true, me, classes, more: all.length > en.length, requests: x.requests || [], live: (lv.live || []).map(l => Object.assign(l, { className: nameOf(l.k) })), push: lv.push };
      }
      if (a === 'appFind') {
        // the code says which class: their own classes open now first, then any class open now (a new class they join)
        const code = String(req.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
        const en = await mine(), ids = en.map(e => e.k);
        let list;
        if (k) list = [k];
        else { const g = await H('openGuess', { now: Date.now() }); list = ids.filter(id => g.maybe.includes(id)).concat(pub.map(c => c.id).filter(id => g.maybe.includes(id) && !ids.includes(id))).slice(0, 15); }
        const cks = await Promise.all(list.map(async id => ({ id, c: await C(id, { action: 'codeCheck', code }) })));
        // a class that asks for no code matches without one: only their own classes count then, or the class the QR link named
        const hit = (cks.find(x => x.c.match && (ids.includes(x.id) || k || (x.c.need && code.length === 6))) || {}).id;
        if (!hit) return fail('code', code ? 'That code is not right, or it has changed. Scan the screen again.' : cks.some(x => x.c.open) ? 'Scan the QR on the classroom screen, or type the 6-letter code under it.' : 'No class you can check in to is open right now.');
        const lk = await C(hit, { action: 'lookup', phone, code, device: dev });
        if (!lk.ok) return Object.assign(lk, { k: hit, className: nameOf(hit) });
        if (!lk.found && !lk.canRegister) return Object.assign(fail('unknown', 'You are not on the class list of ' + nameOf(hit) + ' yet. Ask your facilitator to add you.'), { k: hit, className: nameOf(hit) });
        const e = en.find(x => x.k === hit);
        return { ok: true, k: hit, className: nameOf(hit), join: !lk.found, already: lk.already || '', date: lk.date, ticket: lk.ticket,
          student: { id: lk.found ? lk.student.id : '', name: e ? e.name : me.name, phone } };
      }
      if (a === 'appCheckin') {
        if (!k) return fail('noclass', 'That class is not running any more.');
        // a class they don't attend yet: they join it with their account's name first
        if (req.join) {
          const p = await H('person', { phone });
          const r = await C(k, { action: 'register', phone, name: p.person ? p.person.name : me.name, ticket: req.ticket, device: dev });
          if (!r.ok) return Object.assign(r, { k, className: nameOf(k) });
          await sync(k);
        }
        const r = await C(k, { action: 'checkin', phone, ticket: req.ticket, device: dev });
        return Object.assign(r, { k, className: nameOf(k) });
      }
      if (a === 'appExcuse') {
        const e = (await mine()).find(x => x.k === k), date = String(req.date || ''), reason = cleanNm(req.reason);
        if (!e) return fail('input', 'Pick one of your classes.');
        const days = (Date.parse(date) - Date.now()) / 86400000;
        if (!okDate(date) || days < -91 || days > 92) return fail('input', 'Pick a date within three months.');
        if (reason.length < 3 || reason.length > 160) return fail('input', 'Say why in a few words (up to 160 letters).');
        return await H('xreqAdd', { k, sid: e.sid, phone, name: e.name, date, reason });
      }
      if (a === 'appExcuseDrop') return await H('xreqDrop', { rid: req.rid, phone });
      if (a === 'appSave') {
        const r = await H('accSave', { phone, name: req.name, photo: req.photo, password: req.password, oldPassword: req.oldPassword });
        if (!r.ok || !(r.renamed || r.photo)) return r;
        // the new name and photo reach every class they attend
        for (const e of (await mine()).slice(0, CORNER_STATS)) {
          if (r.renamed && (await I(e.k, { op: 'applyPerson', sid: e.sid, name: r.me.name, phone })).ok) await sync(e.k);
          if (r.photo) await I(e.k, { op: 'setPhoto', sid: e.sid, photo: r.me.photo });
        }
        return r;
      }
      if (a === 'appLogout') {
        // this browser stops getting reminders for the account (all phones, when they sign out everywhere)
        await H('pushSet', { phone, on: false, sub: { endpoint: req.ep }, all: !!req.all });
        return await H('accLogout', { token: req.token, all: !!req.all });
      }
      if (a === 'appPush') return await H('pushSet', { phone, on: req.on !== false, sub: req.sub && typeof req.sub === 'object' ? req.sub : {} });
      if (a === 'appPushTest') return await H('pushTest', { phone, ep: req.ep });
      if (a === 'appHelp') return await H('areqHelp', { phone, other: req.other, note: req.note });
      return fail('action', 'Unknown step.');
    };

    // the WhatsApp helper: never a person's sign-in, never any other data (see Corner.waNext)
    if (WA_HELPER[a]) {
      T.actor.role = 'helper'; T.actor.who = 'WhatsApp helper';
      return json(await H(a, { key: req.helperKey, rid: req.rid, claim: req.claim, sent: req.sent === true, reason: req.reason }));
    }
    // the Firebase reader: "I set the flag, look now" (anyone may ask; it only makes the Worker read the slot)
    if (a === 'fbPoke') return json(await H('fbPoke'));
    if (LIVE_OPEN[a]) {
      T.actor.role = 'public'; T.actor.who = a === 'liveOpen' ? 'live slides' : '';
      return json(await H(a, { deck: req.deck, join: req.join, end: req.end, pk: req.pk, code: req.code, ip }));
    }
    if (a === 'login') return json(await H('login', { req, ip }));
    if (a === 'logout') return json(await H('logout', { req }));
    if (a === 'maint') {
      if (gone) return json(fail('noclass', 'That class is not running any more.'));
      k = k || 'cyber';
      // wrong-key tries are counted once for the whole Corner, not once per class
      if ((await H('maintFails')).locked) return json(fail('locked', 'Too many wrong server keys. Wait 15 minutes.'));
      if (typeof req.key !== 'string') req.key = '';
      T.actor.role = 'setup'; T.actor.who = 'SETUP_KEY';
      const r = await C(k, req);
      if (r.reason === 'key') { T.actor.role = 'public'; T.actor.who = ''; await H('maintFail'); }
      if (r.ok && req.op !== 'check') await H('maintOk', { step: String(req.op || '') });
      // the class checked the server key; sign-in lives in the Corner, so these steps happen there too
      if (r.ok && (req.op === 'setPassword' || req.op === 'unlock' || req.op === 'reset')) await H('maint', { req });
      // sign out everywhere: sign-in lives in the Corner, so one call ends every sign-in at every class
      // (other classes' QR secrets change in the Danger zone, one class at a time, so this never hits the per-request limit)
      if (r.ok && req.op === 'import') { await sync(k); await saveSched(k); }
      return json(r);
    }

    // the student app: sign in once, then check in, see every class, send excuses, keep a profile
    if (APP_OPEN[a]) return json(await H(a, { phone: req.phone, name: req.name, note: req.note, code: req.code, password: req.password, trust: req.trust, ip }));
    if (APP[a]) return json(await app(a));
    if (STUDENT[a] && accounts && a !== 'status') return json(fail('signin', 'Sign in to the attendance app first. This page shows how.'));
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
          return json(Object.assign(r, { multi: true, branch, accounts, phoneKey, k: k || '', className: k ? nameOf(k) : '', classes: pub.map(c => ({ id: c.id, name: c.name, open: opened.includes(c.id) })), pick: !k && opened.length > 1 }));
        }
        if (!k && a !== 'me') {
          if (opened.length > 1) return json({ ok: false, reason: 'pick', message: 'Pick your class first.', classes: pub.filter(c => opened.includes(c.id)).map(c => ({ id: c.id, name: c.name })) });
          k = pub[0] ? pub[0].id : 'cyber';
        }
      }
      if (a === 'status') { const r = await C(k, req); return json(Object.assign(r, { multi: true, branch, accounts, phoneKey, k, className: nameOf(k), classes: pub.map(c => ({ id: c.id, name: c.name })) })); }
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
    T.actor.role = who.admin ? 'admin' : who.coord ? 'coordinator' : 'facilitator';
    T.actor.who = who.me ? who.me.name + ' · ' + who.me.phone : 'Admin';
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
      // restore points: the Corner's and each class's own, newest first (the page goes through the databases one by one)
      if (op === 'points') return db === 'corner' ? await H('bkList') : await I(db, { op: 'danger:backups' });
      if (op === 'point') {
        const why = cleanNm(req.why).slice(0, 80) || 'Made by the admin';
        const r = db === 'corner' ? await H('bkMake', { why }) : await I(db, { op: 'danger:backup', why });
        if (r.ok) await note('Made a restore point: ' + why);
        return r;
      }
      if (op === 'restore') {
        if (String(req.confirm || '').trim().toUpperCase() !== 'RESTORE') return fail('input', 'Type RESTORE to confirm.');
        const r = db === 'corner' ? await H('bkRestore', { id: req.id }) : await I(db, { op: 'danger:restore', id: req.id });
        if (r.ok) {
          await note('Went back to the restore point of ' + new Date(Number(r.from) + 330 * 60000).toISOString().slice(0, 16).replace('T', ' ') + ' (a restore point of just before was made first)');
          if (db === 'corner') dropClasses(); else { await sync(db); await saveSched(db); }
        }
        return r;
      }
      return fail('action', 'Unknown step.');
    };
    // a starter account first chooses its own password
    if (who.me && who.me.mustSetup && a !== 'myAccount') return json({ ok: false, reason: 'setup', message: 'Set up your account first.', me: who.me });
    if (a === 'danger') return json(await danger());
    // the change log: the admin only (it shows who did what, and from which internet address)
    if (a === 'changes' || a === 'changesCheck') {
      if (!who.admin) return json(fail('input', 'Only the admin can see the change log.'));
      return json(a === 'changes' ? await H('chgList', { before: req.before, kind: req.kind, role: req.role, find: req.find, limit: req.limit }) : await H('chgVerify', { from: req.from }));
    }
    if (STU_ADMIN[a]) {
      if (!who.hub) return json(fail('input', 'Only the admin and coordinators can see student requests.'));
      const by = who.me ? who.me.name : 'Admin';
      if (a === 'stuInbox') return json(Object.assign(await H('areqList'), who.admin ? { wa: (await H('waState')).wa } : {}));
      if (a === 'stuReq') return json(await H('areqSet', { rid: req.rid, status: req.status, by }));
      if (a === 'stuKey') return json(await H('areqIssue', { phone: req.phone, name: req.name, by }));
      // before a move the page shows both numbers as they are now (names, classes, accounts)
      if (a === 'stuMoveCheck') {
        const from = cleanPh(req.from), to = cleanPh(req.to);
        if (!from || !to) return json(fail('input', 'Type both numbers, like 0771234567.'));
        return json(await H('moveCheck', { from, to }));
      }
      if (!who.admin) return json(fail('input', 'Only the admin can do this.'));
      if (a === 'stuLoginSet') { const r = await H('stuLoginSet', { on: !!req.on }); dropClasses(); return json(r); }
      if (a === 'phoneKeySet') { const r = await H('phoneKeySet', { on: req.on, known: req.known }); dropClasses(); return json(r); }
      if (a === 'waSave') return json(await H('waSave', { cfg: req.cfg, newKey: req.newKey === true, revoke: req.revoke === true }));
      // a student's records move to their new number: in each class the old number's student gets the new number,
      // and where the new number already had its own student (they registered again) the two become one
      const from = cleanPh(req.from), to = cleanPh(req.to);
      if (!from || !to) return json(fail('input', 'Type both numbers, like 0771234567.'));
      if (from === to) return json(fail('input', 'The two numbers are the same.'));
      const plan = await H('movePlan', { from, to });
      if (plan.staff) return json(fail('input', 'One of these numbers belongs to a facilitator.'));
      if (!plan.from.length) return json(fail('input', 'Nobody is on a class list with ' + from + '.'));
      const moved = [], failed = [];
      for (const e of plan.from.slice(0, CORNER_STATS)) {
        if (!classes.some(c => c.id === e.k)) continue;
        const t = plan.to.find(x => x.k === e.k);
        const r = t ? await I(e.k, { op: 'mergeStudent', from: t.sid, into: e.sid, phone: to }) : await I(e.k, { op: 'applyPerson', sid: e.sid, name: e.name, phone: to });
        if (r.ok) { await sync(e.k); moved.push(nameOf(e.k) + (t ? ' (' + t.sid + ' joined into ' + e.sid + ')' : '')); } else failed.push(nameOf(e.k));
      }
      if (moved.length) await H('moveDone', { from, to, rid: req.rid, by, what: moved.join(', ') });
      return json({ ok: moved.length > 0, moved, failed, message: moved.length ? '' : 'Nothing could be moved. ' + (failed.length ? 'Check ' + failed.join(', ') + ' in the Danger zone.' : '') });
    }
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
    if (!who.admin && !who.coord) T.actor.role = role === 'owner' ? 'lead' : 'facilitator';
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
    // this laptop presents the live slides for the class: its key makes the deck's live code show in the students' app
    if (a === 'presentKey') return json(await H('presentKey', { k, by: staff.name, drop: req.drop }));
    // an excuse a student sent from the app: accepted, it goes into the class's excuses
    if (a === 'excuseReq') {
      const x = (await H('xreqGet', { rid: req.rid })).request;
      if (!x || x.k !== k) return json(fail('input', 'That excuse request is gone.'));
      if (x.status !== 'new') return json({ ok: true, request: x });
      if (req.accept) { const e = await C(k, { action: 'excuse', id: x.sid, date: x.date, excused: true, reason: x.reason }, staff); if (!e.ok) return json(e); }
      return json(await H('xreqSet', { rid: x.rid, status: req.accept ? 'accepted' : 'declined', by: staff.name }));
    }
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
    if (r.ok && a === 'data') {
      r.corner.branch = branch; r.corner.accounts = accounts;
      if (who.hub) r.corner.stuReq = (await H('areqCount')).n;
      if (!who.coord) r.xreq = (await H('xreqFor', { k })).requests || [];
    }
    if (r.ok && SYNC_AFTER[a]) await sync(k);
    if (r.ok && SCHED_AFTER[a]) await saveSched(k);
    return json(r);
}

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
  'CREATE TABLE IF NOT EXISTS audit (at INTEGER, db TEXT, what TEXT)',
  // the student app: one account per mobile number, across every class (pv: a new password ends the other sign-ins)
  'CREATE TABLE IF NOT EXISTS accounts (phone TEXT PRIMARY KEY, name TEXT, salt TEXT, hash TEXT, pv INTEGER, photo TEXT, created INTEGER, last INTEGER)',
  // students asking the admin: a sign-in key (kind signin), or "I can't see my old records" (kind help, other = the old number)
  'CREATE TABLE IF NOT EXISTS areq (rid TEXT PRIMARY KEY, kind TEXT, phone TEXT, name TEXT, other TEXT, note TEXT, at INTEGER, code TEXT, status TEXT, updated INTEGER, by TEXT)',
  // excuses a student sent from the app, waiting for the class's facilitators
  'CREATE TABLE IF NOT EXISTS xreq (rid TEXT PRIMARY KEY, k TEXT, sid TEXT, phone TEXT, name TEXT, date TEXT, reason TEXT, at INTEGER, status TEXT, updated INTEGER, by TEXT)',
  // the change log of every database (see chgSetup): rows are only added, each sealed to the one before
  'CREATE TABLE IF NOT EXISTS changes (seq INTEGER PRIMARY KEY, at INTEGER, kind TEXT, who TEXT, role TEXT, ip TEXT, action TEXT, place TEXT, target TEXT, op TEXT, before TEXT, after TEXT, kid TEXT, seal TEXT)',
  // restore points of the Corner itself (classes, people, accounts, roles), like each class's backups
  'CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, why TEXT, data TEXT)',
  'CREATE TABLE IF NOT EXISTS backup_parts (bid INTEGER, n INTEGER, data TEXT, PRIMARY KEY (bid, n))',
  // the class reminders: each browser that said yes (its push address and keys) and the notifications waiting to go
  'CREATE TABLE IF NOT EXISTS push (endpoint TEXT PRIMARY KEY, phone TEXT, p256dh TEXT, auth TEXT, at INTEGER, sent INTEGER)',
  'CREATE TABLE IF NOT EXISTS pushq (n INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT, payload TEXT, at INTEGER)',
  // live slides codes: which deck and live room a code opens, the class it shows for (from a linked laptop), until when
  'CREATE TABLE IF NOT EXISTS live (code TEXT PRIMARY KEY, room TEXT, deck TEXT, j TEXT, k TEXT, by TEXT, at INTEGER, exp INTEGER, endh TEXT)'
];
const HUB_TABLES = ['props', 'classes', 'people', 'enrol', 'staff', 'roles', 'accounts', 'areq', 'xreq'];
// a restore keeps today's sign-ins and the log's key: only the data goes back
// (and the WhatsApp helper's key and switch: a restore must not bring back a key the admin replaced)
const RESTORE_KEEP_PROPS = { epoch: 1, aep: 1, inited: 1, chgKey: 1, backup: 1, dangerBak: 1, bkAt: 1, waHash: 1, wa: 1, vapid: 1, remindDay: 1 };
// a restore point is stored in pieces: one SQLite value holds at most 2 MB
function bkSave(sql, tx, why, text, kept) {
  const at = Date.now(), PART = 500000;
  let bid = 0;
  tx(() => {
    bid = sql.exec("INSERT INTO backups (at, why, data) VALUES (?, ?, '') RETURNING id", at, why || '').one().id;
    for (let i = 0, n = 0; i < text.length; i += PART, n++) sql.exec('INSERT INTO backup_parts (bid, n, data) VALUES (?, ?, ?)', bid, n, text.slice(i, i + PART));
    sql.exec('DELETE FROM backups WHERE id NOT IN (SELECT id FROM backups ORDER BY id DESC LIMIT ?)', kept);
    sql.exec('DELETE FROM backup_parts WHERE bid NOT IN (SELECT id FROM backups)');
  });
  return { id: bid, at };
}
function bkList(sql) {
  return sql.exec('SELECT b.id, b.at, b.why, LENGTH(b.data) + COALESCE((SELECT SUM(LENGTH(p.data)) FROM backup_parts p WHERE p.bid = b.id), 0) AS size FROM backups b ORDER BY b.id DESC').toArray();
}
function bkRead(sql, id) {
  const b = sql.exec('SELECT id, at, why, data FROM backups WHERE id = ?', Number(id)).toArray()[0];
  if (!b) return null;
  const text = b.data || sql.exec('SELECT data FROM backup_parts WHERE bid = ? ORDER BY n', b.id).toArray().map(r => r.data).join('');
  try { return { id: b.id, at: b.at, why: b.why, snap: JSON.parse(text) }; } catch (e) { return null; }
}
// the WhatsApp helper's limits: the admin picks within these (WhatsApp blocks numbers that send too much, too fast)
const WA_MAX = { perHour: 10, perDay: 40, gap: 2 };
const WA_DEFAULT = { on: false, perHour: 6, perDay: 20, gap: 4, from: '07:30', to: '20:30', known: true, base: '' };
const RP_NOW = 'rp:27';
const RP_WHY = 'Restore point before the security update (server 27)';
// student app sign-in: a key from the admin works once within KEY_DAYS; a phone stays signed in for STU_DAYS after its last use
const KEY_DAYS = 7, STU_DAYS = 180, KEY_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const newKey = () => { const a = new Uint8Array(8); crypto.getRandomValues(a); return Array.from(a, x => KEY_ABC[x & 31]).join(''); };
const okDate = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')) && !isNaN(Date.parse(d));
const cleanPh = v => { let d = String(v || '').replace(/\D/g, ''); if (d.length === 11 && d.startsWith('94')) d = '0' + d.slice(2); if (d.length === 9 && d[0] !== '0') d = '0' + d; return /^0\d{9}$/.test(d) ? d : ''; };
const cleanNm = v => String(v || '').trim().replace(/\s+/g, ' ');
const okName = n => n.length >= 2 && n.length <= 60 && /^[\p{L}\p{M} .'-]+$/u.test(n);
const mask = n => cleanNm(n).split(' ').map(w => w.slice(0, 2) + (w.length > 2 ? '*'.repeat(w.length - 2) : '')).join(' ');
const hashPw = (pw, salt) => { let h = salt + ':' + pw; for (let i = 0; i < 300; i++) h = SHA.hex(salt + h); return h; };
const fail = (reason, message) => ({ ok: false, reason, message });
// a password a classmate could guess in a few tries is refused: too short, only digits, the mobile number, or a common one
const WEAK_PW = /^(password|passw0rd|qwerty|qwertyuiop|asdfghjk|abcdefgh|abcd1234|iloveyou|letmein|welcome|sunshine|princess|football|admin123|student|computer|internet|cyber|hacker|lanka|srilanka|matara|american)\d*$/i;
const pwProblem = (pw, phone) => {
  pw = String(pw || '');
  if (pw.length < 8) return 'Choose a password with at least 8 characters.';
  if (/^\d+$/.test(pw)) return 'Use letters too, not only numbers.';
  if (/^(.)\1+$/.test(pw) || WEAK_PW.test(pw)) return 'That password is too easy to guess. Choose another one.';
  if (phone && pw.replace(/\D/g, '').includes(String(phone).slice(1))) return 'Don’t use your mobile number in your password.';
  return '';
};
// the admin's Danger zone: look at any table, change a cell, delete or add a row, or run SQL.
// Long values (photos, backups) are cut for the screen and can't be edited from there.
// Cloudflare's own tables (and the local test server's), and the change log with its helpers, which nobody edits
const DB_SKIP = /^(_cf_|sqlite_|__|changes$|chg_|backups$|backup_parts$)/;
// SQL that names the change log, its triggers or the schema is refused, so the log can't be switched off or rewritten
const SQL_GUARD = /\b(changes|chg_buf|chg_mute|chg_meta|backups|backup_parts|trigger|sqlite_master|sqlite_schema|sqlite_temp_master|writable_schema)\b|\bchg_\w+/i;
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
      if (SQL_GUARD.test(text)) return fail('input', 'The change log, the restore points and the database schema can’t be read or changed with SQL. See American Corner › Change log, and Restore points above.');
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

/* ---------- the change log ----------
   Every database has triggers that copy each changed row (before and after) into chg_buf, inside the same
   transaction as the change, so nothing that writes can skip them: the page, a student, the Danger zone's
   editor and SQL, an import or a restore. At the end of each request the rows go to the Corner's `changes`
   table with who did it, their role and where from. There, rows are only ever added: triggers refuse to edit
   or delete them, the Danger zone can't name the table, and each row carries a seal (an HMAC of the row and
   the seal before it, keyed by the SETUP_KEY secret, which is not in any database). A row changed or removed
   any other way breaks the chain, and the admin's Change log page says where. */
const CHG_VER = 1;
// tables that change all the time and mean nothing (caches, backups, the log's own rows)
// (push addresses are a browser's keys; reminders and live codes come and go, and their steps are logged as steps)
const CHG_SKIP = /^(kv|chg_buf|chg_mute|chg_meta|changes|backups|backup_parts|audit|push|pushq|live|_cf_.*|sqlite_.*|__.*)$/;
// props that are bookkeeping, not settings
const CHG_PROP_SKIP = "k NOT IN ('roomNet','backup','dangerBak','sver','idNext','inited','chgKey','bkAt','remindDay') AND k NOT LIKE 'ver:%' AND k NOT LIKE 'sched:%' AND k NOT LIKE 'rp:%'";
// what is never written into the log as it is: password hashes, keys, codes and pictures
const CHG_SECRET_COLS = { salt: 1, hash: 1, code: 1 };
const CHG_SECRET_PROPS = { adminHash: 1, adminSalt: 1, qrKey: 1, stuSecret: 1, trusted: 1, waHash: 1, vapid: 1 };
const CHG_PIC_COLS = { photo: 1, logo: 1 };
// how a row is named in the log
const CHG_ID = {
  t_students: o => o.id, t_attendance: o => o.id + ' ' + o.date, t_excuses: o => o.id + ' ' + o.date, t_days: o => o.date, t_profiles: o => o.id,
  t_requests: o => o.rid, t_staff: o => o.id, t_log: o => o.ts + ' ' + o.action, props: o => o.k, classes: o => o.id, people: o => o.phone,
  enrol: o => o.k + ' ' + o.sid, staff: o => o.id, roles: o => o.sid + ' ' + o.k, accounts: o => o.phone, areq: o => o.rid, xreq: o => o.rid
};
const CHG_ROWS = 200;  // rows kept in detail per request; a bigger change (an SQL update of every row) is summed up after that
// never lets a database fail to start: without triggers the log still has every step, sign-in and failed try, just not each row
function chgSetupSafe(sql) { try { chgSetup(sql); return ''; } catch (e) { return String(e && e.message || e); } }
function chgSetup(sql) {
  if (sql.exec("SELECT 1 AS x FROM sqlite_master WHERE type = 'table' AND name = 'changes'").toArray().length) {
    sql.exec("CREATE TRIGGER IF NOT EXISTS changes_keep_u BEFORE UPDATE ON changes BEGIN SELECT RAISE(ABORT, 'The change log can only grow.'); END");
    sql.exec("CREATE TRIGGER IF NOT EXISTS changes_keep_d BEFORE DELETE ON changes BEGIN SELECT RAISE(ABORT, 'The change log can only grow.'); END");
  }
  sql.exec('CREATE TABLE IF NOT EXISTS chg_buf (n INTEGER PRIMARY KEY AUTOINCREMENT, tbl TEXT, op TEXT, old TEXT, new TEXT)');
  sql.exec('CREATE TABLE IF NOT EXISTS chg_mute (x INTEGER)');
  sql.exec('CREATE TABLE IF NOT EXISTS chg_meta (k TEXT PRIMARY KEY, v TEXT)');
  const tables = sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").toArray().map(r => r.name).filter(n => !CHG_SKIP.test(n));
  const cols = {}; for (const t of tables) cols[t] = sql.exec(`PRAGMA table_info("${t}")`).toArray().map(c => c.name);
  // the triggers follow the tables: made again only when a table or column is new
  const sig = JSON.stringify([CHG_VER, cols]), have = sql.exec("SELECT v FROM chg_meta WHERE k = 'sig'").toArray()[0];
  if (have && have.v === sig) return;
  const old = sql.exec("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'chg\\_%' ESCAPE '\\'").toArray().map(r => r.name);
  for (const n of old) sql.exec(`DROP TRIGGER IF EXISTS "${n}"`);
  const quiet = 'NOT EXISTS (SELECT 1 FROM chg_mute)';
  for (const t of tables) {
    const c = cols[t], obj = p => 'json_object(' + c.map(x => `'${x}', ${p}."${x}"`).join(', ') + ')';
    const keep = p => (t === 'props' ? ' AND ' + CHG_PROP_SKIP.replace(/\bk\b/g, p + '.k') : '');
    // an upsert that changes nothing is not a change; the time of a student's last visit isn't either
    const diff = c.filter(x => !(t === 'accounts' && x === 'last')).map(x => `OLD."${x}" IS NOT NEW."${x}"`).join(' OR ');
    // new activity log lines are the activity log itself; only edits and deletes of them are changes
    if (t !== 't_log') sql.exec(`CREATE TRIGGER "chg_${t}_i" AFTER INSERT ON "${t}" WHEN ${quiet}${keep('NEW')} BEGIN INSERT INTO chg_buf (tbl, op, old, new) VALUES ('${t}', 'add', NULL, ${obj('NEW')}); END`);
    sql.exec(`CREATE TRIGGER "chg_${t}_u" AFTER UPDATE ON "${t}" WHEN ${quiet}${keep('NEW')} AND (${diff}) BEGIN INSERT INTO chg_buf (tbl, op, old, new) VALUES ('${t}', 'edit', ${obj('OLD')}, ${obj('NEW')}); END`);
    sql.exec(`CREATE TRIGGER "chg_${t}_d" AFTER DELETE ON "${t}" WHEN ${quiet}${keep('OLD')} BEGIN INSERT INTO chg_buf (tbl, op, old, new) VALUES ('${t}', 'del', ${obj('OLD')}, NULL); END`);
  }
  sql.exec("INSERT INTO chg_meta (k, v) VALUES ('sig', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", sig);
}
// a big step (restore, clear a term, prune) writes one summary line instead of every row
function chgQuiet(sql, fn, note) {
  let on = true; try { sql.exec('INSERT INTO chg_mute VALUES (1)'); } catch (e) { on = false; }
  try { return fn(); } finally {
    if (on) { try { sql.exec('DELETE FROM chg_mute'); if (note) sql.exec("INSERT INTO chg_buf (tbl, op, old, new) VALUES ('', 'note', NULL, ?)", JSON.stringify(note)); } catch (e) {} }
  }
}
const chgFp = v => '[hidden ' + SHA.hex('fp:' + v).slice(0, 6) + ']';
function chgClean(t, o) {
  if (!o) return o;
  const x = {};
  for (const k in o) {
    const v = o[k];
    if (v == null || v === '') { x[k] = v; continue; }
    if (CHG_SECRET_COLS[k]) x[k] = chgFp(v);
    else if (CHG_PIC_COLS[k]) x[k] = '[picture, ' + Math.round(String(v).length * 3 / 4096) + ' KB]';
    else x[k] = String(v).length > 600 ? String(v).slice(0, 600) + '…' : v;
  }
  if (t === 'props' && x.k) {
    if (CHG_SECRET_PROPS[x.k]) x.v = chgFp(o.v);
    else if (x.k === 'branch') { try { const b = JSON.parse(o.v); if (b.logo) b.logo = '[picture]'; x.v = JSON.stringify(b); } catch (e) {} }
  }
  return x;
}
// the triggers' rows, ready for the log: secrets hidden, a delete and an add of the same row joined into one edit
// (the class database rewrites a changed row that way), and only the columns that changed
function chgDrain(sql) {
  const raw = sql.exec('SELECT tbl, op, old, new FROM chg_buf ORDER BY n').toArray();
  if (!raw.length) return [];
  sql.exec('DELETE FROM chg_buf');
  const out = [], dels = {}, more = {};
  const P = v => { try { return v == null ? null : JSON.parse(v); } catch (e) { return null; } };
  for (const r of raw) {
    if (r.op === 'note') { out.push({ target: '', before: null, after: P(r.new) }); continue; }
    const before = P(r.old), after = P(r.new), name = CHG_ID[r.tbl] ? CHG_ID[r.tbl](before || after || {}) : '';
    const item = { table: r.tbl, row: String(name == null ? '' : name), op: r.op, before, after };
    if (r.op === 'del') { const key = r.tbl + '|' + item.row; (dels[key] = dels[key] || []).push(out.length); }
    if (r.op === 'add') {
      const key = r.tbl + '|' + item.row, hit = dels[key] && dels[key].length ? dels[key].shift() : -1;
      if (hit >= 0 && out[hit]) { out[hit].op = 'edit'; out[hit].after = after; continue; }
    }
    out.push(item);
  }
  const done = [];
  for (const it of out) {
    if (it.target === '') { done.push(it); continue; }
    let b = chgClean(it.table, it.before), a = chgClean(it.table, it.after);
    if (it.op === 'edit' && b && a) {
      const keepB = {}, keepA = {};
      for (const k in a) if (String(a[k]) !== String(b[k])) { keepB[k] = b[k]; keepA[k] = a[k]; }
      if (!Object.keys(keepA).length) continue;
      b = keepB; a = keepA;
    }
    if (done.length >= CHG_ROWS) { more[it.table] = (more[it.table] || 0) + 1; continue; }
    done.push({ target: it.table.replace(/^t_/, '') + (it.row ? ' ' + it.row : ''), op: it.op, before: b, after: a });
  }
  for (const t in more) done.push({ target: t.replace(/^t_/, ''), op: 'more', before: null, after: { rows: more[t], note: 'more rows changed in this step than the log lists one by one' } });
  return done;
}
const chgHex = a => a.map(x => ('0' + x.toString(16)).slice(-2)).join('');
const chgBody = r => JSON.stringify([r.seq, r.at, r.kind, r.who, r.role, r.ip, r.action, r.place, r.target, r.op, r.before, r.after, r.kid]);
// students' addresses are cut to the network (a.b.x.x); staff, the admin and failed sign-ins keep the full address
const chgIp = (ip, role) => {
  ip = String(ip || '');
  if (role !== 'student' && role !== 'public') return ip;
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':') + '::/64';
  return ip.replace(/^(\d+\.\d+)\.\d+\.\d+$/, '$1.x.x');
};

export class Corner extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    HUB_SQL.forEach(q => this.sql.exec(q));
    // setup = 'no': a starter account that has not chosen its own password yet
    if (!this.all('PRAGMA table_info(staff)').some(c => c.name === 'setup')) this.sql.exec("ALTER TABLE staff ADD COLUMN setup TEXT DEFAULT 'yes'");
    this.chgErr = chgSetupSafe(this.sql);
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
    // the page says which sign-in this is (as: 'admin' or 'staff'), so a number the browser filled in by itself
    // can never turn an admin sign-in into a facilitator one, even when both use the same password
    if (req.as === 'admin') req = Object.assign({}, req, { phone: '' });
    else if (req.as === 'staff' && !cleanPh(req.phone)) return fail('input', 'Type your mobile number, or choose Sign in as admin.');
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
  /* ----- the change log (see chgSetup) ----- */
  // the seal key is the SETUP_KEY secret, which no database holds; without one, a key kept here (weaker: the
  // Danger zone can't read it, but someone with the Cloudflare account could)
  chgKey() { const k = String(this.env.SETUP_KEY || ''); if (k.length >= 12) return k; let p = this.prop('chgKey'); if (!p) { p = randHex(32); this.prop('chgKey', p); } return p; }
  chgKid() { return SHA.hex('kid:' + this.chgKey()).slice(0, 8); }
  chgAdd(ctx, kind, items) {
    if (!items || !items.length) return;
    ctx = ctx || {};
    const key = this.chgKey(), kid = this.chgKid(), role = String(ctx.role || 'system').slice(0, 20);
    let last = this.one('SELECT seq, seal FROM changes ORDER BY seq DESC LIMIT 1') || { seq: 0, seal: '' };
    const txt = v => (v == null ? '' : (typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 4000));
    for (const it of items) {
      const r = { seq: last.seq + 1, at: Date.now(), kind: String(it.kind || kind), who: String(ctx.who || (role === 'system' ? 'server' : '')).slice(0, 120), role,
        ip: chgIp(ctx.ip, it.kind === 'alert' || kind === 'alert' ? 'staff' : role), action: String(ctx.action || '').slice(0, 40), place: String(it.place || 'American Corner').slice(0, 60),
        target: String(it.target || '').slice(0, 200), op: String(it.op || ''), before: txt(it.before), after: txt(it.after), kid };
      r.seal = chgHex(SHA.hmac(key, last.seal + '\n' + chgBody(r)));
      this.sql.exec('INSERT INTO changes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', r.seq, r.at, r.kind, r.who, r.role, r.ip, r.action, r.place, r.target, r.op, r.before, r.after, r.kid, r.seal);
      last = r;
    }
  }
  // a failed sign-in or a wrong key: kept with the full address, at most 60 an hour from one address
  alert(ctx, target, after) {
    const ip = String((ctx || {}).ip || ''), n = Number(this.kvGet('chga:' + ip) || 0) + 1;
    if (n <= 61) this.kvPut('chga:' + ip, n, 3600);
    if (n > 61) return;
    if (n === 61) after = { note: 'More than 60 failed tries from this address within an hour. The rest are not listed one by one.' };
    this.chgAdd(ctx, 'alert', [{ target, op: 'try', after }]);
  }
  chgFlush(ctx) { let items = []; try { items = chgDrain(this.sql); } catch (e) {} if (items.length) this.chgAdd(ctx, 'change', items); }
  chgCheckRow(r, prev, key, kid) { return r.kid !== kid ? null : chgHex(SHA.hmac(key, prev + '\n' + chgBody(r))) === r.seal; }
  chgList(q) {
    const lim = Math.min(Math.max(Number(q.limit) || 100, 1), 200), before = Number(q.before) || 0, where = [], args = [];
    if (before) { where.push('seq < ?'); args.push(before); }
    if (['change', 'signin', 'alert'].includes(q.kind)) { where.push('kind = ?'); args.push(q.kind); }
    if (q.role) { where.push('role = ?'); args.push(String(q.role)); }
    const f = String(q.find || '').trim().slice(0, 100);
    if (f) { where.push('(who LIKE ? OR ip LIKE ? OR action LIKE ? OR place LIKE ? OR target LIKE ? OR before LIKE ? OR after LIKE ?)'); for (let i = 0; i < 7; i++) args.push('%' + f + '%'); }
    const W = where.length ? ' WHERE ' + where.join(' AND ') : '';
    const rows = this.all(`SELECT * FROM changes${W} ORDER BY seq DESC LIMIT ?`, ...args, lim);
    // each row shown is checked against the seal of the row before it
    const key = this.chgKey(), kid = this.chgKid(), bySeq = {};
    rows.forEach(r => { bySeq[r.seq] = r; });
    const out = rows.map(r => {
      const p = r.seq === 1 ? { seal: '' } : bySeq[r.seq - 1] || this.one('SELECT seal FROM changes WHERE seq = ?', r.seq - 1);
      const o = Object.assign({}, r, { ok: p ? this.chgCheckRow(r, p.seal, key, kid) : false });
      delete o.seal; delete o.kid; return o;
    });
    const top = this.one('SELECT MAX(seq) AS m, COUNT(*) AS n FROM changes') || {};
    return { ok: true, rows: out, total: top.n || 0, last: top.m || 0, problem: this.chgErr || '', keyed: String(this.env.SETUP_KEY || '').length >= 12 };
  }
  // the whole chain, a few thousand rows per call (the page asks again from `next` until done)
  async chgVerify(from) {
    from = Math.max(1, Math.floor(Number(from) || 1));
    const enc = new TextEncoder(), kid = this.chgKid();
    const ck = await crypto.subtle.importKey('raw', enc.encode(this.chgKey()), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const rows = this.all('SELECT * FROM changes WHERE seq >= ? ORDER BY seq LIMIT 3000', from);
    const total = (this.one('SELECT MAX(seq) AS m FROM changes') || {}).m || 0;
    let prev = '';
    if (from > 1) { const p = this.one('SELECT seal FROM changes WHERE seq = ?', from - 1); if (!p) return { ok: true, total, broken: { seq: from - 1, why: 'Entry ' + (from - 1) + ' is missing.' } }; prev = p.seal; }
    let expect = from, old = 0;
    for (const r of rows) {
      if (r.seq !== expect) return { ok: true, total, broken: { seq: expect, why: 'Entries ' + expect + (r.seq - 1 > expect ? ' to ' + (r.seq - 1) : '') + ' are missing.' } };
      if (r.kid !== kid) old++;
      else {
        const s = chgHex(Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', ck, enc.encode(prev + '\n' + chgBody(r))))));
        if (s !== r.seal) return { ok: true, total, broken: { seq: r.seq, why: 'Entry ' + r.seq + ' was changed after it was written.' } };
      }
      prev = r.seal; expect++;
    }
    return { ok: true, total, checked: rows.length, old, next: expect, done: expect > total };
  }

  /* ----- restore points of the Corner ----- */
  snapshot() { const all = { kind: 'corner-copy', at: Date.now(), tables: {} }; for (const t of HUB_TABLES) all.tables[t] = this.all(`SELECT * FROM "${t}"`); return all; }
  backupNow(why) { return bkSave(this.sql, fn => this.ctx.storage.transactionSync(fn), why, JSON.stringify(this.snapshot()), BACKUPS_KEPT); }
  restore(id) {
    const b = bkRead(this.sql, id);
    if (!b || !b.snap || b.snap.kind !== 'corner-copy') return fail('input', 'That restore point is gone.');
    const when = new Date(b.at + 330 * 60000).toISOString().slice(0, 16).replace('T', ' ');
    this.backupNow('Before going back to ' + when);
    const n = {};
    chgQuiet(this.sql, () => this.ctx.storage.transactionSync(() => {
      for (const t of HUB_TABLES) {
        const rows = Array.isArray(b.snap.tables[t]) ? b.snap.tables[t] : [], cols = this.all(`PRAGMA table_info("${t}")`).map(c => c.name);
        if (t === 'props') { rows.filter(r => r && !RESTORE_KEEP_PROPS[r.k] && !/^rp:/.test(r.k)).forEach(r => this.prop(r.k, r.v == null ? '' : r.v)); n.settings = rows.length; continue; }
        this.sql.exec(`DELETE FROM "${t}"`);
        for (const r of rows) { const use = cols.filter(c => r && c in r); if (use.length) this.sql.exec(`INSERT INTO "${t}" (${use.map(c => `"${c}"`).join(', ')}) VALUES (${use.map(() => '?').join(', ')})`, ...use.map(c => r[c])); }
        n[t] = rows.length;
      }
    }), { restored: 'American Corner', from: when, why: b.why, rows: n });
    return { ok: true, n, from: b.at };
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

  /* ----- the student app: accounts, the admin's requests inbox, excuses sent from the app ----- */
  // counts tries in kv; true once over max within the window
  over(key, max, sec) { const n = Number(this.kvGet(key) || 0) + 1; if (n <= max + 1) this.kvPut(key, n, sec); return n > max; }
  stuLogin() { return this.prop('stuLogin') !== '0'; }
  // the name on the class lists wins over the one typed when asking for a key (the admin may fix it in Students, or a move brings it)
  accOut(a) {
    if (!a) return null;
    const p = this.one('SELECT name FROM people WHERE phone = ?', a.phone);
    if (p && p.name && p.name !== a.name) { a.name = p.name; this.sql.exec('UPDATE accounts SET name = ? WHERE phone = ?', a.name, a.phone); }
    return { phone: a.phone, name: a.name, photo: a.photo || '' };
  }
  stuTok(phone, pv) { const t = randHex(20); this.kvPut('stu:' + t, JSON.stringify({ phone, pv, at: Date.now() }), STU_DAYS * 86400); return t; }
  accWho(token) {
    if (!/^[a-f0-9]{40}$/.test(String(token || ''))) return { ok: false };
    let t = null; try { t = JSON.parse(this.kvGet('stu:' + token) || 'null'); } catch (e) {}
    const a = t ? this.one('SELECT * FROM accounts WHERE phone = ?', t.phone) : null;
    if (!a || Number(a.pv) !== Number(t.pv)) return { ok: false };
    // used again: the phone stays signed in for another STU_DAYS (written at most once a day)
    if (Date.now() - Number(t.at || 0) > 86400000) {
      this.kvPut('stu:' + token, JSON.stringify({ phone: a.phone, pv: a.pv, at: Date.now() }), STU_DAYS * 86400);
      this.sql.exec('UPDATE accounts SET last = ? WHERE phone = ?', Date.now(), a.phone);
    }
    return { ok: true, me: this.accOut(a) };
  }
  // step 1: a student asks for a sign-in key. The answer is the same for any number, so it tells nobody who studies here.
  accRequest(q) {
    const phone = cleanPh(q.phone), name = cleanNm(q.name), now = Date.now();
    if (!phone) return fail('phone', 'Type your mobile number, like 0771234567.');
    if (!okName(name)) return fail('name', 'Type your name with letters only.');
    if (this.over('arp:' + phone, 3, 3600) || this.over('ari:' + String(q.ip || ''), 20, 3600)) return fail('slow', 'Too many requests. Try again in an hour.');
    if (this.one('SELECT id FROM staff WHERE phone = ?', phone)) return fail('staff', 'That number belongs to a facilitator. Use Staff sign in at the bottom of the page.');
    const SENT = { ok: true, message: 'Request sent. The admin checks it and sends your key on WhatsApp. Then come back and tap I have a key.' };
    const open = this.one("SELECT rid FROM areq WHERE kind = 'signin' AND phone = ? AND status IN ('new', 'sent') AND at > ?", phone, now - KEY_DAYS * 86400000);
    if (open) { this.sql.exec('UPDATE areq SET name = ?, updated = ? WHERE rid = ?', name, now, open.rid); return SENT; }
    this.sql.exec("INSERT INTO areq VALUES (?, 'signin', ?, ?, '', ?, ?, ?, 'new', ?, '')", randHex(6), phone, name, String(q.note || '').slice(0, 200), now, newKey(), now);
    return SENT;
  }
  // step 2: the key from the admin, once, and the student's own password; the phone is signed in straight away
  accActivate(q) {
    const phone = cleanPh(q.phone), code = String(q.code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''), pw = String(q.password || ''), now = Date.now();
    if (!phone) return fail('phone', 'Type your mobile number, like 0771234567.');
    if (this.over('aak:' + phone, 8, 900) || this.over('aai:' + String(q.ip || ''), 40, 900)) return fail('slow', 'Too many tries. Wait 15 minutes.');
    const r = code.length === 8 ? this.one("SELECT * FROM areq WHERE kind = 'signin' AND phone = ? AND code = ? AND status IN ('new', 'sent') AND at > ?", phone, code, now - KEY_DAYS * 86400000) : null;
    if (!r) return fail('key', 'That key is not right for this number, or it has expired. Ask for a new one.');
    const weak = pwProblem(pw, phone); if (weak) return fail('password', weak);
    const cur = this.one('SELECT * FROM accounts WHERE phone = ?', phone), person = this.one('SELECT name FROM people WHERE phone = ?', phone);
    const salt = randHex(16), pv = cur ? Number(cur.pv) + 1 : 1;
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('INSERT OR REPLACE INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?, ?)', phone, person ? person.name : cur ? cur.name : r.name, salt, hashPw(pw, salt), pv, cur ? cur.photo : '', cur ? cur.created : now, now);
      this.sql.exec("UPDATE areq SET status = 'used', updated = ? WHERE rid = ?", now, r.rid);
    });
    return { ok: true, token: this.stuTok(phone, pv), trust: this.stuTrust(phone), me: this.accOut(this.one('SELECT * FROM accounts WHERE phone = ?', phone)) };
  }
  /* the admin's switch for the first sign-in: the mobile number the student gave is the key, no WhatsApp message.
     Off unless the admin turns it on; the WhatsApp key above still works either way (and is how a student gets
     back a number someone else took). Only a number with no app account yet, never a facilitator's, and unless
     the admin says otherwise only a number on a class list. The answer is the same for every number it refuses. */
  phoneKey() { let c = {}; try { c = JSON.parse(this.prop('phoneKey') || '{}'); } catch (e) {} return { on: !!c.on, known: c.known !== false }; }
  accFirst(q) {
    const c = this.phoneKey(), phone = cleanPh(q.phone), pw = String(q.password || ''), now = Date.now();
    if (!c.on || !this.stuLogin()) return fail('off', 'First sign-in with your number is not on. Tap Ask for a key.');
    if (!phone) return fail('phone', 'Type your mobile number, like 0771234567.');
    // per number, per internet address, and for everyone together (a flood of guessed numbers stops at the last)
    if (this.over('apf:' + phone, 5, 900) || this.over('apfi:' + String(q.ip || ''), 20, 900) || this.over('apf:all', 300, 3600)) return fail('slow', 'Too many tries. Wait 15 minutes.');
    const no = fail('number', 'This number can’t use first sign-in. Signed in before? Use your password. If not, tap Ask for a key.');
    if (this.one('SELECT id FROM staff WHERE phone = ?', phone) || this.one('SELECT phone FROM accounts WHERE phone = ?', phone)) return no;
    const person = this.one('SELECT name FROM people WHERE phone = ?', phone), listed = this.one("SELECT name FROM enrol WHERE phone = ? AND active != 'no'", phone);
    if (c.known && !person && !listed) return no;
    const name = person && person.name ? person.name : listed && listed.name ? listed.name : cleanNm(q.name);
    if (!okName(name)) return fail('name', 'Type your name with letters only.');
    const weak = pwProblem(pw, phone); if (weak) return fail('password', weak);
    const salt = randHex(16);
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?, ?)', phone, name, salt, hashPw(pw, salt), 1, '', now, now);
      // a key waiting to go out on WhatsApp isn't needed now (the helper and the Firebase queue skip used requests)
      this.sql.exec("UPDATE areq SET status = 'used', updated = ? WHERE kind = 'signin' AND phone = ? AND status IN ('new', 'sent')", now, phone);
    });
    return { ok: true, token: this.stuTok(phone, 1), trust: this.stuTrust(phone), me: this.accOut(this.one('SELECT * FROM accounts WHERE phone = ?', phone)) };
  }
  // a phone that signed in before gets its own count of wrong passwords, so a classmate typing wrong passwords
  // for someone else's number can't lock that student out of their own phone
  stuTrust(phone) { const t = randHex(16); this.kvPut('strust:' + t, phone, STU_DAYS * 86400); return t; }
  stuTrusted(t, phone) { return /^[a-f0-9]{32}$/.test(String(t || '')) && this.kvGet('strust:' + t) === phone; }
  accLogin(q) {
    const phone = cleanPh(q.phone), trust = this.stuTrusted(q.trust, phone), fk = 'sfail:' + (phone || 'x') + (trust ? ':t' : ''), ik = 'sfail:ip:' + String(q.ip || '');
    const f = Number(this.kvGet(fk) || 0), fi = Number(this.kvGet(ik) || 0);
    if (f >= 10 || (!trust && fi >= 60)) return fail('locked', 'Too many wrong passwords. Wait 15 minutes, or ask for a new key.');
    const a = phone ? this.one('SELECT * FROM accounts WHERE phone = ?', phone) : null;
    if (!a || hashPw(String(q.password || ''), a.salt) !== a.hash) {
      this.kvPut(fk, f + 1, 900); this.kvPut(ik, fi + 1, 900);
      // the same answer whether or not the number has an account, so it can't be used to find who studies here
      return fail('password', 'Wrong number or password. New here, or forgot it? Tap Ask for a key.');
    }
    this.sql.exec('DELETE FROM kv WHERE k = ?', fk);
    this.sql.exec('UPDATE accounts SET last = ? WHERE phone = ?', Date.now(), phone);
    return { ok: true, token: this.stuTok(phone, a.pv), trust: trust ? q.trust : this.stuTrust(phone), me: this.accOut(a) };
  }
  accSave(q, phone) {
    const a = this.one('SELECT * FROM accounts WHERE phone = ?', phone);
    if (!a) return fail('signin', 'Sign in again.');
    if (this.over('asv:' + phone, 30, 3600)) return fail('slow', 'Too many changes in a short time. Try again in an hour.');
    const out = { ok: true };
    if (q.name != null) { const n = cleanNm(q.name); if (!okName(n)) return fail('input', 'Type your name with letters only.'); out.renamed = n !== a.name; a.name = n; }
    if (q.photo != null) { if (q.photo !== '' && !okPhoto(q.photo)) return fail('input', 'That photo could not be used. Try another one.'); a.photo = q.photo; out.photo = true; }
    if (q.password != null) {
      if (hashPw(String(q.oldPassword || ''), a.salt) !== a.hash) return fail('input', 'Your current password is not right.');
      const weak = pwProblem(q.password, phone); if (weak) return fail('input', weak);
      a.salt = randHex(16); a.hash = hashPw(String(q.password), a.salt); a.pv = Number(a.pv) + 1;
      // a new password signs out every other phone; this one gets a new sign-in
      out.token = this.stuTok(phone, a.pv);
    }
    this.sql.exec('UPDATE accounts SET name = ?, photo = ?, salt = ?, hash = ?, pv = ? WHERE phone = ?', a.name, a.photo || '', a.salt, a.hash, a.pv, phone);
    if (out.renamed) this.sql.exec('UPDATE people SET name = ?, updated = ? WHERE phone = ?', a.name, Date.now(), phone);
    out.me = this.accOut(a);
    return out;
  }
  // the inbox: open requests and the last 30 days, with who each number is at the Corner
  // what the Corner knows about a number right now: the person's name, the app account and every class list it is on
  phoneInfo(ph, cls) {
    if (!ph) return null;
    if (!cls) { cls = {}; this.all('SELECT id, name FROM classes').forEach(c => { cls[c.id] = c.name; }); }
    const p = this.one('SELECT name FROM people WHERE phone = ?', ph), a = this.one('SELECT name FROM accounts WHERE phone = ?', ph);
    return { phone: ph, name: p ? p.name : '', account: !!a, accountName: a ? a.name : '',
      classes: this.all('SELECT k, sid, name FROM enrol WHERE phone = ?', ph).map(e => ({ k: e.k, sid: e.sid, sname: e.name, name: cls[e.k] || e.k })) };
  }
  areqList() {
    const now = Date.now(), cls = {}; this.all('SELECT id, name FROM classes').forEach(c => { cls[c.id] = c.name; });
    const info = ph => this.phoneInfo(ph, cls);
    return this.all("SELECT * FROM areq WHERE status IN ('new', 'sent') OR updated > ? ORDER BY at DESC LIMIT 300", now - 30 * 86400000)
      .map(r => Object.assign(r, { live: (r.status === 'new' || r.status === 'sent') && (r.kind !== 'signin' || r.at > now - KEY_DAYS * 86400000), who: info(r.phone), was: r.kind === 'help' ? info(cleanPh(r.other)) : null,
        waErr: r.kind === 'signin' && r.status === 'new' ? this.kvGet('wa:err:' + r.rid) || '' : '' }));
  }
  areqCount() { return this.one("SELECT COUNT(*) AS n FROM areq WHERE status = 'new' AND (kind != 'signin' OR at > ?)", Date.now() - KEY_DAYS * 86400000).n; }
  areqSet(q, by) {
    const r = this.one('SELECT * FROM areq WHERE rid = ?', String(q.rid || ''));
    if (!r) return fail('input', 'That request is gone.');
    const now = Date.now();
    // a fresh key: the old one stops working and the 7 days start again
    if (q.status === 'rekey') { if (r.kind !== 'signin') return fail('input', 'Only sign-in requests have keys.'); this.sql.exec("UPDATE areq SET code = ?, at = ?, status = 'new', updated = ?, by = ? WHERE rid = ?", newKey(), now, now, by, r.rid); }
    else if (['new', 'sent', 'dismissed', 'done'].includes(q.status)) {
      if (r.status === 'used') return { ok: true, request: r };
      // "done" on a missing-records request means the records were moved: while the old number is still on a class list, they were not
      const old = r.kind === 'help' && q.status === 'done' ? cleanPh(r.other) : '';
      if (old && this.one('SELECT sid FROM enrol WHERE phone = ?', old)) return fail('move', old + ' is still on a class list. Move the records first, or dismiss the request.');
      this.sql.exec('UPDATE areq SET status = ?, updated = ?, by = ? WHERE rid = ?', q.status, now, by, r.rid);
    }
    else return fail('input', 'Pick a step.');
    return { ok: true, request: this.one('SELECT * FROM areq WHERE rid = ?', r.rid) };
  }
  // the admin gives a key without a request (a new student, or someone who lost their password)
  areqIssue(q, by) {
    const phone = cleanPh(q.phone), p = phone ? this.one('SELECT name FROM people WHERE phone = ?', phone) : null, name = cleanNm(q.name) || (p ? p.name : '');
    if (!phone) return fail('input', 'Type a mobile number like 0771234567.');
    if (!okName(name)) return fail('input', 'Type the student’s name.');
    if (this.one('SELECT id FROM staff WHERE phone = ?', phone)) return fail('input', 'That number belongs to a facilitator.');
    const now = Date.now(), rid = randHex(6);
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE areq SET status = 'dismissed', updated = ? WHERE kind = 'signin' AND phone = ? AND status IN ('new', 'sent')", now, phone);
      this.sql.exec("INSERT INTO areq VALUES (?, 'signin', ?, ?, '', '', ?, ?, 'new', ?, ?)", rid, phone, name, now, newKey(), now, by);
    });
    return { ok: true, request: this.one('SELECT * FROM areq WHERE rid = ?', rid) };
  }
  // "I can't see my old records": the student (signed in with the new number) names the old one
  areqHelp(q, phone) {
    const a = this.one('SELECT name FROM accounts WHERE phone = ?', phone), other = String(q.other || '').trim().slice(0, 40), note = String(q.note || '').trim().slice(0, 300);
    if (!other && !note) return fail('input', 'Type your old number, or tell the admin what is missing.');
    if (cleanPh(other) === phone) return fail('input', 'That is the number you are signed in with. Type the old one.');
    if (this.over('arh:' + phone, 3, 86400)) return fail('slow', 'You already sent a few messages today. The admin will look at them.');
    const now = Date.now();
    this.sql.exec("DELETE FROM areq WHERE kind = 'help' AND phone = ? AND status = 'new'", phone);
    this.sql.exec("INSERT INTO areq VALUES (?, 'help', ?, ?, ?, ?, ?, '', 'new', ?, '')", randHex(6), phone, a ? a.name : '', cleanPh(other) || other, note, now, now);
    return { ok: true, message: 'Sent. The admin will check and move your records to this number.' };
  }
  // the admin moved the records: the new number keeps its account, the old number's account goes
  moveDone(q, by) {
    const from = cleanPh(q.from), to = cleanPh(q.to), now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const old = this.one('SELECT * FROM accounts WHERE phone = ?', from);
      if (old && !this.one('SELECT phone FROM accounts WHERE phone = ?', to)) this.sql.exec('UPDATE accounts SET phone = ?, pv = pv + 1 WHERE phone = ?', to, from);
      else this.sql.exec('DELETE FROM accounts WHERE phone = ?', from);
      if (q.rid) this.sql.exec("UPDATE areq SET status = 'done', updated = ?, by = ? WHERE rid = ?", now, by, String(q.rid));
      this.sql.exec('INSERT INTO audit VALUES (?, ?, ?)', now, 'American Corner', ('Moved records from ' + from + ' to ' + to + ': ' + String(q.what || '')).slice(0, 300));
    });
    return { ok: true };
  }
  xreqAdd(q) {
    const now = Date.now();
    if (this.over('xr:' + q.phone, 10, 86400)) return fail('slow', 'You sent many excuses today. Talk to your facilitator.');
    if (this.one("SELECT rid FROM xreq WHERE k = ? AND sid = ? AND date = ? AND status = 'new'", q.k, q.sid, q.date)) return fail('input', 'You already sent an excuse for that day. Your facilitator will look at it.');
    const rid = randHex(6);
    this.sql.exec("INSERT INTO xreq VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, '')", rid, q.k, q.sid, q.phone, q.name, q.date, q.reason, now, now);
    return { ok: true, request: this.one('SELECT * FROM xreq WHERE rid = ?', rid) };
  }

  /* ----- the WhatsApp helper: a small program on the admin's laptop sends sign-in keys from WhatsApp Web -----
     It has its own key (only its hash is kept here), made in Student requests. With it the helper can do two
     things and nothing else: take the next sign-in key to send, and say whether it went. The limits are kept
     here, not in the helper, so a changed or copied helper can't send more: a few messages an hour and a day,
     minutes apart, in the day only, one at a time, each only to the number that asked. Every key it takes and
     every message it sends goes into the change log. */
  waCfg() {
    let c = {}; try { c = JSON.parse(this.prop('wa') || '{}'); } catch (e) {}
    return Object.assign({}, WA_DEFAULT, c);
  }
  waState() {
    const c = this.waCfg(), sent = this.waSent(), now = Date.now();
    let fb = null; try { fb = JSON.parse(this.kvGet('wa:fb') || 'null'); } catch (e) {}
    return Object.assign({}, c, { hasKey: !!this.prop('waHash'), seen: Number(this.kvGet('wa:seen') || 0), firebase: this.fbSet(), fb,
      hour: sent.filter(t => t > now - 3600000).length, day: sent.filter(t => t > now - 86400000).length, last: sent.length ? sent[sent.length - 1] : 0 });
  }
  waSent() { try { return JSON.parse(this.kvGet('wa:sent') || '[]').filter(t => t > Date.now() - 86400000); } catch (e) { return []; } }
  waSave(q) {
    const c = this.waCfg(), x = q.cfg && typeof q.cfg === 'object' ? q.cfg : {};
    const num = (v, lo, hi, d) => { v = Math.round(Number(v)); return isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
    const hm = (v, d) => (/^([01]\d|2[0-3]):[0-5]\d$/.test(String(v || '')) ? String(v) : d);
    if (x.on != null) c.on = !!x.on;
    if (x.perHour != null) c.perHour = num(x.perHour, 1, WA_MAX.perHour, c.perHour);
    if (x.perDay != null) c.perDay = num(x.perDay, 1, WA_MAX.perDay, c.perDay);
    if (x.gap != null) c.gap = num(x.gap, WA_MAX.gap, 60, c.gap);
    if (x.from != null) c.from = hm(x.from, c.from);
    if (x.to != null) c.to = hm(x.to, c.to);
    if (x.known != null) c.known = !!x.known;
    if (x.base != null) {
      let u = null; try { u = new URL(String(x.base)); } catch (e) {}
      if (!u || !/^https?:$/.test(u.protocol) || String(x.base).length > 300 || u.searchParams.has('key')) return fail('input', 'The link to the attendance app is not right.');
      u.hash = ''; c.base = u.toString();
    }
    if (c.from >= c.to) return fail('input', 'The sending hours must start before they end.');
    if (c.on && !c.base) return fail('input', 'Open this page from the attendance app’s own address first.');
    let key = '';
    this.ctx.storage.transactionSync(() => {
      this.prop('wa', JSON.stringify(c));
      if (q.newKey) { key = 'wa_' + randHex(24); this.prop('waHash', SHA.hex('wa:' + key)); this.sql.exec("DELETE FROM kv WHERE k = 'wa:claim'"); }
      else if (q.revoke) { this.prop('waHash', ''); this.sql.exec("DELETE FROM kv WHERE k = 'wa:claim'"); }
    });
    // the key is shown once, to the admin; only its hash is kept
    return Object.assign({ ok: true, wa: this.waState() }, key ? { key } : {});
  }
  // the helper's key; wrong keys are counted like wrong passwords (10 from one address in 15 minutes lock it)
  waAuth(q, ctx) {
    const ip = String(ctx.ip || ''), h = this.prop('waHash');
    if (Number(this.kvGet('wafail:' + ip) || 0) >= 10 || Number(this.kvGet('wafail') || 0) >= 100) return fail('locked', 'Too many wrong helper keys. Wait 15 minutes.');
    if (!h || !/^wa_[a-f0-9]{48}$/.test(String(q.key || '')) || !sameText(SHA.hex('wa:' + q.key), h)) {
      this.kvPut('wafail', Number(this.kvGet('wafail') || 0) + 1, 900); this.kvPut('wafail:' + ip, Number(this.kvGet('wafail:' + ip) || 0) + 1, 900);
      this.alert(ctx, 'WhatsApp helper', { result: h ? 'wrong helper key' : 'no helper key is set' });
      return fail('key', 'The helper key is not right. Make a new one in Student requests.');
    }
    this.kvPut('wa:seen', Date.now(), 7 * 86400);
    if (!this.waCfg().on) return fail('off', 'Sending is turned off in Student requests.');
    return null;
  }
  waNext(q, ctx) {
    const bad = this.waAuth(q, ctx); if (bad) return bad;
    return this.waTake(ctx, 600);
  }
  // the next key to send, if the limits allow; it stays taken (one at a time) for `hold` seconds or until answered
  // `free`: the Firebase queue, where the admin's own reader sends: no hours, limits or waiting, only one at a time
  waTake(ctx, hold, free) {
    const c = this.waCfg(), now = Date.now(), sent = this.waSent();
    const wait = (sec, why) => ({ ok: true, wait: Math.max(30, Math.ceil(sec)), why });
    if (!free) {
      // in the day only (Sri Lanka time)
      const hm = new Date(now + 330 * 60000).toISOString().slice(11, 16);
      if (hm < c.from || hm >= c.to) return wait(15 * 60, 'Outside the sending hours (' + c.from + ' to ' + c.to + ').');
      const hour = sent.filter(t => t > now - 3600000), last = sent.length ? sent[sent.length - 1] : 0;
      if (sent.length >= c.perDay) return wait(sent[sent.length - c.perDay] + 86400000 - now, 'Daily limit reached (' + c.perDay + ').');
      if (hour.length >= c.perHour) return wait(hour[hour.length - c.perHour] + 3600000 - now, 'Hourly limit reached (' + c.perHour + ').');
      if (last && now - last < c.gap * 60000) return wait((last + c.gap * 60000 - now) / 1000, 'Waiting between messages.');
    }
    // one at a time: a key taken and not answered for 10 minutes counts as one try
    if (this.kvGet('wa:claim')) return wait(60, 'Waiting for the last message.');
    const list = this.all("SELECT * FROM areq WHERE kind = 'signin' AND status = 'new' AND at > ? AND at < ? ORDER BY at LIMIT 50", now - KEY_DAYS * 86400000, free ? now + 1 : now - 60000);
    // the helper tries a key twice; the Firebase queue tries again until the reader says the number has no WhatsApp
    const r = list.find(x => Number(this.kvGet('wa:try:' + x.rid) || 0) < (free ? 9 : 2) && !this.one('SELECT id FROM staff WHERE phone = ?', x.phone)
      && (!c.known || this.one("SELECT sid FROM enrol WHERE phone = ? AND active != 'no'", x.phone)));
    if (!r) return wait(120, 'Nothing to send.');
    const claim = randHex(8);
    this.kvPut('wa:claim', JSON.stringify({ rid: r.rid, claim, code: r.code, fb: !!free }), hold);
    this.kvPut('wa:try:' + r.rid, Number(this.kvGet('wa:try:' + r.rid) || 0) + 1, (KEY_DAYS + 1) * 86400);
    this.chgAdd(ctx, 'change', [{ target: 'areq ' + r.rid, op: 'helper took key', after: { phone: r.phone, name: r.name } }]);
    const link = new URL(c.base); link.searchParams.set('key', r.phone + '.' + r.code);
    const first = String(r.name || '').split(' ')[0];
    return { ok: true, rid: r.rid, claim, to: '94' + r.phone.slice(1), name: first, key: r.code.slice(0, 4) + '-' + r.code.slice(4), link: link.toString(),
      text: 'Hi ' + first + ', your key for the class attendance app:\n\n*' + r.code.slice(0, 4) + '-' + r.code.slice(4) + '*\n\nOpen this link and choose your password:\n' + link.toString() + '\n\nThe key works once, within 7 days. After that the app keeps you signed in.' };
  }
  waDone(q, ctx) {
    const bad = this.waAuth(q, ctx); if (bad && bad.reason !== 'off') return bad;
    let cl = null; try { cl = JSON.parse(this.kvGet('wa:claim') || 'null'); } catch (e) {}
    if (!cl || cl.rid !== String(q.rid || '') || !sameText(cl.claim, String(q.claim || ''))) return fail('input', 'That message was not handed out, or it is too late to answer it.');
    return this.waFinish(cl, q.sent === true, q.reason, ctx);
  }
  waFinish(cl, sentOk, reason, ctx) {
    this.sql.exec("DELETE FROM kv WHERE k = 'wa:claim'");
    const r = this.one('SELECT * FROM areq WHERE rid = ?', cl.rid);
    if (sentOk) {
      const sent = this.waSent(); sent.push(Date.now()); this.kvPut('wa:sent', JSON.stringify(sent), 2 * 86400);
      this.sql.exec("DELETE FROM kv WHERE k = ?", 'wa:err:' + cl.rid);
      // the admin may have sent it by hand, or given a new key, in the meantime: only the key that went is marked
      if (r && r.status === 'new' && r.code === cl.code) this.sql.exec("UPDATE areq SET status = 'sent', updated = ?, by = ? WHERE rid = ?", Date.now(), String(ctx.who || 'WhatsApp helper'), r.rid);
      return { ok: true };
    }
    const why = String(reason || 'not sent').replace(/[^\w .,:'()-]/g, '').slice(0, 80) || 'not sent';
    // a number that has no WhatsApp is not tried again; anything else gets one more try later
    if (/no whatsapp/i.test(why)) this.kvPut('wa:try:' + cl.rid, 9, (KEY_DAYS + 1) * 86400);
    this.kvPut('wa:err:' + cl.rid, why, (KEY_DAYS + 1) * 86400);
    this.chgAdd(ctx, 'change', [{ target: 'areq ' + cl.rid, op: 'helper not sent', after: { phone: r ? r.phone : '', reason: why } }]);
    return { ok: true };
  }

  /* ----- the Firebase queue: the same sending, through a Firebase Realtime Database -----
     One slot, /keyQueue/current: { rid, phone, name, text, flag: "pending" }. The admin's own WhatsApp side
     watches it, sends the message and sets flag to "sent" (or "failed", with a reason). The slot is looked at
     straight away when a student asks for a key (or the admin makes one), when the reader pokes the Worker
     (action fbPoke) after setting the flag, and once a minute in any case. A "sent" slot marks the request sent
     here, and the next key goes in at once: no hours or limits here, the reader decides how fast it sends.
     Settings: FIREBASE_URL in wrangler.toml; in Cloudflare the secret FIREBASE_SERVICE_ACCOUNT (or FIREBASE_SECRET). */
  fbSet() { return !!(String(this.env.FIREBASE_URL || '').startsWith('http') && (this.fbAccount() || String(this.env.FIREBASE_SECRET || ''))); }
  // the service account (its JSON key file, as the secret FIREBASE_SERVICE_ACCOUNT): the same sign-in the Admin SDK
  // uses, which the Admin SDK can't do on Cloudflare itself. The older database secret (FIREBASE_SECRET) still works.
  fbAccount() {
    try { const a = JSON.parse(String(this.env.FIREBASE_SERVICE_ACCOUNT || '')); return a && a.client_email && a.private_key ? a : null; } catch (e) { return null; }
  }
  // "access_token=…" from a signed JWT, kept for 50 minutes; or "auth=…" with the database secret
  async fbAuth() {
    const a = this.fbAccount();
    if (!a) return 'auth=' + encodeURIComponent(String(this.env.FIREBASE_SECRET));
    if (this.fbTok && this.fbTok.exp > Date.now()) return this.fbTok.q;
    const b64 = x => btoa(typeof x === 'string' ? x : String.fromCharCode(...new Uint8Array(x))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const aud = a.token_uri || 'https://oauth2.googleapis.com/token', now = Math.floor(Date.now() / 1000);
    const head = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' + b64(JSON.stringify({ iss: a.client_email, aud, iat: now, exp: now + 3600,
      scope: 'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email' }));
    const der = Uint8Array.from(atob(String(a.private_key).replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    const jwt = head + '.' + b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(head)));
    const r = await fetch(aud, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt });
    const t = await r.json().catch(() => ({}));
    if (!r.ok || !t.access_token) throw new Error('Google sign-in for the service account failed (' + r.status + ')');
    this.fbTok = { q: 'access_token=' + encodeURIComponent(t.access_token), exp: Date.now() + 50 * 60000 };
    return this.fbTok.q;
  }
  // one look at a time (two at once could empty a slot the other just filled); a call meanwhile looks again after
  async fbTick() {
    if (!this.fbSet()) return { ok: false, why: 'Firebase is not set up.' };
    if (this.fbBusy) { this.fbAgain = true; return this.fbBusy; }
    let r;
    try {
      do { this.fbAgain = false; this.fbBusy = this.fbLook(); r = await this.fbBusy; } while (this.fbAgain);
    } finally { this.fbBusy = null; }
    return r;
  }
  async fbLook() {
    const ctx = { role: 'helper', who: 'Firebase queue', ip: '', action: 'firebase' };
    const base = String(this.env.FIREBASE_URL).replace(/\/+$/, '') + '/keyQueue/';
    const fb = async (method, p, body) => {
      const r = await fetch(base + p + '.json?' + await this.fbAuth(), { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
      // a token Google stopped taking: a new one next time
      if (r.status === 401) this.fbTok = null;
      if (!r.ok) throw new Error('Firebase said ' + r.status);
      return r.json();
    };
    let why = '';
    const say = async w => {
      why = w;
      this.kvPut('wa:fb', JSON.stringify({ at: Date.now(), why: w }), 7 * 86400);
      // the reader can show why nothing comes (written on every look, so a status deleted by hand comes back)
      await fb('PUT', 'status', { why: w, at: Date.now() }).catch(() => {});
    };
    try {
      const c = this.waCfg(), cur = await fb('GET', 'current');
      let cl = null; try { cl = JSON.parse(this.kvGet('wa:claim') || 'null'); } catch (e) {}
      if (cur && cur.rid) {
        const mine = cl && cl.rid === cur.rid && sameText(cl.claim, String(cur.claim || ''));
        if (cur.flag === 'pending') {
          // still waiting for the reader; a slot the server no longer stands behind (turned off, key replaced) is taken away
          if (mine && c.on) { await say('Waiting for the reader to send it.'); return { ok: true, why }; }
          if (mine) this.sql.exec("DELETE FROM kv WHERE k = 'wa:claim'");
          await fb('DELETE', 'current');
        } else {
          if (mine) this.waFinish(cl, cur.flag === 'sent', cur.reason || cur.flag, ctx);
          await fb('DELETE', 'current');
        }
      }
      // the slot no longer holds the key handed out (deleted by hand in the console, or replaced): it goes in again
      // (a key handed out before this marked the queue's own keys counts as the queue's)
      if (cl && cl.fb !== false && this.kvGet('wa:claim')) this.sql.exec("DELETE FROM kv WHERE k = 'wa:claim'");
      if (!c.on) { await say('Sending is turned off in Student requests.'); return { ok: true, why }; }
      // the slot is held for up to 12 hours: the laptop may be off
      const n = this.waTake(ctx, 12 * 3600, true);
      if (!n.rid) { await say(n.why || 'Nothing to send.'); return { ok: true, why }; }
      try { await fb('PUT', 'current', { rid: n.rid, claim: n.claim, phone: n.to, name: n.name, key: n.key, link: n.link, text: n.text, flag: 'pending', at: Date.now() }); }
      catch (e) { this.sql.exec("DELETE FROM kv WHERE k = 'wa:claim'"); throw e; }
      await say('A key is waiting to be sent.');
      return { ok: true, why };
    } catch (e) {
      this.kvPut('wa:fb', JSON.stringify({ at: Date.now(), why: 'Problem: ' + String(e && e.message || e).slice(0, 80) }), 7 * 86400);
      return { ok: false, why: String(e && e.message || e) };
    } finally { this.chgFlush(ctx); }
  }

  /* ----- class reminders (web push) ----- */
  async vapid() {
    const get = () => { try { const v = JSON.parse(this.prop('vapid') || 'null'); return v && v.pub && v.jwk ? v : null; } catch (e) { return null; } };
    const had = get(); if (had) return had;
    const made = await vapidMake();
    // two first requests at once: the one saved first wins, so every browser subscribes to the same key
    const won = get(); if (won) return won;
    this.prop('vapid', JSON.stringify(made));
    return made;
  }
  pushSet(q) {
    const phone = cleanPh(q.phone), sub = q.sub && typeof q.sub === 'object' ? q.sub : {}, ep = String(sub.endpoint || '');
    if (!phone) return fail('input', 'Sign in again.');
    if (!q.on) {
      const n = q.all ? this.sql.exec('DELETE FROM push WHERE phone = ?', phone).rowsWritten : ep ? this.sql.exec('DELETE FROM push WHERE endpoint = ? AND phone = ?', ep, phone).rowsWritten : 0;
      return { ok: true, on: false, n };
    }
    const keys = sub.keys && typeof sub.keys === 'object' ? sub.keys : {};
    if (!pushEndpointOk(ep, this.env) || !pushKeysOk(keys)) return fail('input', 'This browser’s notifications can’t be used. Try Chrome, Edge, Firefox or Safari.');
    if (this.over('pushset:' + phone, 20, 3600)) return fail('slow', 'Too many tries. Try again in an hour.');
    this.sql.exec('INSERT INTO push (endpoint, phone, p256dh, auth, at, sent) VALUES (?, ?, ?, ?, ?, 0) ON CONFLICT(endpoint) DO UPDATE SET phone = excluded.phone, p256dh = excluded.p256dh, auth = excluded.auth, at = excluded.at',
      ep, phone, String(keys.p256dh), String(keys.auth), Date.now());
    // a few browsers per person: the oldest goes
    this.sql.exec('DELETE FROM push WHERE phone = ? AND endpoint NOT IN (SELECT endpoint FROM push WHERE phone = ? ORDER BY at DESC LIMIT 5)', phone, phone);
    return { ok: true, on: true };
  }
  async pushTest(q) {
    const phone = cleanPh(q.phone), sub = this.one('SELECT * FROM push WHERE endpoint = ? AND phone = ?', String(q.ep || ''), phone);
    if (!sub) return fail('input', 'Turn on reminders in this browser first.');
    if (this.over('pushtest:' + phone, 5, 3600)) return fail('slow', 'Enough tests for now. Try again in an hour.');
    let st = 0;
    try { st = await pushSend(await this.vapid(), sub, { t: 'Reminders are on', b: 'You get a message the evening before each class.', u: 'attendance.html', g: 'test' }); } catch (e) {}
    if (st === 404 || st === 410) { this.sql.exec('DELETE FROM push WHERE endpoint = ?', sub.endpoint); return fail('gone', 'This browser stopped taking notifications. Turn reminders on again.'); }
    return st >= 200 && st < 300 ? { ok: true } : fail('push', 'The browser’s notification service did not take it (' + (st || 'no answer') + '). Try again later.');
  }
  // a few waiting notifications go out (taken off the list first, so two minutes at once never send one twice)
  async pushTick() {
    const rows = this.all('SELECT n, endpoint, payload, at FROM pushq ORDER BY n LIMIT ?', PUSH_BATCH);
    if (!rows.length) return 0;
    this.sql.exec('DELETE FROM pushq WHERE n <= ?', rows[rows.length - 1].n);
    const v = await this.vapid();
    let sent = 0;
    for (const r of rows) {
      const sub = Date.now() - r.at < 12 * 3600000 ? this.one('SELECT * FROM push WHERE endpoint = ?', r.endpoint) : null;
      if (!sub) continue;
      let st = 0; try { st = await pushSend(v, sub, JSON.parse(r.payload)); } catch (e) {}
      if (st === 404 || st === 410) this.sql.exec('DELETE FROM push WHERE endpoint = ?', r.endpoint);
      else if (st >= 200 && st < 300) { sent++; this.sql.exec('UPDATE push SET sent = ? WHERE endpoint = ?', Date.now(), r.endpoint); }
    }
    return sent;
  }
  // every minute: send what waits; once a day after REMIND_AT (Sri Lanka time) the Worker brings each class's next days (q.classes),
  // and every student enrolled in a class that meets tomorrow gets one notification on each browser that said yes
  async remind(q) {
    const now = Date.now(), t = new Date(now + REMIND_TZ * 60000).toISOString(), today = t.slice(0, 10), hm = t.slice(11, 16);
    if (q.plan) {
      if (q.plan !== today || this.prop('remindDay') === today) return { ok: true, queued: 0 };
      this.prop('remindDay', today);
      const tomorrow = new Date(now + REMIND_TZ * 60000 + 86400000).toISOString().slice(0, 10), what = [];
      let n = 0;
      this.ctx.storage.transactionSync(() => {
        for (const c of (Array.isArray(q.classes) ? q.classes : [])) {
          const d = (Array.isArray(c.upcoming) ? c.upcoming : []).find(x => x && x.date === tomorrow);
          if (!d || !this.one("SELECT id FROM classes WHERE id = ? AND active != 'no'", String(c.k))) continue;
          const payload = JSON.stringify({ t: 'Class tomorrow: ' + String(c.name || '').slice(0, 60), b: niceDay(d.date) + ', ' + d.start + ' to ' + d.end + '.' + (d.note ? ' ' + String(d.note).slice(0, 120) : ''), u: 'attendance.html', g: 'class-' + c.k + '-' + d.date });
          const to = this.all("SELECT DISTINCT p.endpoint FROM push p JOIN enrol e ON e.phone = p.phone WHERE e.k = ? AND e.active != 'no'", String(c.k));
          to.forEach(r => this.sql.exec('INSERT INTO pushq (endpoint, payload, at) VALUES (?, ?, ?)', r.endpoint, payload, now));
          n += to.length; what.push(c.name + ' (' + to.length + ')');
        }
      });
      if (what.length) this.chgAdd({ role: 'system', who: 'Class reminders' }, 'change', [{ target: 'class reminders', op: 'step', after: { day: tomorrow, classes: what.join(', '), notifications: n } }]);
      return { ok: true, queued: n, sent: await this.pushTick() };
    }
    const sent = await this.pushTick();
    const at = /^\d\d:\d\d$/.test(this.prop('remindAt') || '') ? this.prop('remindAt') : REMIND_AT;
    const plan = hm >= at && this.prop('remindDay') !== today && this.one('SELECT 1 AS x FROM push LIMIT 1') ? today : '';
    const classes = plan ? this.all("SELECT DISTINCT c.id, c.name FROM push p JOIN enrol e ON e.phone = p.phone JOIN classes c ON c.id = e.k WHERE e.active != 'no' AND c.active != 'no'") : [];
    return { ok: true, plan, classes, sent };
  }
  /* ----- live slides codes ----- */
  liveCode() { const ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', b = crypto.getRandomValues(new Uint8Array(6)); return Array.from(b, x => ABC[x & 31]).join(''); }
  liveOpen(q, ctx) {
    const deck = String(q.deck || ''), j = String(q.join || ''), now = Date.now(), ip = String(q.ip || '');
    if (!LIVE_DECK.test(deck) || !LIVE_JOIN.test(j)) return fail('input', 'That is not a live class link.');
    if (this.over('lvo:' + ip, 30, 3600)) return fail('slow', 'Too many live classes from here. Try again in an hour.');
    this.sql.exec('DELETE FROM live WHERE exp < ?', now);
    const room = j.split('.')[0], exp = now + LIVE_HOURS * 3600000;
    // a laptop linked to a class (Live QR › Live slides): the class's students see this live class in their app
    let pk = null;
    if (/^[a-f0-9]{32}$/.test(String(q.pk || ''))) { try { pk = JSON.parse(this.kvGet('pk:' + SHA.hex(String(q.pk))) || 'null'); } catch (e) {} }
    const cls = pk ? this.one("SELECT id, name FROM classes WHERE id = ? AND active != 'no'", String(pk.k)) : null;
    const out = code => ({ ok: true, code, end: undefined, exp, k: cls ? cls.id : '', className: cls ? cls.name : '', linked: !!cls, pkBad: !!q.pk && !cls });
    // the same live class again (the deck reloaded, or its half-hourly refresh): the same code, kept a while longer
    const end = /^[a-f0-9]{32}$/.test(String(q.end || '')) ? String(q.end) : '';
    const had = end ? this.one('SELECT code, k FROM live WHERE room = ? AND endh = ?', room, SHA.hex('lvend:' + end)) : null;
    if (had) {
      this.sql.exec('UPDATE live SET exp = ?, deck = ?, j = ?, k = ?, by = ? WHERE code = ?', exp, deck, j, cls ? cls.id : '', cls ? String(pk.by || '') : '', had.code);
      if (cls && had.k !== cls.id) this.chgAdd(ctx, 'change', [{ place: cls.name, target: 'live slides', op: 'start', after: { code: had.code, deck, by: pk.by } }]);
      return Object.assign(out(had.code), { end });
    }
    if (this.one('SELECT COUNT(*) AS n FROM live').n >= 300 || this.over('lvo', 300, 3600)) return fail('slow', 'Too many live classes right now. Try again later.');
    let code = '';
    for (let i = 0; i < 20 && !code; i++) { const c = this.liveCode(); if (!this.one('SELECT 1 AS x FROM live WHERE code = ?', c)) code = c; }
    const fresh = randHex(16);
    this.sql.exec('INSERT INTO live (code, room, deck, j, k, by, at, exp, endh) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', code, room, deck, j, cls ? cls.id : '', cls ? String(pk.by || '') : '', now, exp, SHA.hex('lvend:' + fresh));
    if (cls) this.chgAdd(ctx, 'change', [{ place: cls.name, target: 'live slides', op: 'start', after: { code, deck, by: pk.by } }]);
    return Object.assign(out(code), { end: fresh });
  }
  liveEnd(q) {
    const end = /^[a-f0-9]{32}$/.test(String(q.end || '')) ? String(q.end) : '';
    return { ok: true, n: end ? this.sql.exec('DELETE FROM live WHERE code = ? AND endh = ?', String(q.code || '').toUpperCase(), SHA.hex('lvend:' + end)).rowsWritten : 0 };
  }
  // a typed code: right ones are never limited (a whole classroom shares one internet address), wrong ones are
  liveFind(q) {
    const code = String(q.code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''), ip = String(q.ip || '');
    if (Number(this.kvGet('lvf:' + ip) || 0) >= 40) return fail('slow', 'Too many wrong codes. Wait 10 minutes.');
    const r = code.length === 6 ? this.one('SELECT deck, j, exp FROM live WHERE code = ?', code) : null;
    if (!r || r.exp < Date.now()) { this.over('lvf:' + ip, 40, 600); return fail('code', 'That code is not right, or the live class has ended. Check the code on the screen.'); }
    return { ok: true, deck: r.deck, join: r.j };
  }
  async liveMine(q) {
    const ks = (Array.isArray(q.ks) ? q.ks : []).map(String).slice(0, 90), phone = cleanPh(q.phone), ep = String(q.ep || '');
    const live = ks.length ? this.all(`SELECT code, deck, j, k FROM live WHERE exp > ? AND k IN (${ks.map(() => '?').join(', ')}) ORDER BY at DESC`, Date.now(), ...ks).map(r => ({ code: r.code, deck: r.deck, join: r.j, k: r.k })).filter((l, i, a) => a.findIndex(x => x.k === l.k) === i) : [];
    const v = await this.vapid();
    return { live, push: { key: v.pub, mine: !!(ep && this.one('SELECT 1 AS x FROM push WHERE endpoint = ? AND phone = ?', ep, phone)), at: REMIND_AT } };
  }
  // a facilitator links this laptop to their class for 180 days (the key stays in the laptop's browser; the deck reads it)
  presentKey(q, ctx) {
    const cls = this.one('SELECT id, name FROM classes WHERE id = ?', String(q.k || ''));
    if (!cls) return fail('input', 'That class is gone.');
    if (q.drop) {
      const n = this.sql.exec('DELETE FROM kv WHERE k = ?', 'pk:' + SHA.hex(String(q.drop))).rowsWritten;
      if (n) this.chgAdd(ctx, 'change', [{ place: cls.name, target: 'live slides laptop', op: 'unlinked', after: { by: q.by } }]);
      return { ok: true };
    }
    const key = randHex(16);
    this.kvPut('pk:' + SHA.hex(key), JSON.stringify({ k: cls.id, by: String(q.by || ''), at: Date.now() }), 180 * 86400);
    this.chgAdd(ctx, 'change', [{ place: cls.name, target: 'live slides laptop', op: 'linked', after: { by: q.by, days: 180 } }]);
    return { ok: true, key, k: cls.id, className: cls.name, until: Date.now() + 180 * 86400000 };
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/fbtick') return json(await this.fbTick());
    if (url.pathname === '/remind') { const c = { role: 'system', who: 'Class reminders' }; try { return json(await this.remind(await request.json())); } finally { this.chgFlush(c); } }
    if (url.pathname === '/cron') {
      this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now());
      // a restore point every night, always
      try { this.backupNow('Nightly restore point'); } catch (e) {}
      return json({ ok: true });
    }
    const q = await request.json(), ctx = q._ctx && typeof q._ctx === 'object' ? q._ctx : { role: 'system' };
    // the first request after the security update keeps a restore point of everything as it was
    if (!this.prop(RP_NOW)) { if (this.prop('inited')) { try { this.backupNow(RP_WHY); } catch (e) {} } this.prop(RP_NOW, '1'); }
    if (q.op === 'chgVerify') return json(await this.chgVerify(q.from));
    // the Firebase reader set the flag: look at the slot now (at most 60 a minute, from anyone)
    if (q.op === 'fbPoke') { if (this.over('fbpoke', 60, 60)) return json(fail('slow', 'Too many. The slot is looked at every minute anyway.')); await this.fbTick(); return json({ ok: true }); }
    // whatever the step changed goes into the change log, with who asked for it
    let res;
    try { res = q.op === 'pushTest' || q.op === 'liveMine' ? json(await this[q.op](q, ctx)) : this.route(q, ctx); } finally { this.chgFlush(ctx); }
    // a new key, or a changed switch: the Firebase slot gets it straight away
    if (FB_NOW[q.op] && this.fbSet()) { try { await this.fbTick(); } catch (e) {} }
    return res;
  }
  route(q, ctx) {
    const req = q.req || {}, who = q.who;
    switch (q.op) {
      case 'inited': return json({ inited: !!this.prop('inited') });
      case 'init': return json(this.init(q.seed));
      case 'classes': return json({ classes: this.all('SELECT * FROM classes ORDER BY ord, name'), branch: this.branch(), stuLogin: this.stuLogin(), phoneKey: this.phoneKey().on });
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
      // wrong server keys: 10 from one address lock that address for 15 minutes; 200 from everywhere lock Setup for everyone
      // (before, 10 from anywhere locked everyone, so a student could keep the admin out of Setup)
      case 'maintFails': { const ip = String(ctx.ip || ''); return json({ locked: Number(this.kvGet('maintfail:ip:' + ip) || 0) >= 10 || Number(this.kvGet('maintfail') || 0) >= 200 }); }
      case 'maintFail': {
        const ip = String(ctx.ip || '');
        this.kvPut('maintfail', Number(this.kvGet('maintfail') || 0) + 1, 900); this.kvPut('maintfail:ip:' + ip, Number(this.kvGet('maintfail:ip:' + ip) || 0) + 1, 900);
        this.alert(Object.assign({}, ctx, { role: 'public', who: 'Setup' }), 'server key', { result: 'wrong server key' });
        return json({ ok: true });
      }
      case 'maintOk': this.chgAdd(Object.assign({}, ctx, { role: 'setup', who: 'SETUP_KEY' }), 'change', [{ target: 'Setup › Cloudflare server tools', op: 'step', after: { step: String(q.step || '') } }]); return json({ ok: true });
      case 'chg': this.chgAdd(ctx, 'change', (Array.isArray(q.rows) ? q.rows : []).slice(0, 2000)); return json({ ok: true });
      case 'chgList': return json(this.chgList(q));
      case 'bkList': return json({ ok: true, points: bkList(this.sql) });
      case 'bkMake': { const b = this.backupNow(String(q.why || 'Restore point').slice(0, 120)); return json({ ok: true, id: b.id, at: b.at }); }
      case 'bkRestore': return json(this.restore(q.id));
      case 'person': {
        const ph = cleanPh(q.phone), p = ph ? this.one('SELECT * FROM people WHERE phone = ?', ph) : null;
        return json({ person: p ? { name: p.name, masked: mask(p.name) } : null, staff: !!(ph && this.one('SELECT id FROM staff WHERE phone = ?', ph)) });
      }
      case 'enrolOf': return json({ enrol: this.all("SELECT k, sid FROM enrol WHERE phone = ? AND active != 'no'", cleanPh(q.phone)) });
      // the student app
      case 'stuLogin': return json({ on: this.stuLogin() });
      case 'stuLoginSet': this.prop('stuLogin', q.on ? '1' : '0'); return json({ ok: true, on: this.stuLogin() });
      case 'phoneKeySet': {
        const c = this.phoneKey();
        if (q.on != null) c.on = !!q.on;
        if (q.known != null) c.known = !!q.known;
        this.prop('phoneKey', JSON.stringify(c));
        return json({ ok: true, phoneKey: this.phoneKey() });
      }
      case 'accRequest': return json(this.accRequest(q));
      case 'accActivate': {
        const r = this.accActivate(q), c = Object.assign({}, ctx, { who: cleanPh(q.phone) || String(q.phone || '').slice(0, 20), role: 'student' });
        if (r.ok) this.chgAdd(c, 'signin', [{ target: 'student app', op: 'key used', after: { phone: r.me.phone, name: r.me.name } }]);
        else if (r.reason === 'key' || r.reason === 'slow') this.alert(c, 'student app key', { phone: cleanPh(q.phone), result: r.reason === 'slow' ? 'too many tries' : 'wrong key' });
        return json(r);
      }
      case 'accFirst': {
        const r = this.accFirst(q), c = Object.assign({}, ctx, { who: cleanPh(q.phone) || String(q.phone || '').slice(0, 20), role: 'student' });
        if (r.ok) this.chgAdd(c, 'signin', [{ target: 'student app', op: 'first sign-in with number', after: { phone: r.me.phone, name: r.me.name } }]);
        else if (r.reason === 'number' || r.reason === 'slow') this.alert(c, 'student app first sign-in', { phone: cleanPh(q.phone), result: r.reason === 'slow' ? 'too many tries' : 'number not allowed' });
        return json(r);
      }
      case 'accLogin': {
        const r = this.accLogin(q), c = Object.assign({}, ctx, { who: cleanPh(q.phone) || String(q.phone || '').slice(0, 20), role: 'student' });
        if (r.ok) this.chgAdd(c, 'signin', [{ target: 'student app', op: 'signin', after: { phone: r.me.phone, name: r.me.name } }]);
        else if (r.reason === 'password' || r.reason === 'locked') this.alert(c, 'student app sign-in', { phone: cleanPh(q.phone), result: r.reason === 'locked' ? 'locked out' : 'wrong password' });
        return json(r);
      }
      case 'accWho': return json(this.accWho(q.token));
      case 'accSave': return json(this.accSave(q, q.phone));
      case 'accLogout': {
        let t = null; try { t = JSON.parse(this.kvGet('stu:' + String(q.token || '')) || 'null'); } catch (e) {}
        this.sql.exec('DELETE FROM kv WHERE k = ?', 'stu:' + String(q.token || ''));
        // sign out everywhere: every phone's sign-in for this account stops working
        if (t && q.all) this.sql.exec('UPDATE accounts SET pv = pv + 1 WHERE phone = ?', t.phone);
        return json({ ok: true });
      }
      case 'pushSet': {
        const r = this.pushSet(q);
        if (r.ok && (r.on || r.n)) this.chgAdd(Object.assign({}, ctx, { role: 'student' }), 'change', [{ target: 'class reminders', op: r.on ? 'on' : 'off', after: { phone: cleanPh(q.phone), browsers: r.on ? 1 : r.n } }]);
        return json(r);
      }
      case 'liveOpen': return json(this.liveOpen(q, ctx));
      case 'liveEnd': return json(this.liveEnd(q));
      case 'liveFind': return json(this.liveFind(q));
      case 'presentKey': return json(this.presentKey(q, ctx));
      case 'enrolFull': return json({ enrol: this.all("SELECT k, sid, name FROM enrol WHERE phone = ? AND active != 'no'", cleanPh(q.phone)) });
      case 'areqList': return json({ ok: true, requests: this.areqList(), on: this.stuLogin(), phoneKey: this.phoneKey() });
      case 'waState': return json({ wa: this.waState() });
      case 'waSave': return json(this.waSave(q));
      case 'waNext': return json(this.waNext(q, ctx));
      case 'waDone': return json(this.waDone(q, ctx));
      case 'areqCount': return json({ n: this.areqCount() });
      case 'areqSet': return json(this.areqSet(q, q.by || ''));
      case 'areqIssue': return json(this.areqIssue(q, q.by || ''));
      case 'areqHelp': return json(this.areqHelp(q, q.phone));
      case 'movePlan': {
        const from = cleanPh(q.from), to = cleanPh(q.to), p = this.one('SELECT name FROM people WHERE phone = ?', from);
        return json({ from: this.all('SELECT k, sid, name FROM enrol WHERE phone = ?', from), to: this.all('SELECT k, sid, name FROM enrol WHERE phone = ?', to), name: p ? p.name : '',
          staff: !!this.one('SELECT id FROM staff WHERE phone IN (?, ?)', from, to) });
      }
      case 'moveDone': return json(this.moveDone(q, q.by || ''));
      case 'moveCheck': { const from = cleanPh(q.from), to = cleanPh(q.to);
        return json({ ok: true, from: this.phoneInfo(from) || { phone: '', classes: [] }, to: this.phoneInfo(to) || { phone: '', classes: [] }, staff: !!this.one('SELECT id FROM staff WHERE phone IN (?, ?)', from, to) }); }
      case 'xreqAdd': return json(this.xreqAdd(q));
      case 'xreqMine': return json({ requests: this.all('SELECT rid, k, sid, date, reason, at, status, updated FROM xreq WHERE phone = ? AND (status = ? OR updated > ?) ORDER BY date DESC', q.phone, 'new', Date.now() - 60 * 86400000) });
      case 'xreqFor': return json({ requests: this.all('SELECT * FROM xreq WHERE k = ? AND (status = ? OR updated > ?) ORDER BY at DESC LIMIT 200', q.k, 'new', Date.now() - 30 * 86400000) });
      case 'xreqGet': return json({ request: this.one('SELECT * FROM xreq WHERE rid = ?', String(q.rid || '')) });
      case 'xreqSet': this.sql.exec('UPDATE xreq SET status = ?, updated = ?, by = ? WHERE rid = ?', q.status, Date.now(), q.by || '', String(q.rid || '')); return json({ ok: true, request: this.one('SELECT * FROM xreq WHERE rid = ?', String(q.rid || '')) });
      case 'xreqDrop': return json({ ok: true, n: this.sql.exec("DELETE FROM xreq WHERE rid = ? AND phone = ? AND status = 'new'", String(q.rid || ''), q.phone).rowsWritten });
      case 'login': {
        const r = this.login(req, q.ip), main = req.as === 'admin' || !req.phone;
        const c = Object.assign({}, ctx, { who: r.ok ? (r.me ? r.me.name + ' · ' + r.me.phone : 'Admin') : main ? 'main password' : cleanPh(req.phone) || String(req.phone || '').slice(0, 20),
          role: r.ok ? (r.corner.admin ? 'admin' : r.corner.coordinator ? 'coordinator' : 'facilitator') : 'public' });
        if (r.ok) this.chgAdd(c, 'signin', [{ target: main ? 'admin sign-in' : 'staff sign-in', op: 'signin', after: { browser: req.trust && r.trust === req.trust ? 'trusted' : 'new' } }]);
        else if (r.reason === 'password' || r.reason === 'locked') this.alert(c, main ? 'admin sign-in' : 'staff sign-in', { number: main ? '' : cleanPh(req.phone), result: r.reason === 'locked' ? 'locked out' : 'wrong password' });
        return json(r);
      }
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
        if (!this.prop('adminHash') || hashPw(String(q.password || ''), this.prop('adminSalt')) !== this.prop('adminHash')) { this.kvPut('dangerfail', JSON.stringify({ n: f.n + 1, at: Date.now() }), 3600); this.alert(ctx, 'Danger zone', { result: 'wrong main password' }); return json(fail('password', 'The main password is not right.')); }
        this.sql.exec("DELETE FROM kv WHERE k = 'dangerfail'");
        return json({ ok: true });
      }
      case 'dangerDb': return json(dbTool(this.sql, fn => this.ctx.storage.transactionSync(fn), q.q || {}));
      case 'audit':
        this.sql.exec('INSERT INTO audit VALUES (?, ?, ?)', Date.now(), String(q.db || ''), String(q.what || '').slice(0, 300));
        this.chgAdd(ctx, 'change', [{ place: String(q.db || ''), target: 'Danger zone', op: 'step', after: { what: String(q.what || '').slice(0, 300) } }]);
        this.sql.exec('DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY at DESC LIMIT 300)');
        return json({ ok: true });
      case 'auditList': return json({ audit: this.all('SELECT at, db, what FROM audit ORDER BY at DESC LIMIT 50') });
      case 'prune': {
        // what nothing points to any more: old sign-ins, enrolments and roles of deleted classes or accounts, people in no class
        const n = {};
        chgQuiet(this.sql, () => this.ctx.storage.transactionSync(() => {
          n.signins = this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now()).rowsWritten;
          n.enrolments = this.sql.exec('DELETE FROM enrol WHERE k NOT IN (SELECT id FROM classes)').rowsWritten;
          n.roles = this.sql.exec('DELETE FROM roles WHERE k NOT IN (SELECT id FROM classes) OR sid NOT IN (SELECT id FROM staff)').rowsWritten;
          n.people = this.sql.exec('DELETE FROM people WHERE phone NOT IN (SELECT phone FROM enrol)').rowsWritten;
          if (q.auditDays > 0) n.audit = this.sql.exec('DELETE FROM audit WHERE at < ?', Date.now() - q.auditDays * 86400000).rowsWritten;
        }), { pruned: 'American Corner', rows: n });
        return json({ ok: true, n });
      }
      case 'signOutAll': {
        // everyone signs in again, every trusted browser is forgotten; this admin's sign-in is renewed
        this.prop('epoch', Number(this.epoch()) + 1);
        this.sql.exec("DELETE FROM kv WHERE k LIKE 'tok:%' OR k LIKE 'trust:%' OR k LIKE 'loginfail%' OR k LIKE 'pk:%'");
        if (/^[a-f0-9]{16,64}$/.test(String(req.token || ''))) this.kvPut('tok:' + req.token, JSON.stringify({ sid: '', ep: this.epoch(), s8: '', aep: this.prop('aep') || '1' }), 21600);
        return json({ ok: true });
      }
      case 'unlockAll': return json({ ok: true, n: this.sql.exec("DELETE FROM kv WHERE k LIKE 'loginfail%' OR k LIKE 'maintfail%' OR k LIKE 'sfail:%'").rowsWritten });
      case 'maint':
        if (req.op === 'setPassword') { const salt = randHex(20); this.prop('adminSalt', salt); this.prop('adminHash', hashPw(String(req.password || ''), salt)); this.prop('epoch', Number(this.epoch()) + 1); }
        if (req.op === 'unlock') this.sql.exec("DELETE FROM kv WHERE k LIKE 'loginfail%' OR k LIKE 'maintfail%' OR k LIKE 'sfail:%'");
        // sign out everywhere: every token, every trusted browser
        if (req.op === 'reset') { this.prop('epoch', Number(this.epoch()) + 1); this.sql.exec("DELETE FROM kv WHERE k LIKE 'loginfail%' OR k LIKE 'trust:%' OR k LIKE 'tok:%' OR k LIKE 'pk:%'"); }
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
    this.chgErr = chgSetupSafe(this.sql);
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
  run(req, net, staff, trusted) {
    this.cur = { net, staff, trusted: !!trusted };
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
      trustedStudent: () => !!self.cur.trusted,
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
    if (fails >= 200) return { ok: false, reason: 'locked', message: 'Too many wrong server keys. Wait 15 minutes.' };
    if (typeof req.key !== 'string' || !sameText(req.key, key)) { this.env_.cachePut('maintfail', String(fails + 1), 900); return { ok: false, reason: 'key', message: 'Wrong server key.' }; }
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
      chgQuiet(this.sql, () => this.ctx.storage.transactionSync(() => {
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
      }), { imported: 'a backup file (.json)', replaced: !!hasData, rows: counts });
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
      chgQuiet(this.sql, () => this.ctx.storage.transactionSync(() => {
        if (days) n.log = this.sql.exec('DELETE FROM t_log WHERE CAST(ts AS INTEGER) < ?', Date.now() - days * 86400000).rowsWritten;
        if (keep >= 0) {
          n.backups = this.sql.exec('DELETE FROM backups WHERE id NOT IN (SELECT id FROM backups ORDER BY id DESC LIMIT ?)', keep).rowsWritten;
          this.sql.exec('DELETE FROM backup_parts WHERE bid NOT IN (SELECT id FROM backups)');
        }
        // profile key requests that were used, dismissed, or never answered in 30 days
        n.requests = this.sql.exec("DELETE FROM t_requests WHERE status IN ('used', 'dismissed') OR CAST(at AS INTEGER) < ?", Date.now() - 30 * 86400000).rowsWritten;
        n.cache = this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now()).rowsWritten;
      }), { pruned: 'class', rows: n });
      const info = this.backupInfo(); info.count = this.sql.exec('SELECT COUNT(*) AS n FROM backups').one().n; E.setProp('backup', JSON.stringify(info));
      return after({ ok: true, n });
    }
    // new check-in codes: the QR on screen changes, and a code someone copied stops working
    if (op === 'rotateQr') { E.setProp('qrKey', E.random()); E.setProp('trusted', '{}'); return { ok: true }; }
    // a new term: the register, excuses, class days and log go; students, team and settings stay
    if (op === 'clearAttendance') {
      try { this.backupNow('before clearing attendance'); } catch (e) { return fail('error', 'Could not back up the class first, so nothing was cleared: ' + String(e.message || e)); }
      const n = {};
      chgQuiet(this.sql, () => this.ctx.storage.transactionSync(() => { for (const t of ['attendance', 'excuses', 'days', 'log']) n[t] = this.sql.exec(`DELETE FROM t_${t}`).rowsWritten; }), { cleared: 'attendance, excuses, class days and log (a restore point was made first)', rows: n });
      return after({ ok: true, n });
    }
    // restore points: list, make one, go back to one (a restore point of now is made first, so going back can be undone)
    if (op === 'backups') return { ok: true, points: bkList(this.sql) };
    if (op === 'backup') { const info = this.backupNow(String(q.why || 'Restore point').slice(0, 120)); return { ok: true, at: info.last }; }
    if (op === 'restore') return after(this.restore(q.id));
    return fail('action', 'Unknown step.');
  }
  restore(id) {
    const b = bkRead(this.sql, id);
    if (!b || !b.snap || !b.snap.tables) return fail('input', 'That restore point is gone.');
    const when = new Date(b.at + 330 * 60000).toISOString().slice(0, 16).replace('T', ' ');
    try { this.backupNow('Before going back to ' + when); } catch (e) { return fail('error', 'Could not keep a restore point of now first, so nothing was changed: ' + String(e.message || e)); }
    const n = {}, E = this.env_;
    chgQuiet(this.sql, () => this.ctx.storage.transactionSync(() => {
      // the activity log stays as it is: it is the record of what happened since
      for (const t of Object.keys(TABLES).filter(t => t !== 'log')) {
        const rows = Array.isArray(b.snap.tables[t]) ? b.snap.tables[t].filter(r => r && typeof r === 'object') : [];
        this.sql.exec(`DELETE FROM t_${t}`);
        rows.forEach(o => this.sql.exec(`INSERT INTO t_${t} VALUES (${TABLES[t].map(() => '?').join(',')})`, ...TABLES[t].map(c => (o[c] == null ? '' : String(o[c])))));
        n[t] = rows.length;
      }
      for (const k of Object.keys(b.snap.props || {})) if (!RESTORE_KEEP_PROPS[k] && !/^rp:/.test(k) && k !== 'sver') E.setProp(k, b.snap.props[k] == null ? '' : b.snap.props[k]);
      // the Corner takes this class's student list as new
      E.setProp('sver', String(Number(E.getProp('sver') || 0) + 1));
    }), { restored: 'class', from: when, why: b.why, rows: n });
    this.tabs = {};
    return { ok: true, n, from: b.at };
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
    // the student app: this person's record here (they signed in to their account at the Corner)
    if (q.op === 'record') return this.run({ action: 'me', id: q.sid, device: 'app' }, null, null, true);
    // the student's photo from the app, so facilitators see it in this class too
    if (q.op === 'setPhoto') {
      if (q.photo && !okPhoto(q.photo)) return { ok: false };
      const ps = E.read('profiles').filter(r => r.id !== q.sid);
      if (q.photo) ps.push({ id: q.sid, photo: q.photo, updated: String(Date.now()) });
      try { this.ctx.storage.transactionSync(() => E.write('profiles', ps)); } catch (e) { this.tabs = {}; return { ok: false }; }
      return { ok: true };
    }
    // the admin moved a student's records to their new number, and this class had them twice (old and new number):
    // the older ID keeps everything, the newer one's check-ins and excuses join it, and the new number goes on it
    if (q.op === 'mergeStudent') {
      const rows = E.read('students'), into = rows.find(r => r.id === q.into), from = rows.find(r => r.id === q.from);
      if (!into || !from || into.id === from.id) return { ok: false };
      try {
        this.ctx.storage.transactionSync(() => {
          const att = E.read('attendance'), had = new Set(att.filter(r => r.id === into.id).map(r => r.date));
          E.write('attendance', att.filter(r => r.id !== from.id || !had.has(r.date)).map(r => (r.id === from.id ? Object.assign(r, { id: into.id, name: into.name }) : r)));
          const exc = E.read('excuses'), hadE = new Set(exc.filter(r => r.id === into.id).map(r => r.date));
          E.write('excuses', exc.filter(r => r.id !== from.id || !hadE.has(r.date)).map(r => (r.id === from.id ? Object.assign(r, { id: into.id }) : r)));
          const ps = E.read('profiles'), mine = ps.some(r => r.id === into.id);
          E.write('profiles', ps.filter(r => r.id !== from.id || !mine).map(r => (r.id === from.id ? Object.assign(r, { id: into.id }) : r)));
          into.phone = q.phone;
          E.write('students', rows.filter(r => r.id !== from.id));
        });
      } catch (e) { this.tabs = {}; return { ok: false }; }
      return { ok: true, kept: into.id, removed: from.id };
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
    if (url.pathname === '/int' && request.headers.get('x-wipe') !== null) { await this.ctx.storage.deleteAll(); this.tabs = {}; this.tables(); this.chgErr = chgSetupSafe(this.sql); return json({ ok: true }); }
    if (url.pathname === '/cron' && request.headers.get('x-cron') === '1' && request.method === 'POST') {
      // a restore point every night, always (the switch on the page used to make this optional)
      try { this.backupNow('Nightly restore point'); } catch (e) { const i = this.backupInfo(); i.error = String(e.message || e); i.errorAt = Date.now(); this.env_.setProp('backup', JSON.stringify(i)); }
      this.sql.exec('DELETE FROM kv WHERE exp < ?', Date.now());
      return json({ ok: true });
    }
    // the first request after the security update keeps a restore point of the class as it was
    if (this.env_.getProp(RP_NOW) == null) {
      try { if (this.sql.exec('SELECT (SELECT COUNT(*) FROM t_students) + (SELECT COUNT(*) FROM t_attendance) AS n').one().n) this.backupNow(RP_WHY); } catch (e) {}
      this.env_.setProp(RP_NOW, '1');
    }
    return json(this.answer(await this.handle(request, url)));
  }
  // what this request changed (the triggers' rows) rides back to the front door, which puts it in the change log
  answer(out) {
    let c = []; try { c = chgDrain(this.sql); } catch (e) {}
    if (c.length && out && typeof out === 'object') out._chg = c;
    return out;
  }
  async handle(request, url) {
    if (url.pathname === '/int') return this.internal(await request.json());
    let net = null, staff = null;
    try { net = JSON.parse(request.headers.get('x-att-net') || 'null'); } catch (e) {}
    try { staff = JSON.parse(request.headers.get('x-att-staff') || 'null'); } catch (e) {}
    if (request.method === 'GET') return this.run({ action: 'status' }, net, null);
    const body = await request.text();
    if (body.length > MAX_IMPORT) return { ok: false, reason: 'input', message: 'Request too big.' };
    let req;
    try { req = JSON.parse(body); } catch (e) { return { ok: false, reason: 'input', message: 'Bad request.' }; }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return { ok: false, reason: 'input', message: 'Bad request.' };
    if (body.length > MAX_BODY && !(req.action === 'maint' && req.op === 'import')) return { ok: false, reason: 'input', message: 'Request too big.' };
    if (req.action === 'maint') { this.cur = { net: null, staff: null }; return this.maint(req); }
    return this.run(req, net, staff);
  }
}
