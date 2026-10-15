/*
  Cyber Security class attendance server (Google Apps Script, free).

  What it does
  - Stores attendance in the Google Sheet this script is attached to
    (tabs: Students, Attendance, Excuses, Days, Log).
  - Uses Google's clock, not the student's phone, to decide if check-in is open.
  - Students register once with their mobile number and name and get the next
    student ID (format set by the instructor, e.g. ACM-0001). After that they
    check in with the mobile number and confirm their ID and name.
  - Checks the rotating code from the classroom QR, one check-in per student
    per day, one student per phone per day, and the admin password.

  Setup (once, about 5 minutes; attendance.html > Instructor > Setup shows the same steps)
  1. Create a new Google Sheet. Extensions > Apps Script.
  2. Replace everything in Code.gs with this file. Save.
  3. Deploy > New deployment > type "Web app". Execute as: Me.
     Who has access: Anyone. Deploy, allow access, copy the Web app URL.
  4. Reload the Sheet. Menu "Attendance" > "Set admin password".
  5. Paste the Web app URL in attendance.html > Instructor > Setup.
  After editing this code later: Deploy > Manage deployments > Edit > Version: New version.
  Version 7 adds Drive backups: after pasting it, run Attendance > Back up now in the Sheet once
  and allow access, then deploy the new version.

  Security
  - Everything a student must not see or change is decided here, not in the page: the page is
    public, so hiding a button or a URL protects nothing. Instructor actions need a token that only
    a correct password gives (kept 6 hours, in this script's cache).
  - Students only ever get their own masked or confirmed details back.
*/

// bump when the page needs new server actions; the page warns when Apps Script runs an older copy
var SERVER_VERSION = 12;

var DEFAULT_SETTINGS = {
  days: [6],            // 0 Sun ... 6 Sat
  start: '09:00',
  end: '13:00',
  tzOffset: 330,        // minutes from UTC: Asia/Colombo is +05:30, no daylight saving
  tzName: 'Asia/Colombo',
  requireCode: true,    // must scan the live QR (or type its code) in the room
  selfRegister: true,   // new students may register themselves (mobile number + name) on first check-in
  oneDevice: true,      // one student per phone per day
  selfEdit: true,       // students may change their own name, number and photo (after signing in with a key from the instructor)
  fromFirst: true,      // count a student's classes from the day they joined, not from week 1
  slotSeconds: 30,      // QR code changes every 30 s
  codeSlots: 5,         // a code stays valid for 5 slots (about 2.5 min)
  idPrefix: 'ACM-',     // student IDs are given in order: prefix + number + suffix, e.g. ACM-0001
  idSuffix: '',
  idDigits: 4,
  idStart: 1
};

var TABLES = {
  students:   ['id', 'name', 'added', 'source', 'active', 'phone'],
  attendance: ['date', 'id', 'name', 'time', 'device', 'method', 'note'],
  excuses:    ['date', 'id', 'reason', 'added'],
  days:       ['date', 'status', 'note'],
  log:        ['ts', 'date', 'time', 'action', 'id', 'name', 'device', 'result', 'detail'],
  profiles:   ['id', 'photo', 'updated'],  // profile photos, kept apart so the Students tab stays small and fast
  requests:   ['rid', 'id', 'name', 'phone', 'at', 'code', 'status', 'updated'],  // profile key requests: the instructor's inbox
  staff:      ['id', 'name', 'phone', 'role', 'active', 'salt', 'hash', 'added']  // instructor accounts (photos go in Profiles); the hash is never sent to the page
};

var SHEET_NAMES = { students: 'Students', attendance: 'Attendance', excuses: 'Excuses', days: 'Days', log: 'Log', profiles: 'Profiles', requests: 'Key requests', staff: 'Instructors' };
var BACKUPS_KEPT = 30;

var CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/* ---------- core: no Google APIs in here, so the page's demo mode runs the same code ---------- */
function AttendanceCore(rawEnv) {
  // read each tab at most once per request; any write to a tab clears its copy
  var memo = {}, env = {};
  for (var key in rawEnv) env[key] = rawEnv[key];
  env.read = function (t) {
    if (!memo[t]) memo[t] = rawEnv.read(t);
    return memo[t].map(function (r) { var o = {}; for (var k in r) o[k] = r[k]; return o; });
  };
  env.append = function (t, o) { delete memo[t]; rawEnv.append(t, o); };
  env.write = function (t, rows) { delete memo[t]; rawEnv.write(t, rows); };
  // one writer at a time; a step that already holds the lock just runs
  var inLock = false;
  env.lock = function (fn, waitMs) {
    if (inLock) return fn();
    return rawEnv.lock(function () { inLock = true; try { return fn(); } finally { inLock = false; } }, waitMs);
  };

  function settings() {
    var s = {}, k, saved = {};
    try { saved = JSON.parse(env.getProp('settings') || '{}'); } catch (e) {}
    for (k in DEFAULT_SETTINGS) s[k] = DEFAULT_SETTINGS[k];
    for (k in saved) if (k in DEFAULT_SETTINGS) s[k] = saved[k];
    return s;
  }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function local(ms, s) {
    var d = new Date(ms + s.tzOffset * 60000);
    return {
      date: d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()),
      time: pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()),
      sec: pad(d.getUTCSeconds()),
      day: d.getUTCDay()
    };
  }
  function extraWindow(now) {
    var x = Number(env.getProp('extraUntil') || 0);
    return x > now ? x : 0;
  }
  function isOpen(now, s) {
    var t = local(now, s);
    if (extraWindow(now)) return true;
    if (env.getProp('closedDay') === t.date) return false;
    return s.days.indexOf(t.day) >= 0 && t.time >= s.start && t.time < s.end && !cancelled(t.date);
  }
  // a past class day the instructor opened for a while so they can fix its marks in the register
  function openDay(now) {
    var r = null;
    try { r = JSON.parse(env.getProp('openDay') || 'null'); } catch (e) {}
    return r && r.until > now && /^\d{4}-\d{2}-\d{2}$/.test(r.date) ? r : null;
  }
  // past days are locked; today and the opened day can be changed
  function editable(date, now, s) {
    var today = local(now, s).date, o = openDay(now);
    return date === today || (o && o.date === date);
  }
  var LOCKED = 'That day is locked. Open it for editing in Register first.';
  // today's absences count only once the class window is over (13:00 by default)
  function todayDone(now, s) {
    var t = local(now, s);
    return !isOpen(now, s) && (s.days.indexOf(t.day) < 0 || t.time >= s.end || env.getProp('closedDay') === t.date);
  }
  function counted(date, now, s) {
    var today = local(now, s).date;
    return date < today || (date === today && todayDone(now, s));
  }
  function cancelled(date) {
    return env.read('days').some(function (r) { return r.date === date && r.status === 'cancelled'; });
  }
  function nextOpen(now, s) {
    // ms of the next window start, checking minute-precision for the coming 8 days
    for (var i = 0; i < 9; i++) {
      var t = local(now + i * 86400000, s);
      if (s.days.indexOf(t.day) < 0 || cancelled(t.date)) continue;
      var hm = s.start.split(':');
      var startLocal = Date.UTC(+t.date.slice(0, 4), +t.date.slice(5, 7) - 1, +t.date.slice(8, 10), +hm[0], +hm[1]);
      var startMs = startLocal - s.tzOffset * 60000;
      if (startMs > now) return startMs;
    }
    return 0;
  }
  function codeFor(key, slot) {
    var b = env.hmac(key, 'att:' + slot), out = '';
    for (var i = 0; i < 6; i++) out += CODE_ALPHABET.charAt(b[i] & 31);
    return out;
  }
  function qrKey() {
    var k = env.getProp('qrKey');
    if (!k) { k = env.random(); env.setProp('qrKey', k); }
    return k;
  }
  function codeOk(code, now, s) {
    code = String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (code.length !== 6) return false;
    var slot = Math.floor(now / (s.slotSeconds * 1000)), key = qrKey();
    for (var i = -1; i < s.codeSlots; i++) if (codeFor(key, slot - i) === code) return true;
    return false;
  }
  function cleanId(v) { return String(v || '').trim().toUpperCase().replace(/\s+/g, ''); }
  function cleanName(v) { return String(v || '').trim().replace(/\s+/g, ' '); }
  function sameName(a, b) { return cleanName(a).toLowerCase() === cleanName(b).toLowerCase(); }
  function validId(id) { return /^[A-Z0-9][A-Z0-9_\/-]{1,29}$/.test(id); }
  // Sri Lankan numbers: 0771234567, 077 123 4567, +94 77 123 4567, 94771234567 all become 0771234567
  function cleanPhone(v) {
    var d = String(v || '').replace(/[^\d]/g, '');
    if (d.length === 11 && d.slice(0, 2) === '94') d = '0' + d.slice(2);
    if (d.length === 9 && d.charAt(0) !== '0') d = '0' + d;
    return /^0\d{9}$/.test(d) ? d : '';
  }
  function formatId(s, n) {
    var num = String(n);
    while (num.length < s.idDigits) num = '0' + num;
    return s.idPrefix + num + s.idSuffix;
  }
  function nextId(s, students) {
    var used = {}, n = Math.max(Number(env.getProp('idNext') || 0), Number(s.idStart) || 1);
    students.forEach(function (r) { used[r.id] = true; });
    while (used[formatId(s, n)]) n++;
    env.setProp('idNext', String(n + 1));
    return formatId(s, n);
  }
  function staffByPhone(phone) { return phone ? env.read('staff').filter(function (r) { return r.phone === phone; })[0] || null : null; }
  var STAFF_PHONE = 'That number belongs to an instructor. Students use their own number.';
  function byPhone(phone) { return env.read('students').filter(function (r) { return r.phone && r.phone === phone; })[0] || null; }
  function studentOut(st) { return { id: st.id, name: st.name, phone: st.phone }; }
  // before a student proves anything, show only enough of the name to recognise it: "Dineth Yasuru" -> "Di**** Ya****"
  function maskName(n) { return cleanName(n).split(' ').map(function (w) { return w.slice(0, 2) + (w.length > 2 ? new Array(w.length - 1).join('*') : ''); }).join(' '); }
  function cleanDevice(v) { return String(v || '').replace(/[^a-z0-9]/gi, '').slice(0, 40); }

  // Profile key: separate from check-in. A student types their number and asks for a key; the request
  // lands in the instructor's Inbox with a short sign-in code, which the instructor sends on WhatsApp.
  // The code (once, within 3 days) gives the phone the long key (an HMAC of the ID with a server
  // secret) that profile changes need. Students > Edit > Sign out of profile cancels every key of one student.
  function keyVersions() { try { return JSON.parse(env.getProp('stuKv') || '{}'); } catch (e) { return {}; } }
  function stuKey(id) {
    var sec = env.getProp('stuSecret');
    if (!sec) { sec = env.random(); env.setProp('stuSecret', sec); }
    return env.hmac(sec, 'student:' + id + ':' + (keyVersions()[id] || 0)).slice(0, 16).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  function keyOk(id, key) {
    if (!validId(id) || !/^[a-f0-9]{32}$/.test(String(key || ''))) return false;
    var want = stuKey(id), diff = 0;
    for (var i = 0; i < 32; i++) diff |= want.charCodeAt(i) ^ String(key).charCodeAt(i);
    return diff === 0;
  }
  // photos: small square JPEGs made by the page, about 10 KB
  function validPhoto(p) { return typeof p === 'string' && p.length <= 40000 && /^data:image\/jpeg;base64,\/9j\/[A-Za-z0-9+\/]+=*$/.test(p); }
  // shared checks for every student step: real browser, not too many tries, valid number, open now, live code
  function gate(req, now, s, L) {
    var device = String(req.device || '').slice(0, 40);
    if (!/^[a-z0-9]{8,40}$/i.test(device)) { L('rejected', 'no device id'); return fail('device', 'Open this page in a normal browser tab and try again.'); }
    if (rateLimited('rl:' + device, 20, 600)) { L('rejected', 'too many tries'); return fail('slow', 'Too many tries. Wait 10 minutes.'); }
    if (!cleanPhone(req.phone)) { L('rejected', 'bad number'); return fail('phone', 'Type your mobile number, like 0771234567.'); }
    // a new device id per try is easy to fake, so each number has its own limit too
    if (rateLimited('rp:' + cleanPhone(req.phone), 12, 600)) { L('rejected', 'too many tries for number'); return fail('slow', 'Too many tries for this number. Wait 10 minutes.'); }
    if (!isOpen(now, s)) { L('rejected', 'closed'); return fail('closed', 'Check-in is closed now.', { nextOpen: nextOpen(now, s) }); }
    if (s.requireCode && !codeOk(req.code, now, s)) { L('rejected', 'bad or old code'); return fail('code', 'That QR code has expired. Scan the screen again.'); }
    return null;
  }
  function validName(n) { return n.length >= 2 && n.length <= 60 && /^[\p{L}\p{M} .'-]+$/u.test(n); }

  function log(now, s, action, id, name, device, result, detail) {
    var t = local(now, s), row = { ts: String(now), date: t.date, time: t.time + ':' + t.sec, action: action,
      id: String(id || '').slice(0, 40), name: String(name || '').slice(0, 60), device: device === 'admin' ? 'admin' : cleanDevice(device), result: result, detail: String(detail || '').slice(0, 500) };
    // rows are added inside the lock so two at once never land on the same line; a log line is not worth a long wait
    try { env.lock(function () { env.append('log', row); }, 5000); } catch (e) {}
  }
  function rateLimited(key, max, seconds) {
    var n = Number(env.cacheGet(key) || 0) + 1;
    if (n <= max + 1) env.cachePut(key, String(n), seconds);
    return n > max;
  }
  function publicStatus(now) {
    var s = settings(), t = local(now, s);
    var o = openDay(now);
    return { ok: true, version: SERVER_VERSION, now: now, today: t.date, time: t.time, open: isOpen(now, s), todayDone: todayDone(now, s),
      extraUntil: extraWindow(now), nextOpen: nextOpen(now, s), openDay: o ? { date: o.date, until: o.until } : null,
      window: { days: s.days, start: s.start, end: s.end, tzName: s.tzName, tzOffset: s.tzOffset },
      requireCode: s.requireCode, selfRegister: s.selfRegister, selfEdit: s.selfEdit, configured: !!env.getProp('adminHash'), idExample: formatId(s, Number(s.idStart) || 1) };
  }
  function fail(reason, msg, extra) {
    var r = { ok: false, reason: reason, message: msg };
    for (var k in (extra || {})) r[k] = extra[k];
    return r;
  }

  // step 1: student types their number; answer who it belongs to so they can confirm
  function lookup(req, now) {
    var s = settings(), t = local(now, s), phone = cleanPhone(req.phone);
    var L = function (result, detail) { log(now, s, 'lookup', phone || String(req.phone || '').slice(0, 20), '', String(req.device || '').slice(0, 40), result, detail); };
    var bad = gate(req, now, s, L); if (bad) return bad;
    var st = byPhone(phone);
    if (!st) return { ok: true, found: false, phone: phone, canRegister: s.selfRegister, idExample: formatId(s, Number(s.idStart) || 1) };
    if (String(st.active) === 'no') { L('rejected', 'inactive ' + st.id); return fail('inactive', 'This number is switched off. Talk to your instructor.'); }
    var mine = env.read('attendance').filter(function (r) { return r.date === t.date && r.id === st.id; })[0];
    return { ok: true, found: true, student: { id: st.id, name: maskName(st.name) }, masked: true, already: mine ? mine.time : '', date: t.date };
  }

  // first time only: number + name get the next student ID
  function register(req, now) {
    var s = settings(), t = local(now, s), phone = cleanPhone(req.phone), name = cleanName(req.name);
    var L = function (result, detail) { log(now, s, 'register', phone, name, String(req.device || '').slice(0, 40), result, detail); };
    var bad = gate(req, now, s, L); if (bad) return bad;
    if (!s.selfRegister) { L('rejected', 'self register off'); return fail('unknown', 'This number is not on the class list. Talk to your instructor.'); }
    if (!validName(name)) { L('rejected', 'bad name'); return fail('name', 'Type your name with letters only.'); }
    var hit = byPhone(phone);
    if (hit) { L('duplicate', 'number already ' + hit.id); return { ok: true, student: studentOut(hit), existing: true }; }
    if (staffByPhone(phone)) { L('rejected', 'instructor number'); return fail('unknown', STAFF_PHONE); }
    var st = { id: nextId(s, env.read('students')), name: name, added: t.date, source: 'self', active: 'yes', phone: phone };
    env.append('students', st);
    L('accepted', st.id);
    return { ok: true, student: studentOut(st) };
  }

  // step 2: student confirmed "this is me"
  function checkin(req, now) {
    var s = settings(), t = local(now, s), phone = cleanPhone(req.phone), device = String(req.device || '').slice(0, 40);
    var st = phone ? byPhone(phone) : null;
    var L = function (result, detail) { log(now, s, 'checkin', st ? st.id : phone, st ? st.name : '', device, result, detail); };
    var bad = gate(req, now, s, L); if (bad) return bad;
    if (!st) { L('rejected', 'unknown number'); return fail('unknown', 'This number is not registered yet.'); }
    if (String(st.active) === 'no') { L('rejected', 'inactive'); return fail('inactive', 'This number is switched off. Talk to your instructor.'); }
    if (req.id && cleanId(req.id) !== st.id) { L('rejected', 'confirmed ' + cleanId(req.id) + ' but number is ' + st.id); return fail('changed', 'Your details changed. Type your number again.'); }

    var mine = null, other = null;
    env.read('attendance').forEach(function (r) {
      if (r.date !== t.date) return;
      if (r.id === st.id) mine = r;
      else if (s.oneDevice && r.device && r.device === device) other = r;
    });
    if (mine) { L('duplicate', 'already at ' + mine.time); return { ok: true, already: true, date: t.date, time: mine.time, student: studentOut(st) }; }
    if (other) { L('rejected', 'device used by ' + other.id); return fail('shared', 'This phone already checked in another student today. Use your own phone, or ask your instructor.'); }

    env.append('attendance', { date: t.date, id: st.id, name: st.name, time: t.time, device: device, method: s.requireCode ? 'qr' : 'open', note: '' });
    if (!env.read('days').some(function (r) { return r.date === t.date; })) env.append('days', { date: t.date, status: 'held', note: '' });
    L('accepted', '');
    return { ok: true, date: t.date, time: t.time, student: studentOut(st) };
  }

  function me(req, now) {
    var s = settings(), phone = cleanPhone(req.phone), name = cleanName(req.name), device = String(req.device || '').slice(0, 40);
    if (rateLimited('rl:' + device, 20, 600) || (phone && rateLimited('rm:' + phone, 10, 600))) return fail('slow', 'Too many tries. Wait 10 minutes.');
    var st = null;
    if (req.key) { st = env.read('students').filter(function (r) { return r.id === cleanId(req.id); })[0] || null; if (st && !keyOk(st.id, req.key)) st = null; }
    else if (phone) { st = byPhone(phone); if (st && !sameName(st.name, name)) st = null; }
    if (!st) return fail('notfound', 'No record for this number and name yet.');
    var id = st.id, today = local(now, s).date;
    var att = {}, exc = {}, start = st.added || today;
    env.read('attendance').forEach(function (r) { if (r.id === id) { att[r.date] = r.time; if (r.date < start) start = r.date; } });
    if (!s.fromFirst) start = '';
    var days = env.read('days').filter(function (r) { return r.status !== 'cancelled' && (counted(r.date, now, s) || att[r.date]) && r.date >= start; }).map(function (r) { return r.date; }).sort();
    env.read('excuses').forEach(function (r) { if (r.id === id) exc[r.date] = r.reason || 'excused'; });
    return { ok: true, id: id, name: st.name, phone: st.phone, records: days.map(function (d) {
      return { date: d, status: att[d] ? 'present' : exc[d] ? 'excused' : 'absent', time: att[d] || '' };
    }), upcomingExcuses: Object.keys(exc).filter(function (d) { return d > today; }).sort() };
  }

  /* ----- the student's own profile ----- */
  function profileStudent(req) {
    var id = cleanId(req.id);
    if (rateLimited('pf:' + id, 30, 3600)) return { err: fail('slow', 'Too many tries. Wait an hour.') };
    var KEY = 'Sign in again: ask your instructor for a new key.';
    if (!keyOk(id, req.key)) return { err: fail('key', KEY) };
    var st = env.read('students').filter(function (r) { return r.id === id; })[0];
    if (!st || String(st.active) === 'no') return { err: fail('key', KEY) };
    return { st: st };
  }
  // step 1: "send me a key". The answer is the same whether or not the number is registered, so it
  // can't be used to find out who is in the class.
  var REQ_DAYS = 3;
  function newCode() { var r = env.random(), c = ''; for (var i = 0; i < 8; i++) c += CODE_ALPHABET.charAt(parseInt(r.substr(i * 2, 2), 16) & 31); return c; }
  function keyRequest(req, now) {
    var s = settings(), phone = cleanPhone(req.phone), device = cleanDevice(req.device);
    if (!/^[a-z0-9]{8,40}$/i.test(device)) return fail('device', 'Open this page in a normal browser tab and try again.');
    if (!phone) return fail('phone', 'Type your mobile number, like 0771234567.');
    if (rateLimited('kr:' + device, 6, 3600) || rateLimited('kp:' + phone, 3, 3600)) return fail('slow', 'Too many requests. Try again in an hour, or message your instructor.');
    if (!s.selfEdit) return fail('off', 'Your instructor has turned off profile changes.');
    var SENT = { ok: true, message: 'Request sent. Your instructor will send your key on WhatsApp. Then type it here.' };
    var st = byPhone(phone);
    if (!st || String(st.active) === 'no') { log(now, s, 'key request', phone, '', device, 'rejected', 'unknown number'); return SENT; }
    var rows = env.read('requests'), open = rows.filter(function (r) { return r.id === st.id && r.status !== 'used' && r.status !== 'dismissed' && now - Number(r.at) < REQ_DAYS * 86400000; })[0];
    if (open) { log(now, s, 'key request', st.id, st.name, device, 'duplicate', 'already waiting'); return SENT; }
    var rid = env.random().slice(0, 12);
    env.append('requests', { rid: rid, id: st.id, name: st.name, phone: st.phone, at: String(now), code: newCode(), status: 'new', updated: String(now) });
    log(now, s, 'key request', st.id, st.name, device, 'accepted', rid);
    return SENT;
  }
  // step 2: the student types the code the instructor sent
  function keySignIn(req, now) {
    var s = settings(), phone = cleanPhone(req.phone), device = cleanDevice(req.device), code = String(req.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!phone) return fail('phone', 'Type your mobile number, like 0771234567.');
    if (rateLimited('ks:' + phone, 6, 900) || rateLimited('kd:' + device, 10, 900)) return fail('slow', 'Too many tries. Wait 15 minutes.');
    var st = byPhone(phone), BAD = fail('code', 'That key is not right for this number, or it has expired. Ask your instructor for a new one.');
    if (!st || String(st.active) === 'no' || code.length !== 8) { log(now, s, 'key sign-in', phone, '', device, 'rejected', 'bad key'); return BAD; }
    var rows = env.read('requests'), hit = null;
    rows.forEach(function (r) { if (r.id === st.id && r.code === code && r.status !== 'used' && r.status !== 'dismissed' && now - Number(r.at) < REQ_DAYS * 86400000) hit = r; });
    if (!hit) { log(now, s, 'key sign-in', st.id, st.name, device, 'rejected', 'bad key'); return BAD; }
    hit.status = 'used'; hit.updated = String(now);
    env.write('requests', rows);
    log(now, s, 'key sign-in', st.id, st.name, device, 'accepted', hit.rid);
    return { ok: true, student: studentOut(st), key: stuKey(st.id) };
  }
  function photoOf(id) { var p = env.read('profiles').filter(function (r) { return r.id === id; })[0]; return p ? p.photo : ''; }
  function profileGet(req, now) {
    var r = profileStudent(req); if (r.err) return r.err;
    return { ok: true, student: studentOut(r.st), photo: photoOf(r.st.id), canEdit: settings().selfEdit };
  }
  function profileSave(req, now) {
    var s = settings(), r = profileStudent(req); if (r.err) return r.err;
    if (!s.selfEdit) return fail('off', 'Your instructor has turned off profile changes. Ask them to change it.');
    var st = r.st, id = st.id, changes = [];
    var nm = req.name == null ? st.name : cleanName(req.name), ph = req.phone == null ? st.phone : cleanPhone(req.phone);
    if (!validName(nm)) return fail('name', 'Type your name with letters only.');
    if (!ph) return fail('phone', 'Type your mobile number, like 0771234567.');
    if (req.photo != null && req.photo !== '' && !validPhoto(req.photo)) return fail('photo', 'That photo could not be used. Try another one.');
    var rows = env.read('students');
    if (ph !== st.phone && rows.some(function (x) { return x.phone === ph && x.id !== id; })) return fail('phone', 'That number belongs to another student. Ask your instructor.');
    if (ph !== st.phone && staffByPhone(ph)) return fail('phone', STAFF_PHONE);
    if (nm !== st.name) changes.push('name "' + st.name + '" to "' + nm + '"');
    if (ph !== st.phone) changes.push('number ' + st.phone + ' to ' + ph);
    if (changes.length) {
      rows.forEach(function (x) { if (x.id === id) { x.name = nm; x.phone = ph; } });
      env.write('students', rows);
      if (nm !== st.name) env.write('attendance', env.read('attendance').map(function (x) { if (x.id === id) x.name = nm; return x; }));
    }
    if (req.photo != null) {
      var ps = env.read('profiles'), had = false;
      ps.forEach(function (x) { if (x.id === id) { had = true; x.photo = req.photo; x.updated = String(now); } });
      if (!had && req.photo) ps.push({ id: id, photo: req.photo, updated: String(now) });
      env.write('profiles', ps.filter(function (x) { return x.photo; }));
      changes.push(req.photo ? 'photo' : 'photo removed');
    }
    log(now, s, 'profile', id, nm, req.device, changes.length ? 'accepted' : 'duplicate', changes.join(', ') || 'no change');
    st.name = nm; st.phone = ph;
    return { ok: true, student: studentOut(st), photo: req.photo != null ? req.photo : undefined };
  }

  /* ----- admin ----- */
  function hashPw(pw, salt) {
    var h = salt + ':' + pw;
    for (var i = 0; i < 300; i++) h = env.sha256(salt + h);
    return h;
  }
  function setPassword(pw) {
    if (String(pw || '').length < 8) throw new Error('Password needs at least 8 characters.');
    var salt = env.random();
    env.setProp('adminSalt', salt);
    env.setProp('adminHash', hashPw(pw, salt));
  }
  // a browser that signed in before gets a "trusted" key (90 days). Wrong passwords from other browsers
  // lock sign-in for 15 minutes, but not on a trusted browser, so students can't lock the instructor out.
  function trusted(now) { try { return JSON.parse(env.getProp('trusted') || '{}'); } catch (e) { return {}; } }
  function trustOk(key, now) {
    if (!key || !/^[a-f0-9]{16,64}$/.test(key)) return false;
    var exp = trusted(now)[env.sha256('trust:' + key)];
    return !!exp && exp > now;
  }
  function trustNew(now) {
    var all = trusted(now), out = {}, key = env.random();
    Object.keys(all).filter(function (h) { return all[h] > now; }).sort(function (a, b) { return all[b] - all[a]; }).slice(0, 9).forEach(function (h) { out[h] = all[h]; });
    out[env.sha256('trust:' + key)] = now + 90 * 86400000;
    env.setProp('trusted', JSON.stringify(out));
    return key;
  }
  function epoch() { return env.getProp('admEpoch') || '1'; }
  // instructors sign in with their own number and password; the main password from the Sheet menu still works
  function staffOut(r) { return r ? { id: r.id, name: r.name, phone: r.phone, role: r.role === 'owner' ? 'owner' : 'instructor', active: r.active !== 'no', added: r.added } : null; }
  function login(req, now) {
    var s = settings(), trust = trustOk(req.trust, now), failKey = trust ? 'loginfail:trusted' : 'loginfail';
    var lp = cleanPhone(req.phone), who = null;
    if (req.phone) {
      if (Number(env.cacheGet(failKey) || 0) >= (trust ? 10 : 20)) return fail('locked', 'Too many wrong passwords. Wait 15 minutes, or unlock sign-in (Google Sheet: Attendance menu; Cloudflare: Setup › Cloudflare server tools).');
      who = staffByPhone(lp);
      if (!who || who.active === 'no' || !who.hash || hashPw(String(req.password || ''), who.salt) !== who.hash) {
        env.cachePut(failKey, String(Number(env.cacheGet(failKey) || 0) + 1), 900);
        log(now, s, 'login', lp, '', '', 'rejected', 'wrong number or password' + (trust ? ' (trusted browser)' : ''));
        return fail('password', 'Wrong number or password.');
      }
      var tk = env.random();
      env.cachePut('adm:' + tk, epoch() + '|' + who.id, 21600);
      log(now, s, 'login', who.id, who.name, '', 'accepted', trust ? 'trusted browser' : 'new browser');
      return { ok: true, token: tk, qrKey: qrKey(), now: now, hours: 6, trust: trust ? req.trust : trustNew(now), me: staffOut(who) };
    }
    if (!env.getProp('adminHash')) return fail('nopass', 'No admin password yet. Set it in the Google Sheet (Attendance menu) or in Setup › Cloudflare server tools.');
    if (Number(env.cacheGet(failKey) || 0) >= (trust ? 10 : 20)) { log(now, s, 'login', '', '', '', 'rejected', 'locked' + (trust ? ' (trusted browser)' : '')); return fail('locked', 'Too many wrong passwords. Wait 15 minutes, or unlock sign-in (Google Sheet: Attendance menu; Cloudflare: Setup › Cloudflare server tools).'); }
    if (hashPw(String(req.password || ''), env.getProp('adminSalt')) !== env.getProp('adminHash')) {
      env.cachePut(failKey, String(Number(env.cacheGet(failKey) || 0) + 1), 900);
      log(now, s, 'login', '', '', '', 'rejected', 'wrong password' + (trust ? ' (trusted browser)' : ''));
      return fail('password', 'Wrong password.');
    }
    var token = env.random();
    env.cachePut('adm:' + token, epoch(), 21600);
    log(now, s, 'login', '', '', '', 'accepted', trust ? 'trusted browser' : 'new browser');
    return { ok: true, token: token, qrKey: qrKey(), now: now, hours: 6, trust: trust ? req.trust : trustNew(now) };
  }
  // the session remembers who signed in: '' is the main password, otherwise an instructor id
  var SESSION = null;
  function adminOk(req) {
    SESSION = null;
    if (!req.token || !/^[a-f0-9]{16,64}$/.test(req.token)) return false;
    var v = String(env.cacheGet('adm:' + req.token) || ''), parts = v.split('|');
    if (parts[0] !== epoch()) return false;
    var me = null;
    if (parts[1]) { me = env.read('staff').filter(function (r) { return r.id === parts[1]; })[0]; if (!me || me.active === 'no') return false; }
    SESSION = { me: me };
    return true;
  }
  function isOwner() { return SESSION && (!SESSION.me || SESSION.me.role === 'owner'); }
  // Sheet menu: sign every instructor browser out, forget trusted browsers and change the QR secret
  function resetSecurity() {
    env.setProp('admEpoch', String(Number(epoch()) + 1));
    env.setProp('trusted', '{}');
    env.setProp('qrKey', env.random());
    env.cacheDel('loginfail'); env.cacheDel('loginfail:trusted');
  }
  function unlockLogin() { env.cacheDel('loginfail'); env.cacheDel('loginfail:trusted'); }
  function validDate(d) { return /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')); }

  function admin(req, now) {
    var s = settings(), t = local(now, s), a = req.action, rows, id = cleanId(req.id);
    var byName = SESSION && SESSION.me ? SESSION.me.name : 'main password';
    var A = function (detail) { log(now, s, a, id, byName, 'admin', 'done', detail || ''); };
    if (a === 'logout') { env.cacheDel('adm:' + req.token); return { ok: true }; }
    if (a === 'data') {
      // only the newest 400 log lines; the Log tab keeps everything
      var lg = env.readTail ? env.readTail('log', 400) : env.read('log');
      return { ok: true, now: now, today: t.date, settings: s, status: publicStatus(now),
        students: env.read('students'), attendance: env.read('attendance'), excuses: env.read('excuses'),
        days: env.read('days'), log: lg.slice(Math.max(0, lg.length - 400)), backup: backupInfo(),
        requests: env.read('requests').filter(function (r) { return now - Number(r.at) < 30 * 86400000; }),
        nextIdPreview: formatId(s, Math.max(Number(env.getProp('idNext') || 0), Number(s.idStart) || 1)),
        staff: env.read('staff').map(staffOut), me: SESSION && SESSION.me ? staffOut(SESSION.me) : null, owner: isOwner() };
    }
    if (a === 'staffSave' || a === 'myAccount') {
      // owners add and change instructors; everyone changes their own name, number, photo and password
      rows = env.read('staff');
      var mine = a === 'myAccount', sid = mine ? (SESSION.me ? SESSION.me.id : '') : String(req.sid || '');
      if (mine && !sid) return fail('input', 'You signed in with the main password. Add yourself under Instructors, then sign in with your number.');
      if (!mine && !isOwner()) return fail('input', 'Only an owner can change other instructors.');
      var cur = sid ? rows.filter(function (r) { return r.id === sid; })[0] : null;
      if (sid && !cur) return fail('input', 'That instructor is gone.');
      if (!mine && req.remove) {
        if (SESSION.me && SESSION.me.id === sid) return fail('input', 'You cannot remove yourself.');
        if (cur.role === 'owner' && rows.filter(function (r) { return r.role === 'owner' && r.active !== 'no'; }).length < 2) return fail('input', 'Keep at least one owner.');
        env.write('staff', rows.filter(function (r) { return r.id !== sid; }));
        env.write('profiles', env.read('profiles').filter(function (r) { return r.id !== sid; }));
        log(now, s, a, sid, byName, 'admin', 'done', 'removed ' + cur.name); return { ok: true };
      }
      var sn = req.name == null && cur ? cur.name : cleanName(req.name), sph = req.phone == null && cur ? cur.phone : cleanPhone(req.phone);
      if (!validName(sn)) return fail('input', 'Type a name with letters only.');
      if (!sph) return fail('input', 'Type a mobile number like 0771234567.');
      var sclash = rows.filter(function (r) { return r.phone === sph && r.id !== sid; })[0];
      if (sclash) return fail('input', 'That number already belongs to instructor ' + sclash.name + '.');
      var stu = byPhone(sph);
      if (stu) return fail('input', 'That number belongs to student ' + stu.name + ' (' + stu.id + '). An instructor needs a number of their own.');
      if (req.photo != null && req.photo !== '' && !validPhoto(req.photo)) return fail('input', 'That photo could not be used. Try another one.');
      var pw = req.password == null ? '' : String(req.password);
      if (pw && pw.length < 8) return fail('input', 'The password needs at least 8 characters.');
      if (!cur && !pw) return fail('input', 'Give the new instructor a password (8 or more characters).');
      if (mine && pw && hashPw(String(req.oldPassword || ''), cur.salt) !== cur.hash) return fail('input', 'Your current password is not right.');
      var role = mine || !req.role ? (cur ? cur.role : 'instructor') : (req.role === 'owner' ? 'owner' : 'instructor');
      var act = mine || req.active == null ? (cur ? cur.active : 'yes') : (req.active === false ? 'no' : 'yes');
      if (cur && cur.role === 'owner' && (role !== 'owner' || act === 'no') && rows.filter(function (r) { return r.role === 'owner' && r.active !== 'no' && r.id !== sid; }).length < 1) return fail('input', 'Keep at least one owner.');
      // the first instructor added is an owner, so someone can always manage the team
      if (!cur && !rows.some(function (r) { return r.role === 'owner' && r.active !== 'no'; })) role = 'owner';
      if (!cur) { cur = { id: 'S' + env.random().slice(0, 8), added: t.date }; rows.push(cur); }
      cur.name = sn; cur.phone = sph; cur.role = role; cur.active = act;
      if (req.photo != null) {
        var pr = env.read('profiles').filter(function (r) { return r.id !== cur.id; });
        if (req.photo) pr.push({ id: cur.id, photo: req.photo, updated: String(now) });
        env.write('profiles', pr);
      }
      if (pw) { cur.salt = env.random(); cur.hash = hashPw(pw, cur.salt); }
      env.write('staff', rows);
      log(now, s, a, cur.id, byName, 'admin', 'done', (mine ? 'own account' : 'instructor ' + cur.name) + (pw ? ', password set' : ''));
      return { ok: true, staff: staffOut(cur) };
    }
    if (a === 'photos') {
      var ph = {};
      env.read('profiles').forEach(function (r) { if (r.photo) ph[r.id] = r.photo; });
      return { ok: true, photos: ph };
    }
    if (a === 'photo') {
      // the instructor can remove a photo that should not be there
      if (!validId(id)) return fail('input', 'Pick a student.');
      env.write('profiles', env.read('profiles').filter(function (r) { return r.id !== id; }));
      A('photo removed'); return { ok: true };
    }
    if (a === 'keyReq') {
      // inbox: mark a request sent (you messaged the code) or dismissed (the code stops working)
      rows = env.read('requests');
      var rq = rows.filter(function (r) { return r.rid === String(req.rid || ''); })[0];
      if (!rq) return fail('input', 'That request is gone.');
      if (req.status !== 'sent' && req.status !== 'dismissed' && req.status !== 'new') return fail('input', 'Pick sent or dismissed.');
      if (rq.status === 'used') return { ok: true, request: rq };
      rq.status = req.status; rq.updated = String(now);
      env.write('requests', rows);
      log(now, s, a, rq.id, rq.name, 'admin', 'done', req.status); return { ok: true, request: rq };
    }
    if (a === 'keyIssue') {
      // give a student a code without waiting for them to ask
      var sk = env.read('students').filter(function (r) { return r.id === id; })[0];
      if (!sk || !sk.phone) return fail('input', 'This student needs a mobile number first.');
      rows = env.read('requests');
      rows.forEach(function (r) { if (r.id === id && (r.status === 'new' || r.status === 'sent')) { r.status = 'dismissed'; r.updated = String(now); } });
      var nr = { rid: env.random().slice(0, 12), id: id, name: sk.name, phone: sk.phone, at: String(now), code: newCode(), status: 'new', updated: String(now) };
      rows.push(nr); env.write('requests', rows);
      A('key code made'); return { ok: true, request: nr };
    }
    if (a === 'profileKey') {
      // a lost or shared phone: the old key stops working; the student checks in again to get a new one
      if (!validId(id)) return fail('input', 'Pick a student.');
      var kv = keyVersions(); kv[id] = (kv[id] || 0) + 1; env.setProp('stuKv', JSON.stringify(kv));
      var rq2 = env.read('requests'), ch = false;
      rq2.forEach(function (r) { if (r.id === id && (r.status === 'new' || r.status === 'sent')) { r.status = 'dismissed'; r.updated = String(now); ch = true; } });
      if (ch) env.write('requests', rq2);
      A('profile key reset'); return { ok: true };
    }
    if (a === 'export') {
      // the whole record as one file; password hashes and secrets are never included
      var all = { ok: true, kind: 'attendance-backup', version: SERVER_VERSION, exportedAt: now, today: t.date, settings: s };
      Object.keys(TABLES).forEach(function (k) { all[k] = env.read(k); });
      all.staff = all.staff.map(staffOut);
      A('download'); return all;
    }
    if (a === 'backup') {
      if (!env.backup) return fail('input', 'Backups to Drive work with the Google server, not in demo mode.');
      if (rateLimited('bk', 1, 60)) return fail('input', 'A backup was made less than a minute ago.');
      var b = env.backup('by instructor'); A(b.name); return { ok: true, backup: backupInfo() };
    }
    if (a === 'backupAuto') {
      if (!env.backupAuto) return fail('input', 'Backups to Drive work with the Google server, not in demo mode.');
      env.backupAuto(!!req.on); A(req.on ? 'daily on' : 'daily off'); return { ok: true, backup: backupInfo() };
    }
    if (a === 'today') {
      return { ok: true, now: now, today: t.date, status: publicStatus(now),
        present: env.read('attendance').filter(function (r) { return r.date === t.date; }).map(function (r) { return { id: r.id, name: r.name, time: r.time }; }) };
    }
    if (a === 'mark') {
      if (!validId(id) || !validDate(req.date)) return fail('input', 'Pick a student and a date.');
      var st = env.read('students').filter(function (r) { return r.id === id; })[0];
      if (!st) return fail('input', 'Unknown student.');
      if (req.date > t.date) return fail('input', 'You cannot mark a future day.');
      if (!editable(req.date, now, s)) return fail('locked', LOCKED);
      rows = env.read('attendance').filter(function (r) { return !(r.id === id && r.date === req.date); });
      if (req.present) rows.push({ date: req.date, id: id, name: st.name, time: req.time || t.time, device: '', method: 'admin', note: String(req.note || '').slice(0, 120) });
      env.write('attendance', rows);
      if (req.present && !env.read('days').some(function (r) { return r.date === req.date; })) env.append('days', { date: req.date, status: 'held', note: '' });
      A((req.present ? 'present ' : 'removed ') + req.date);
      return { ok: true };
    }
    if (a === 'marks') {
      // register sheet: many cells at once, [{id, date, present}]
      var known = {}, list = (req.list || []).slice(0, 500), changes = 0;
      env.read('students').forEach(function (r) { known[r.id] = r; });
      rows = env.read('attendance');
      var newDays = {};
      for (var i = 0; i < list.length; i++) {
        var m = list[i], mid = cleanId(m.id);
        if (!known[mid] || !validDate(m.date)) return fail('input', 'Unknown student or date.');
        if (m.date > t.date) return fail('input', 'You cannot mark a future day.');
        if (!editable(m.date, now, s)) return fail('locked', LOCKED);
        var has = rows.some(function (r) { return r.id === mid && r.date === m.date; });
        if (m.present && !has) { rows.push({ date: m.date, id: mid, name: known[mid].name, time: m.date === t.date ? t.time : '', device: '', method: 'admin', note: 'register' }); newDays[m.date] = 1; changes++; log(now, s, 'register', mid, known[mid].name, 'admin', 'done', 'present ' + m.date); }
        if (!m.present && has) { rows = rows.filter(function (r) { return !(r.id === mid && r.date === m.date); }); changes++; log(now, s, 'register', mid, known[mid].name, 'admin', 'done', 'absent ' + m.date); }
      }
      if (changes) env.write('attendance', rows);
      var dd2 = env.read('days');
      Object.keys(newDays).forEach(function (d) { if (!dd2.some(function (r) { return r.date === d; })) env.append('days', { date: d, status: 'held', note: '' }); });
      return { ok: true, changes: changes };
    }
    if (a === 'absentRest') {
      // everyone with no mark on that day gets 0; present and excused stay as they are
      if (!validDate(req.date)) return fail('input', 'Pick a class day.');
      if (req.date > t.date) return fail('input', 'You cannot mark a future day.');
      if (cancelled(req.date)) return fail('input', 'That class was cancelled.');
      if (!editable(req.date, now, s)) return fail('locked', LOCKED);
      var markedA = {}, markedE = {}, firstA = {};
      env.read('attendance').forEach(function (r) { if (r.date === req.date) markedA[r.id] = 1; if (!firstA[r.id] || r.date < firstA[r.id]) firstA[r.id] = r.date; });
      env.read('excuses').forEach(function (r) { if (r.date === req.date) markedE[r.id] = 1; });
      var sts = env.read('students'), absent = 0, moved = 0, ended = req.date === t.date && !todayDone(now, s);
      sts.forEach(function (r) {
        if (r.active === 'no' || markedA[r.id] || markedE[r.id]) return;
        // a student who joined later only counts from the day they joined, so move that day back
        var from = [firstA[r.id], r.added].filter(Boolean).sort()[0] || t.date;
        if (s.fromFirst && from > req.date) { r.added = req.date; moved++; absent++; }
        else if (ended) absent++;
      });
      if (moved) env.write('students', sts);
      // today: end check-in now so the rest count as 0 straight away
      if (ended) { env.setProp('extraUntil', '0'); env.setProp('closedDay', t.date); }
      if (!env.read('days').some(function (r) { return r.date === req.date; })) env.append('days', { date: req.date, status: 'held', note: '' });
      A('rest absent ' + req.date + ': ' + absent + (ended ? ', check-in ended' : ''));
      return { ok: true, absent: absent, ended: ended };
    }
    if (a === 'excuse') {
      if (!validId(id) || !validDate(req.date)) return fail('input', 'Pick a student and a date.');
      rows = env.read('excuses').filter(function (r) { return !(r.id === id && r.date === req.date); });
      if (req.excused) rows.push({ date: req.date, id: id, reason: String(req.reason || '').slice(0, 160), added: t.date });
      env.write('excuses', rows);
      A((req.excused ? 'excused ' : 'unexcused ') + req.date);
      return { ok: true };
    }
    if (a === 'student') {
      rows = env.read('students');
      if (req.remove) {
        if (!validId(id)) return fail('input', 'Pick a student.');
        if (env.read('attendance').some(function (r) { return r.id === id; })) return fail('input', 'This student has attendance. Switch them off instead.');
        env.write('students', rows.filter(function (r) { return r.id !== id; }));
        A('removed'); return { ok: true };
      }
      var nm = cleanName(req.name), ph = cleanPhone(req.phone);
      if (!validName(nm)) return fail('input', 'Type a name with letters only.');
      if (!ph) return fail('input', 'Type a mobile number like 0771234567.');
      var clash = rows.filter(function (r) { return r.phone === ph && r.id !== id; })[0];
      if (clash) return fail('input', 'That number already belongs to ' + clash.name + ' (' + clash.id + ').');
      var sc = staffByPhone(ph); if (sc) return fail('input', 'That number belongs to instructor ' + sc.name + '.');
      var found = null;
      if (id) rows.forEach(function (r) { if (r.id === id) found = r; });
      if (id && !found) return fail('input', 'Unknown student.');
      if (found) { found.name = nm; found.phone = ph; found.active = req.active === false ? 'no' : 'yes'; }
      else { id = nextId(s, rows); rows.push({ id: id, name: nm, added: t.date, source: 'admin', active: req.active === false ? 'no' : 'yes', phone: ph }); }
      env.write('students', rows);
      if (found) env.write('attendance', env.read('attendance').map(function (r) { if (r.id === id) r.name = nm; return r; }));
      A(found ? 'updated' : 'added'); return { ok: true, id: id };
    }
    if (a === 'bulk') {
      rows = env.read('students');
      var added = 0, bad = [];
      (req.list || []).slice(0, 300).forEach(function (x) {
        var bp = cleanPhone(x.phone), bn = cleanName(x.name), line = String(x.phone || '') + ', ' + String(x.name || '');
        if (!bp || !validName(bn)) { bad.push(line); return; }
        var hit = rows.filter(function (r) { return r.phone === bp; })[0];
        if (hit) bad.push(line + ' (number already ' + hit.id + ')');
        else if (staffByPhone(bp)) bad.push(line + ' (an instructor number)');
        else { rows.push({ id: nextId(s, rows), name: bn, added: t.date, source: 'admin', active: 'yes', phone: bp }); added++; }
      });
      env.write('students', rows);
      A('bulk ' + added + ' added'); return { ok: true, added: added, bad: bad };
    }
    if (a === 'day') {
      if (!validDate(req.date)) return fail('input', 'Pick a date.');
      rows = env.read('days').filter(function (r) { return r.date !== req.date; });
      if (req.status === 'held' || req.status === 'cancelled') rows.push({ date: req.date, status: req.status, note: String(req.note || '').slice(0, 120) });
      rows.sort(function (x, y) { return x.date < y.date ? -1 : 1; });
      env.write('days', rows);
      A(req.date + ' ' + (req.status || 'removed')); return { ok: true };
    }
    if (a === 'extra') {
      var mins = Math.max(0, Math.min(240, Number(req.minutes) || 0));
      env.setProp('extraUntil', String(mins ? now + mins * 60000 : 0));
      A('extra window ' + mins + ' min'); return { ok: true, extraUntil: mins ? now + mins * 60000 : 0 };
    }
    if (a === 'openDay') {
      var om = Math.max(0, Math.min(240, Number(req.minutes) || 0));
      if (!om) { env.setProp('openDay', ''); A('closed day for editing'); return { ok: true, openDay: null }; }
      if (!validDate(req.date) || req.date >= t.date) return fail('input', 'Pick a class day before today. Today can always be changed.');
      var od = { date: req.date, until: now + om * 60000 };
      env.setProp('openDay', JSON.stringify(od));
      if (!env.read('days').some(function (r) { return r.date === req.date; })) env.append('days', { date: req.date, status: 'held', note: '' });
      A('opened ' + req.date + ' for editing, ' + om + ' min'); return { ok: true, openDay: od };
    }
    if (a === 'settings') {
      var n = req.settings || {}, out = settings(), hm = /^([01]\d|2[0-3]):[0-5]\d$/;
      if (n.days) { var dd = n.days.map(Number).filter(function (x) { return x >= 0 && x <= 6; }); if (!dd.length) return fail('input', 'Pick at least one day.'); out.days = dd; }
      if (n.start != null) { if (!hm.test(n.start)) return fail('input', 'Start time like 09:00.'); out.start = n.start; }
      if (n.end != null) { if (!hm.test(n.end)) return fail('input', 'End time like 13:00.'); out.end = n.end; }
      if (out.start >= out.end) return fail('input', 'End time must be after start time.');
      ['requireCode', 'selfRegister', 'oneDevice', 'fromFirst', 'selfEdit'].forEach(function (k) { if (typeof n[k] === 'boolean') out[k] = n[k]; });
      if (n.idPrefix != null || n.idSuffix != null || n.idDigits != null || n.idStart != null) {
        var pre = String(n.idPrefix == null ? out.idPrefix : n.idPrefix).trim().toUpperCase(), suf = String(n.idSuffix == null ? out.idSuffix : n.idSuffix).trim().toUpperCase();
        var dig = Math.round(Number(n.idDigits == null ? out.idDigits : n.idDigits)), st0 = Math.round(Number(n.idStart == null ? out.idStart : n.idStart));
        if (!/^[A-Z0-9_\/-]{0,10}$/.test(pre) || !/^[A-Z0-9_\/-]{0,10}$/.test(suf)) return fail('input', 'Prefix and suffix: up to 10 letters, numbers or - _ /.');
        if (pre && !/^[A-Z0-9]/.test(pre)) return fail('input', 'The prefix must start with a letter or number.');
        if (!(dig >= 1 && dig <= 8)) return fail('input', 'Digits: 1 to 8.');
        if (!(st0 >= 0 && st0 < 1e8)) return fail('input', 'Start number: 0 or more.');
        if (pre !== out.idPrefix || suf !== out.idSuffix || dig !== out.idDigits || st0 !== out.idStart) env.setProp('idNext', String(st0));
        out.idPrefix = pre; out.idSuffix = suf; out.idDigits = dig; out.idStart = st0;
      }
      env.setProp('settings', JSON.stringify(out));
      A(JSON.stringify(n)); return { ok: true, settings: out };
    }
    return fail('action', 'Unknown action.');
  }

  function backupInfo() { try { return JSON.parse(env.getProp('backup') || 'null') || { auto: false }; } catch (e) { return { auto: false }; } }

  var WRITES = { staffSave: 1, myAccount: 1, mark: 1, marks: 1, excuse: 1, student: 1, bulk: 1, day: 1, extra: 1, openDay: 1, absentRest: 1, settings: 1, photo: 1, profileKey: 1, keyReq: 1, keyIssue: 1 };
  // reading and backups don't wait for the lock, so the live screen never slows check-in down
  var NOLOCK = { data: 1, today: 1, logout: 1, export: 1, backup: 1, backupAuto: 1, photos: 1 };
  function handle(req) {
    req = req || {};
    var now = env.now();
    try {
      if (req.action === 'status') return publicStatus(now);
      if (req.action === 'lookup') return lookup(req, now);
      if (req.action === 'register') return env.lock(function () { return register(req, now); });
      if (req.action === 'checkin') return env.lock(function () { return checkin(req, now); });
      if (req.action === 'me') return me(req, now);
      if (req.action === 'profile') return profileGet(req, now);
      if (req.action === 'keyRequest') return env.lock(function () { return keyRequest(req, now); });
      if (req.action === 'keySignIn') return env.lock(function () { return keySignIn(req, now); });
      if (req.action === 'profileSave') return env.lock(function () { return profileSave(req, now); });
      if (req.action === 'login') return login(req, now);
      if (!adminOk(req)) return fail('auth', 'Please log in again.');
      if (NOLOCK[req.action]) return admin(req, now);
      return env.lock(function () {
        // the page retries a save when an answer gets lost; the same operation id returns the first answer
        var key = req.opId && WRITES[req.action] ? 'op:' + String(req.opId).slice(0, 40) : '';
        if (key) { var seen = env.cacheGet(key); if (seen) { var o = JSON.parse(seen); o.repeat = true; return o; } }
        var res = admin(req, now);
        if (key && res && res.ok) env.cachePut(key, JSON.stringify(res), 21600);
        return res;
      });
    } catch (e) {
      var m = String(e && e.message ? e.message : e);
      // many students at the same second: the page waits a moment and tries again
      if (/lock|too many simultaneous|service invoked too many/i.test(m)) return fail('busy', 'The server is busy. Trying again.');
      return fail('error', 'Server error: ' + m);
    }
  }

  return { handle: handle, setPassword: setPassword, codeFor: codeFor, local: local, settings: settings, resetSecurity: resetSecurity, unlockLogin: unlockLogin };
}

/* ---------- Google Apps Script adapter ---------- */
// Speed: Sheets reads are slow (about 0.2 s each), so each tab except Log is also kept in the script
// cache. Every write gives the tab a new "generation"; a copy saved under an older generation is never
// read again, so a slow reader can't put back stale data. Typing in the Sheet does the same (onEdit).
var CACHED_TABS = { students: 1, attendance: 1, excuses: 1, days: 1, requests: 1, staff: 1 };
var CACHE_SECONDS = 21600, CHUNK = 90000;
function tabGen_(cache, t, fresh) {
  var g = fresh ? null : cache.get('g:' + t);
  if (!g) { g = Utilities.getUuid().slice(0, 13); cache.put('g:' + t, g, CACHE_SECONDS); }
  return g;
}
function cacheLoad_(cache, t, g) {
  var base = 't:' + t + ':' + g, n = Number(cache.get(base) || 0);
  if (!n) return null;
  var keys = [];
  for (var i = 0; i < n; i++) keys.push(base + ':' + i);
  var got = cache.getAll(keys), str = '';
  for (var j = 0; j < n; j++) { if (got[keys[j]] == null) return null; str += got[keys[j]]; }
  try { return JSON.parse(str); } catch (e) { return null; }
}
function cacheSave_(cache, t, g, rows) {
  // plain ASCII so every chunk stays under the cache's 100 KB per value
  var str = JSON.stringify(rows).replace(/[\u007f-￿]/g, function (c) { return '\\u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4); });
  var base = 't:' + t + ':' + g, n = Math.max(1, Math.ceil(str.length / CHUNK)), parts = {};
  if (n > 40) return;
  for (var i = 0; i < n; i++) parts[base + ':' + i] = str.substr(i * CHUNK, CHUNK);
  parts[base] = String(n);
  try { cache.putAll(parts, CACHE_SECONDS); } catch (e) {}
}

function sheetsEnv_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet(), props = PropertiesService.getScriptProperties(), cache = CacheService.getScriptCache();
  function sheet(t) {
    var sh = ss.getSheetByName(SHEET_NAMES[t]);
    if (!sh) {
      sh = ss.insertSheet(SHEET_NAMES[t]);
      sh.getRange(1, 1, sh.getMaxRows(), TABLES[t].length).setNumberFormat('@');
      sh.getRange(1, 1, 1, TABLES[t].length).setValues([TABLES[t]]).setFontWeight('bold');
      sh.setFrozenRows(1);
    } else if (sh.getLastColumn() < TABLES[t].length) {
      // a tab made by an older version: add the new column headers
      sh.getRange(1, 1, sh.getMaxRows(), TABLES[t].length).setNumberFormat('@');
      sh.getRange(1, 1, 1, TABLES[t].length).setValues([TABLES[t]]).setFontWeight('bold');
    }
    return sh;
  }
  function str(v) {
    if (v instanceof Date) return Utilities.formatDate(v, 'Asia/Colombo', 'yyyy-MM-dd');
    return v == null ? '' : String(v);
  }
  function toRow(t, o) { return TABLES[t].map(function (c) { return o[c] == null ? '' : String(o[c]); }); }
  function rowsOf(t, vals) {
    var cols = TABLES[t];
    return vals.filter(function (r) { return r.join('') !== ''; }).map(function (r) {
      var o = {}; cols.forEach(function (c, i) { o[c] = str(r[i]); }); return o;
    });
  }
  function readSheet(t) {
    var sh = sheet(t), n = sh.getLastRow();
    return n < 2 ? [] : rowsOf(t, sh.getRange(2, 1, n - 1, TABLES[t].length).getValues());
  }
  return {
    now: function () { return Date.now(); },
    read: function (t) {
      if (!CACHED_TABS[t]) return readSheet(t);
      var g = tabGen_(cache, t), rows = cacheLoad_(cache, t, g);
      if (rows) return rows;
      rows = readSheet(t);
      cacheSave_(cache, t, g, rows);
      return rows;
    },
    readTail: function (t, max) {
      var sh = sheet(t), n = sh.getLastRow();
      if (n < 2) return [];
      var from = Math.max(2, n - max + 1);
      return rowsOf(t, sh.getRange(from, 1, n - from + 1, TABLES[t].length).getValues());
    },
    // appends and writes only run inside the lock (see AttendanceCore), so rows never collide
    append: function (t, o) {
      var sh = sheet(t), r = sh.getRange(sh.getLastRow() + 1, 1, 1, TABLES[t].length);
      r.setNumberFormat('@'); r.setValues([toRow(t, o)]);
      if (!CACHED_TABS[t]) return;
      var old = cacheLoad_(cache, t, tabGen_(cache, t)), g = tabGen_(cache, t, true);
      if (old) { var row = {}; TABLES[t].forEach(function (c) { row[c] = o[c] == null ? '' : String(o[c]); }); old.push(row); cacheSave_(cache, t, g, old); }
    },
    write: function (t, rows) {
      var sh = sheet(t), cols = TABLES[t].length, n = sh.getLastRow();
      if (n > 1) sh.getRange(2, 1, n - 1, cols).clearContent();
      if (rows.length) { var r = sh.getRange(2, 1, rows.length, cols); r.setNumberFormat('@'); r.setValues(rows.map(function (o) { return toRow(t, o); })); }
      if (CACHED_TABS[t]) cacheSave_(cache, t, tabGen_(cache, t, true), rows.map(function (o) { var x = {}; TABLES[t].forEach(function (c) { x[c] = o[c] == null ? '' : String(o[c]); }); return x; }).filter(function (x) { return TABLES[t].map(function (c) { return x[c]; }).join('') !== ''; }));
    },
    getProp: function (k) { return props.getProperty(k); },
    setProp: function (k, v) { props.setProperty(k, v); },
    cacheGet: function (k) { return cache.get(k); },
    cachePut: function (k, v, s) { cache.put(k, v, s); },
    cacheDel: function (k) { cache.remove(k); },
    hmac: function (key, msg) { return Utilities.computeHmacSha256Signature(msg, key).map(function (b) { return b & 255; }); },
    sha256: function (s) { return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8).map(function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join(''); },
    random: function () { return Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '').slice(0, 8); },
    lock: function (fn, waitMs) {
      var l = LockService.getScriptLock();
      l.waitLock(waitMs || 28000);
      // flush before letting the next request in, so it reads what this one wrote
      try { return fn(); } finally { SpreadsheetApp.flush(); l.releaseLock(); }
    },
    backup: function (why) { return backupNow_(why); },
    backupAuto: function (on) { setDailyBackup_(on); }
  };
}

/* ---------- backups: a full copy of this Sheet in Drive > "Attendance backups", newest 30 kept ---------- */
function backupFolder_() {
  var props = PropertiesService.getScriptProperties(), id = props.getProperty('backupFolder');
  if (id) { try { var f = DriveApp.getFolderById(id); if (!f.isTrashed()) return f; } catch (e) {} }
  var it = DriveApp.getFoldersByName('Attendance backups'), folder = it.hasNext() ? it.next() : DriveApp.createFolder('Attendance backups');
  props.setProperty('backupFolder', folder.getId());
  return folder;
}
function backupInfo_() { try { return JSON.parse(PropertiesService.getScriptProperties().getProperty('backup') || 'null') || { auto: false }; } catch (e) { return { auto: false }; } }
function backupNow_(why) {
  var ss = SpreadsheetApp.getActiveSpreadsheet(), props = PropertiesService.getScriptProperties(), info = backupInfo_();
  SpreadsheetApp.flush();
  var name = ss.getName() + ' backup ' + Utilities.formatDate(new Date(), 'Asia/Colombo', 'yyyy-MM-dd HH:mm');
  var folder = backupFolder_(), copy = DriveApp.getFileById(ss.getId()).makeCopy(name, folder);
  var files = [], it = folder.getFiles();
  while (it.hasNext()) files.push(it.next());
  files.sort(function (a, b) { return b.getDateCreated() - a.getDateCreated(); });
  files.slice(BACKUPS_KEPT).forEach(function (f) { f.setTrashed(true); });
  info.last = Date.now(); info.name = name; info.url = copy.getUrl(); info.folder = folder.getUrl();
  info.count = Math.min(files.length, BACKUPS_KEPT); info.why = why || ''; info.error = '';
  props.setProperty('backup', JSON.stringify(info));
  return info;
}
function setDailyBackup_(on) {
  ScriptApp.getProjectTriggers().forEach(function (t) { if (t.getHandlerFunction() === 'dailyBackup') ScriptApp.deleteTrigger(t); });
  if (on) ScriptApp.newTrigger('dailyBackup').timeBased().everyDays(1).atHour(22).inTimezone('Asia/Colombo').create();
  var info = backupInfo_(); info.auto = !!on;
  PropertiesService.getScriptProperties().setProperty('backup', JSON.stringify(info));
}
function dailyBackup() {
  try { backupNow_('daily'); }
  catch (e) { var info = backupInfo_(); info.error = String(e.message || e); info.errorAt = Date.now(); PropertiesService.getScriptProperties().setProperty('backup', JSON.stringify(info)); }
}

function json_(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function doGet(e) { return json_(AttendanceCore(sheetsEnv_()).handle({ action: 'status' })); }
function doPost(e) {
  var req = {}, body = e && e.postData ? String(e.postData.contents || '') : '';
  if (body.length > 300000) return json_({ ok: false, reason: 'input', message: 'Request too big.' });
  try { req = JSON.parse(body); } catch (err) { return json_({ ok: false, reason: 'input', message: 'Bad request.' }); }
  if (!req || typeof req !== 'object' || Array.isArray(req)) return json_({ ok: false, reason: 'input', message: 'Bad request.' });
  if (req.action === 'data') ensureChangeTrigger_();
  return json_(AttendanceCore(sheetsEnv_()).handle(req));
}
// typing in the Sheet: forget the cached copy of that tab
function onEdit(e) {
  try {
    var name = e.range.getSheet().getName();
    for (var t in SHEET_NAMES) if (SHEET_NAMES[t] === name && CACHED_TABS[t]) tabGen_(CacheService.getScriptCache(), t, true);
  } catch (err) {}
}
// deleting or inserting rows doesn't fire onEdit, so a change trigger forgets the cached tabs too
function onSheetChange(e) {
  try {
    if (e && e.changeType === 'EDIT') return;
    var cache = CacheService.getScriptCache();
    Object.keys(CACHED_TABS).forEach(function (t) { tabGen_(cache, t, true); });
  } catch (err) {}
}
function ensureChangeTrigger_() {
  try {
    var props = PropertiesService.getScriptProperties();
    if (props.getProperty('changeTrigger') === '1') return;
    var has = ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'onSheetChange'; });
    if (!has) ScriptApp.newTrigger('onSheetChange').forSpreadsheet(SpreadsheetApp.getActiveSpreadsheet()).onChange().create();
    props.setProperty('changeTrigger', '1');
  } catch (err) {}
}
function onOpen() {
  SpreadsheetApp.getUi().createMenu('Attendance')
    .addItem('Set admin password', 'setAdminPassword')
    .addItem('Back up now', 'menuBackup')
    .addItem('Daily backup on or off', 'menuDailyBackup')
    .addSeparator()
    .addItem('Unlock instructor sign-in', 'menuUnlock')
    .addItem('Sign out everywhere and change QR secret', 'menuReset')
    .addItem('Reload the page data from the Sheet', 'menuClearCache')
    .addItem('Create the tabs now', 'createTabs').addToUi();
}
function setAdminPassword() {
  var ui = SpreadsheetApp.getUi(), r = ui.prompt('Admin password', 'At least 8 characters. Only its hash is saved.', ui.ButtonSet.OK_CANCEL);
  if (r.getSelectedButton() !== ui.Button.OK) return;
  try { AttendanceCore(sheetsEnv_()).setPassword(r.getResponseText()); ui.alert('Saved. Log in on the attendance page.'); }
  catch (e) { ui.alert(e.message); }
}
function menuBackup() {
  var info = backupNow_('from the Sheet menu');
  SpreadsheetApp.getUi().alert('Backed up to Drive > Attendance backups as "' + info.name + '". The newest ' + BACKUPS_KEPT + ' copies are kept.');
}
function menuDailyBackup() {
  var ui = SpreadsheetApp.getUi(), on = backupInfo_().auto;
  var r = ui.alert('Daily backup is ' + (on ? 'ON' : 'OFF'), on ? 'Turn it off?' : 'Turn it on? A copy is made every night around 10 pm Sri Lanka time.', ui.ButtonSet.YES_NO);
  if (r === ui.Button.YES) { setDailyBackup_(!on); ui.alert('Daily backup is now ' + (on ? 'OFF.' : 'ON.')); }
}
function menuUnlock() { AttendanceCore(sheetsEnv_()).unlockLogin(); SpreadsheetApp.getUi().alert('Instructor sign-in is unlocked.'); }
function menuReset() {
  var ui = SpreadsheetApp.getUi();
  if (ui.alert('Sign out everywhere?', 'Every instructor browser is signed out, trusted browsers are forgotten and the classroom QR gets a new secret. Use this if you think someone saw your password.', ui.ButtonSet.OK_CANCEL) !== ui.Button.OK) return;
  AttendanceCore(sheetsEnv_()).resetSecurity();
  ui.alert('Done. Sign in again on the attendance page. Change the password too if it may have leaked.');
}
function menuClearCache() {
  var cache = CacheService.getScriptCache();
  Object.keys(CACHED_TABS).forEach(function (t) { tabGen_(cache, t, true); });
  PropertiesService.getScriptProperties().deleteProperty('changeTrigger'); ensureChangeTrigger_();
  SpreadsheetApp.getUi().alert('Done. The page reads the Sheet again.');
}
function createTabs() {
  var env = sheetsEnv_();
  Object.keys(TABLES).forEach(function (t) { env.read(t); });
}

if (typeof module !== 'undefined') module.exports = { AttendanceCore: AttendanceCore, DEFAULT_SETTINGS: DEFAULT_SETTINGS, TABLES: TABLES };
