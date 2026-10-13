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
*/

// bump when the page needs new server actions; the page warns when Apps Script runs an older copy
var SERVER_VERSION = 6;

var DEFAULT_SETTINGS = {
  days: [6],            // 0 Sun ... 6 Sat
  start: '09:00',
  end: '13:00',
  tzOffset: 330,        // minutes from UTC: Asia/Colombo is +05:30, no daylight saving
  tzName: 'Asia/Colombo',
  requireCode: true,    // must scan the live QR (or type its code) in the room
  selfRegister: true,   // new students may register themselves (mobile number + name) on first check-in
  oneDevice: true,      // one student per phone per day
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
  log:        ['ts', 'date', 'time', 'action', 'id', 'name', 'device', 'result', 'detail']
};

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
    return !isOpen(now, s) && (s.days.indexOf(t.day) < 0 || t.time >= s.end);
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
  function byPhone(phone) { return env.read('students').filter(function (r) { return r.phone && r.phone === phone; })[0] || null; }
  function studentOut(st) { return { id: st.id, name: st.name, phone: st.phone }; }
  // shared checks for every student step: real browser, not too many tries, valid number, open now, live code
  function gate(req, now, s, L) {
    var device = String(req.device || '').slice(0, 40);
    if (!/^[a-z0-9]{8,40}$/i.test(device)) { L('rejected', 'no device id'); return fail('device', 'Open this page in a normal browser tab and try again.'); }
    if (rateLimited('rl:' + device, 20, 600)) { L('rejected', 'too many tries'); return fail('slow', 'Too many tries. Wait 10 minutes.'); }
    if (!cleanPhone(req.phone)) { L('rejected', 'bad number'); return fail('phone', 'Type your mobile number, like 0771234567.'); }
    if (!isOpen(now, s)) { L('rejected', 'closed'); return fail('closed', 'Check-in is closed now.', { nextOpen: nextOpen(now, s) }); }
    if (s.requireCode && !codeOk(req.code, now, s)) { L('rejected', 'bad or old code'); return fail('code', 'That QR code has expired. Scan the screen again.'); }
    return null;
  }
  function validName(n) { return n.length >= 2 && n.length <= 60 && /^[\p{L}\p{M} .'-]+$/u.test(n); }

  function log(now, s, action, id, name, device, result, detail) {
    var t = local(now, s);
    env.append('log', { ts: String(now), date: t.date, time: t.time + ':' + t.sec, action: action,
      id: id || '', name: name || '', device: device || '', result: result, detail: detail || '' });
  }
  function rateLimited(key, max, seconds) {
    var n = Number(env.cacheGet(key) || 0) + 1;
    env.cachePut(key, String(n), seconds);
    return n > max;
  }
  function publicStatus(now) {
    var s = settings(), t = local(now, s);
    var o = openDay(now);
    return { ok: true, version: SERVER_VERSION, now: now, today: t.date, time: t.time, open: isOpen(now, s), todayDone: todayDone(now, s),
      extraUntil: extraWindow(now), nextOpen: nextOpen(now, s), openDay: o ? { date: o.date, until: o.until } : null,
      window: { days: s.days, start: s.start, end: s.end, tzName: s.tzName, tzOffset: s.tzOffset },
      requireCode: s.requireCode, selfRegister: s.selfRegister, configured: !!env.getProp('adminHash'), idExample: formatId(s, Number(s.idStart) || 1) };
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
    return { ok: true, found: true, student: studentOut(st), already: mine ? mine.time : '', date: t.date };
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
    if (rateLimited('rl:' + device, 20, 600)) return fail('slow', 'Too many tries. Wait 10 minutes.');
    var st = phone ? byPhone(phone) : null;
    if (!st || !sameName(st.name, name)) return fail('notfound', 'No record for this number and name yet.');
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
  function login(req, now) {
    var s = settings();
    if (!env.getProp('adminHash')) return fail('nopass', 'No admin password yet. In the Google Sheet: Attendance > Set admin password.');
    if (Number(env.cacheGet('loginfail') || 0) >= 20) { log(now, s, 'login', '', '', '', 'rejected', 'locked'); return fail('locked', 'Too many wrong passwords. Wait 15 minutes.'); }
    if (hashPw(String(req.password || ''), env.getProp('adminSalt')) !== env.getProp('adminHash')) {
      env.cachePut('loginfail', String(Number(env.cacheGet('loginfail') || 0) + 1), 900);
      log(now, s, 'login', '', '', '', 'rejected', 'wrong password');
      return fail('password', 'Wrong password.');
    }
    var token = env.random();
    env.cachePut('adm:' + token, '1', 21600);
    log(now, s, 'login', '', '', '', 'accepted', '');
    return { ok: true, token: token, qrKey: qrKey(), now: now, hours: 6 };
  }
  function adminOk(req) { return req.token && /^[a-f0-9]{16,64}$/.test(req.token) && env.cacheGet('adm:' + req.token) === '1'; }
  function validDate(d) { return /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')); }

  function admin(req, now) {
    var s = settings(), t = local(now, s), a = req.action, rows, id = cleanId(req.id);
    var A = function (detail) { log(now, s, a, id, '', 'admin', 'done', detail || ''); };
    if (a === 'logout') { env.cacheDel('adm:' + req.token); return { ok: true }; }
    if (a === 'data') {
      var lg = env.read('log');
      return { ok: true, now: now, today: t.date, settings: s, status: publicStatus(now),
        students: env.read('students'), attendance: env.read('attendance'), excuses: env.read('excuses'),
        days: env.read('days'), log: lg.slice(Math.max(0, lg.length - 400)),
        nextIdPreview: formatId(s, Math.max(Number(env.getProp('idNext') || 0), Number(s.idStart) || 1)) };
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
      ['requireCode', 'selfRegister', 'oneDevice', 'fromFirst'].forEach(function (k) { if (typeof n[k] === 'boolean') out[k] = n[k]; });
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

  var WRITES = { mark: 1, marks: 1, excuse: 1, student: 1, bulk: 1, day: 1, extra: 1, openDay: 1, settings: 1 };
  function handle(req) {
    req = req || {};
    var now = env.now();
    try {
      if (req.action === 'status') return publicStatus(now);
      if (req.action === 'lookup') return lookup(req, now);
      if (req.action === 'register') return env.lock(function () { return register(req, now); });
      if (req.action === 'checkin') return env.lock(function () { return checkin(req, now); });
      if (req.action === 'me') return me(req, now);
      if (req.action === 'login') return login(req, now);
      if (!adminOk(req)) return fail('auth', 'Please log in again.');
      return env.lock(function () {
        // the page retries a save when an answer gets lost; the same operation id returns the first answer
        var key = req.opId && WRITES[req.action] ? 'op:' + String(req.opId).slice(0, 40) : '';
        if (key) { var seen = env.cacheGet(key); if (seen) { var o = JSON.parse(seen); o.repeat = true; return o; } }
        var res = admin(req, now);
        if (key && res && res.ok) env.cachePut(key, JSON.stringify(res), 21600);
        return res;
      });
    } catch (e) {
      return fail('error', 'Server error: ' + (e && e.message ? e.message : e));
    }
  }

  return { handle: handle, setPassword: setPassword, codeFor: codeFor, local: local, settings: settings };
}

/* ---------- Google Apps Script adapter ---------- */
function sheetsEnv_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet(), props = PropertiesService.getScriptProperties(), cache = CacheService.getScriptCache();
  var NAMES = { students: 'Students', attendance: 'Attendance', excuses: 'Excuses', days: 'Days', log: 'Log' };
  function sheet(t) {
    var sh = ss.getSheetByName(NAMES[t]);
    if (!sh) {
      sh = ss.insertSheet(NAMES[t]);
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
  return {
    now: function () { return Date.now(); },
    read: function (t) {
      var sh = sheet(t), n = sh.getLastRow(), cols = TABLES[t];
      if (n < 2) return [];
      return sh.getRange(2, 1, n - 1, cols.length).getValues().filter(function (r) { return r.join('') !== ''; }).map(function (r) {
        var o = {}; cols.forEach(function (c, i) { o[c] = str(r[i]); }); return o;
      });
    },
    append: function (t, o) {
      var sh = sheet(t), r = sh.getRange(sh.getLastRow() + 1, 1, 1, TABLES[t].length);
      r.setNumberFormat('@'); r.setValues([toRow(t, o)]);
    },
    write: function (t, rows) {
      var sh = sheet(t), cols = TABLES[t].length, n = sh.getLastRow();
      if (n > 1) sh.getRange(2, 1, n - 1, cols).clearContent();
      if (rows.length) { var r = sh.getRange(2, 1, rows.length, cols); r.setNumberFormat('@'); r.setValues(rows.map(function (o) { return toRow(t, o); })); }
    },
    getProp: function (k) { return props.getProperty(k); },
    setProp: function (k, v) { props.setProperty(k, v); },
    cacheGet: function (k) { return cache.get(k); },
    cachePut: function (k, v, s) { cache.put(k, v, s); },
    cacheDel: function (k) { cache.remove(k); },
    hmac: function (key, msg) { return Utilities.computeHmacSha256Signature(msg, key).map(function (b) { return b & 255; }); },
    sha256: function (s) { return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8).map(function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join(''); },
    random: function () { return Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '').slice(0, 8); },
    lock: function (fn) { var l = LockService.getScriptLock(); l.waitLock(25000); try { return fn(); } finally { l.releaseLock(); } }
  };
}

function json_(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function doGet(e) { return json_(AttendanceCore(sheetsEnv_()).handle({ action: 'status' })); }
function doPost(e) {
  var req = {};
  try { req = JSON.parse(e.postData.contents); } catch (err) { return json_({ ok: false, reason: 'input', message: 'Bad request.' }); }
  return json_(AttendanceCore(sheetsEnv_()).handle(req));
}
function onOpen() {
  SpreadsheetApp.getUi().createMenu('Attendance').addItem('Set admin password', 'setAdminPassword').addItem('Create the tabs now', 'createTabs').addToUi();
}
function setAdminPassword() {
  var ui = SpreadsheetApp.getUi(), r = ui.prompt('Admin password', 'At least 8 characters. Only its hash is saved.', ui.ButtonSet.OK_CANCEL);
  if (r.getSelectedButton() !== ui.Button.OK) return;
  try { AttendanceCore(sheetsEnv_()).setPassword(r.getResponseText()); ui.alert('Saved. Log in on the attendance page.'); }
  catch (e) { ui.alert(e.message); }
}
function createTabs() {
  var env = sheetsEnv_();
  Object.keys(TABLES).forEach(function (t) { env.read(t); });
}

if (typeof module !== 'undefined') module.exports = { AttendanceCore: AttendanceCore, DEFAULT_SETTINGS: DEFAULT_SETTINGS, TABLES: TABLES };
