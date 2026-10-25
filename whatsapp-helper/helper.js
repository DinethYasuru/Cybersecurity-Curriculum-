/*
  WhatsApp helper for the class attendance app.

  Runs on the admin's laptop. It signs in to WhatsApp Web once (scan the QR in this window), then asks the
  attendance server for the next sign-in key to send, sends it to the student who asked for it, and tells the
  server it went. The server decides who gets a message and how fast (a few an hour and a day, minutes apart,
  in the day only); this helper keeps its own, lower limits too, waits a random while between messages and
  "types" before each one, so it looks like a person and not a bulk sender.

  The helper's key (config.json) can only take the next key to send and say "sent". It can't see students,
  attendance or anything else. Setup: README.md in this folder.
*/
const fs = require('fs');
const path = require('path');
const qrcode = require('qrcode-terminal');
const { Client, LocalAuth } = require('whatsapp-web.js');

const HERE = __dirname;
const CONFIG = path.join(HERE, 'config.json');
const STATE = path.join(HERE, 'state.json');

if (!fs.existsSync(CONFIG)) {
  console.log('No config.json yet. Copy config.example.json to config.json and put your helper key in it (see README.md).');
  process.exit(1);
}
const cfg = JSON.parse(fs.readFileSync(CONFIG, 'utf8'));
if (!/^wa_[a-f0-9]{48}$/.test(String(cfg.helperKey || ''))) {
  console.log('The helper key in config.json is not right. Make one in the attendance app: Student requests > Helper settings > Make helper key.');
  process.exit(1);
}
const SERVER = String(cfg.server || 'https://cyber-attendance.dinethyasuru.workers.dev').replace(/\/+$/, '/');
// this helper's own limits, never above the server's (the server has the final say)
const MAX_HOUR = Math.min(Number(cfg.maxPerHour) || 6, 10);
const MAX_DAY = Math.min(Number(cfg.maxPerDay) || 20, 40);

const sleep = ms => new Promise(r => setTimeout(r, ms));
const rand = (a, b) => a + Math.random() * (b - a);
const now = () => new Date().toLocaleTimeString();
const log = (...a) => console.log('[' + now() + ']', ...a);

// what was sent from this laptop: the times (for the limits) and which requests (never the same one twice)
function loadState() {
  try { const s = JSON.parse(fs.readFileSync(STATE, 'utf8')); return { times: s.times || [], done: s.done || {} }; } catch (e) { return { times: [], done: {} }; }
}
function saveState(s) {
  const day = Date.now() - 86400000, week = Date.now() - 8 * 86400000;
  s.times = s.times.filter(t => t > day);
  for (const k in s.done) if (s.done[k] < week) delete s.done[k];
  fs.writeFileSync(STATE, JSON.stringify(s));
}
const state = loadState();

async function call(body) {
  const res = await fetch(SERVER, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(Object.assign({ helperKey: cfg.helperKey }, body)) });
  return res.json();
}

const client = new Client({
  authStrategy: new LocalAuth({ dataPath: path.join(HERE, '.wwebjs_auth') }),
  puppeteer: { headless: true, args: ['--no-sandbox'] }
});

client.on('qr', qr => {
  console.log('\nScan this with the phone whose WhatsApp should send the keys:');
  console.log('WhatsApp > Settings > Linked devices > Link a device\n');
  qrcode.generate(qr, { small: true });
});
client.on('authenticated', () => log('Signed in to WhatsApp. Next time no QR is needed.'));
client.on('auth_failure', m => { log('WhatsApp sign-in failed:', m, '- delete the .wwebjs_auth folder and start again.'); process.exit(1); });
client.on('disconnected', why => { log('WhatsApp disconnected (' + why + '). Start the helper again; if it keeps happening, link the device again.'); process.exit(1); });
client.on('ready', () => { log('WhatsApp is ready. Waiting for sign-in keys to send. Leave this window open; Ctrl+C stops.'); run(); });

let stopping = false;
process.on('SIGINT', async () => {
  if (stopping) process.exit(0);
  stopping = true; log('Stopping...');
  try { await client.destroy(); } catch (e) {}
  process.exit(0);
});

async function run() {
  let lastWhy = '';
  while (!stopping) {
    // this laptop's own limits first: nothing is taken from the server while they are reached
    const t = Date.now(), hour = state.times.filter(x => x > t - 3600000), day = state.times.filter(x => x > t - 86400000);
    if (hour.length >= MAX_HOUR || day.length >= MAX_DAY) {
      const until = day.length >= MAX_DAY ? day[day.length - MAX_DAY] + 86400000 : hour[hour.length - MAX_HOUR] + 3600000;
      if (lastWhy !== 'mine') log('This laptop\'s own limit reached (' + MAX_HOUR + ' an hour, ' + MAX_DAY + ' a day). Waiting.');
      lastWhy = 'mine'; await sleep(Math.max(until - t, 60000) + rand(5000, 30000)); continue;
    }
    let r;
    try { r = await call({ action: 'waNext' }); } catch (e) { log('Cannot reach the attendance server:', e.message, '- trying again in 5 minutes.'); await sleep(300000); continue; }
    if (!r.ok) {
      if (r.reason === 'off') { if (lastWhy !== 'off') log('Sending is turned off in Student requests. Checking again every 5 minutes.'); lastWhy = 'off'; await sleep(300000); continue; }
      log(r.message || 'The server said no.');
      if (r.reason === 'key') { log('Make a new helper key in Student requests, put it in config.json, and start again.'); process.exit(1); }
      await sleep(900000); continue;
    }
    if (r.wait) {
      if (r.why !== lastWhy) log(r.why, 'Next look in about', Math.round(r.wait / 60) || 1, 'min.');
      lastWhy = r.why;
      await sleep(r.wait * 1000 + rand(5000, 30000));
      continue;
    }
    lastWhy = '';
    await sendOne(r);
    // a person never sends the next one straight away
    await sleep(rand(60000, 180000));
  }
}

async function sendOne(r) {
  const done = (sent, reason) => call({ action: 'waDone', rid: r.rid, claim: r.claim, sent, reason }).catch(e => log('Could not tell the server:', e.message));
  // only ever a Sri Lankan mobile number, and only the one the server named
  if (!/^94\d{9}$/.test(String(r.to || '')) || typeof r.text !== 'string' || r.text.length > 1000) return done(false, 'bad request from server');
  // sent from here already (the helper stopped before the server heard): say so, never send twice
  if (state.done[r.rid]) { log('Already sent that one. Telling the server.'); return done(true); }
  try {
    const id = await client.getNumberId(r.to);
    if (!id) { log('+' + r.to + ' has no WhatsApp. The admin can send this key another way.'); return done(false, 'no WhatsApp on this number'); }
    const chat = await client.getChatById(id._serialized);
    await sleep(rand(2000, 5000));
    await chat.sendStateTyping();
    await sleep(rand(5000, 12000));
    await client.sendMessage(id._serialized, r.text, { linkPreview: false });
    await chat.clearState().catch(() => {});
    state.times.push(Date.now()); state.done[r.rid] = Date.now(); saveState(state);
    log('Sent a key to +' + r.to.slice(0, 4) + '*****' + r.to.slice(-2) + '.');
    return done(true);
  } catch (e) {
    log('Could not send:', e.message);
    return done(false, 'WhatsApp error');
  }
}

log('Starting WhatsApp Web (the first start downloads a browser and takes a minute)...');
client.initialize();
