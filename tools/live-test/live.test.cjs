/* Live slides: a phone that sleeps, reloads or rejoins stays one student.
   Runs a local MQTT broker (aedes over WebSocket), serves the repo, opens a presenter and phones in
   Chromium (Playwright) and checks the presenter's online count and names.
   cd tools/live-test && npm i && node live.test.cjs [Cyber_Session_4_Passwords.html ...] */
const http = require('http'), fs = require('fs'), path = require('path');
const { chromium } = require('playwright');
const aedes = require('aedes')();
const { WebSocketServer, createWebSocketStream } = require('ws');

const ROOT = path.resolve(__dirname, '../..');
const DECKS = process.argv.slice(2).length ? process.argv.slice(2) : ['Cyber_Session_4_Passwords.html', 'Cyber_Session_2b_IP_Subnetting.html'];
const MQTT_JS = path.join(path.dirname(require.resolve('mqtt/package.json')), 'dist/mqtt.min.js');
const sleep = ms => new Promise(r => setTimeout(r, ms));
let fails = 0;
const ok = (c, msg) => { console.log((c ? '  ok  ' : '  FAIL ') + msg); if (!c) fails++; };
async function until(fn, ms = 10000) { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await sleep(200); } return false; }

const broker = http.createServer();
new WebSocketServer({ server: broker }).on('connection', ws => aedes.handle(createWebSocketStream(ws)));
const site = http.createServer((q, r) => {
  const f = path.join(ROOT, decodeURIComponent(q.url.split('?')[0]));
  if (!f.startsWith(ROOT) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { r.writeHead(404); return r.end(); }
  r.writeHead(200, { 'content-type': f.endsWith('.html') ? 'text/html' : 'text/plain' }); fs.createReadStream(f).pipe(r);
});
// screen off, as the class sees it: the phone's sockets die and it can't get back on until it wakes
const asleep = new Set();
aedes.authenticate = (client, u, pw, done) => done(null, ![...asleep].some(id => client.id.startsWith('acm' + id)));
const kick = id => { for (const c of Object.values(aedes.clients)) if (c.id.startsWith('acm' + id)) c.close(); };

async function ctx(browser, phone) {
  const c = await browser.newContext(phone ? { viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true } : { viewport: { width: 1366, height: 768 } });
  await c.route(/^https?:\/\/(?!127\.0\.0\.1)/, rt => /mqtt\.min\.js/.test(rt.request().url()) ? rt.fulfill({ path: MQTT_JS, contentType: 'text/javascript' }) : rt.abort());
  return c;
}
const roster = p => p.$$eval('#lvRoster span', s => s.map(e => e.textContent + (e.className ? '(' + e.className + ')' : '')));
const count = p => p.$eval('#lvN', e => +e.textContent);
// phones run the deck in a scaled frame (the phone shell), so look inside it
const deckOf = async p => (await p.waitForSelector('#shf')).contentFrame().then(async f => { await f.waitForSelector('#lvChip'); return f; });
async function join(c, url, name) {
  const p = await c.newPage(); p.on('pageerror', e => console.log('    page error:', e.message)); await p.goto(url);
  const f = await deckOf(p);
  if (name) { await f.fill('#lvNameIn', name); await f.click('#lvName button'); }
  return p;
}
const slideOf = async p => (await deckOf(p)).$eval('.slide.active', s => s.dataset.id);
const asked = async p => !!(await (await deckOf(p)).$('#lvName'));
const devId = p => p.evaluate(() => localStorage.getItem('acm-live-id') || sessionStorage.getItem('acm-live-id'));

async function deck(browser, file) {
  console.log('\n' + file);
  const base = 'http://127.0.0.1:' + site.address().port + '/' + file;
  const pc = await ctx(browser, false), pres = await pc.newPage();
  await pres.goto(base + '?lvb=' + encodeURIComponent('ws://127.0.0.1:' + broker.address().port) + '#levels');
  await pres.keyboard.press('l');
  await pres.waitForSelector('#lvLink');
  await until(async () => /Connected to 1/.test(await pres.textContent('#lvSt')));
  const url = (await pres.textContent('#lvLink')).trim(); if (process.env.DEBUG) console.log(url);

  const phoneA = await ctx(browser, true), a = await join(phoneA, url, 'Nimal');
  ok(await until(async () => await count(pres) === 1), 'first join: 1 online');
  const idA = await devId(a);

  // screen off: page frozen and its sockets dropped; the teacher moves on meanwhile
  const cdp = await phoneA.newCDPSession(a);
  const vis = h => deckOf(a).then(f => f.evaluate(h => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => h }); document.dispatchEvent(new Event('visibilitychange')); }, h));
  await vis(true);
  await cdp.send('Page.setWebLifecycleState', { state: 'frozen' }).catch(() => {});
  asleep.add(idA); kick(idA);
  await pres.keyboard.press('Escape'); await pres.keyboard.press('ArrowRight'); await pres.keyboard.press('ArrowRight');
  const presSlide = await pres.$eval('.slide.active', s => s.dataset.id);
  await pres.keyboard.press('l'); await pres.waitForSelector('#lvAway', { state: 'attached' });
  ok(await until(async () => /1 reconnecting/.test(await pres.textContent('#lvAway')), 40000), 'screen off: teacher sees "1 reconnecting", not a drop');
  ok(await count(pres) === 0, 'screen off: online count 0');
  // screen on again
  await cdp.send('Page.setWebLifecycleState', { state: 'active' }).catch(() => {});
  asleep.delete(idA);
  await vis(false);
  ok(await until(async () => await count(pres) === 1, 3000), 'screen on: back online within 3 s, without a new QR');
  ok(await until(async () => (await slideOf(a)) === presSlide, 6000), 'screen on: phone is on the teacher\'s slide (' + presSlide + ')');
  ok((await roster(pres)).join() === 'Nimal', 'screen on: one name, ' + (await roster(pres)).join());

  // iPhone throws the page away and reloads it
  await a.reload();
  ok(!(await asked(a)), 'reload: no name question');
  ok(await devId(a) === idA, 'reload: same phone id');
  ok(await until(async () => (await slideOf(a)) === presSlide, 6000), 'reload: back on the teacher\'s slide');
  await sleep(1500);
  ok(await count(pres) === 1 && (await roster(pres)).length === 1, 'reload: count 1, one name');

  // scanning the QR again in the same browser
  const a2 = await join(phoneA, url, null); await a.close();
  ok(!(await asked(a2)) && await devId(a2) === idA, 'scan again: same id, no name question');
  await sleep(1500);
  ok(await count(pres) === 1 && (await roster(pres)).length === 1, 'scan again: count 1, one name');

  // a second student with the same name, both online: two rows
  const phoneB = await ctx(browser, true), b = await join(phoneB, url, 'Nimal');
  ok(await until(async () => await count(pres) === 2), 'same name, two phones online: 2 online');

  // phone B's storage is gone (private tab): after it has gone quiet its new id takes over the old row
  const idB = await devId(b); await phoneB.close(); kick(idB);
  await sleep(17000);
  const phoneC = await ctx(browser, true), c = await join(phoneC, url, 'nimal');
  ok(await until(async () => await count(pres) === 2), 'private-tab rejoin: still 2 online');
  ok(await pres.evaluate(() => JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k => /-roster-/.test(k)))).length) === 2, 'private-tab rejoin: 2 rows in the class file, not 3');

  await Promise.all([pc.close(), phoneA.close(), phoneC.close()]); void c; void a2;
}

(async () => {
  await new Promise(r => broker.listen(0, '127.0.0.1', r));
  await new Promise(r => site.listen(0, '127.0.0.1', r));
  const browser = await chromium.launch();
  try { for (const d of DECKS) await deck(browser, d); }
  catch (e) { console.error(e); fails++; }
  await browser.close(); broker.close(); site.close(); aedes.close();
  console.log(fails ? '\n' + fails + ' failed' : '\nall passed');
  process.exit(fails ? 1 : 0);
})();
