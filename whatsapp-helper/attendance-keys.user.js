// ==UserScript==
// @name         Attendance keys sender
// @namespace    american-corner-matara
// @version      1.0.0
// @description  Sends class attendance app sign-in keys from this WhatsApp Web tab, one at a time, slowly.
// @match        https://web.whatsapp.com/*
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @connect      workers.dev
// @run-at       document-idle
// ==/UserScript==

/*
  No Node, no server on the laptop: this runs inside the WhatsApp Web tab (with the free Tampermonkey extension).
  The attendance server is the queue. In a loop, this script:
    1. asks the server for the next sign-in key to send (the server says "wait" when a limit or the hours say so),
    2. opens that student's chat with the message filled in (web.whatsapp.com/send?phone=...&text=...),
    3. presses Send, and
    4. tells the server it went: the request is flagged sent, and the next one can come.
  The helper key can only do steps 1 and 4. The limits are kept on the server. Setup: README.md in this folder.
*/
(function () {
  'use strict';
  const SERVER_DEFAULT = 'https://cyber-attendance.dinethyasuru.workers.dev/';
  const S = {
    get: (k, d) => { try { const v = GM_getValue(k); return v === undefined ? d : v; } catch (e) { return d; } },
    set: (k, v) => { try { GM_setValue(k, v); } catch (e) {} }
  };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const rand = (a, b) => a + Math.random() * (b - a);

  /* ---------- a small panel at the bottom left: status, pause, key ---------- */
  const box = document.createElement('div');
  box.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:99999;background:#fff;color:#002868;border:2px solid #002868;border-radius:10px;padding:8px 10px;font:13px/1.35 system-ui,sans-serif;max-width:300px;box-shadow:0 4px 16px rgba(0,0,0,.2)';
  box.innerHTML = '<b>Attendance keys</b> <button data-p style="margin-left:6px">Pause</button> <button data-k title="Set the helper key">Key</button><div data-s style="margin-top:4px;color:#333"></div>';
  document.body.appendChild(box);
  const say = t => { box.querySelector('[data-s]').textContent = t; console.log('[attendance keys]', t); };
  const paused = () => S.get('paused', false);
  const paintPause = () => { box.querySelector('[data-p]').textContent = paused() ? 'Start' : 'Pause'; box.style.borderColor = paused() ? '#999' : '#002868'; };
  box.querySelector('[data-p]').onclick = () => { S.set('paused', !paused()); paintPause(); if (!paused()) loop(); else say('Paused. Nothing is sent.'); };
  box.querySelector('[data-k]').onclick = () => askKey(true);
  paintPause();

  function askKey(force) {
    let k = S.get('key', '');
    if (force || !/^wa_[a-f0-9]{48}$/.test(k)) {
      k = (prompt('Paste the helper key from the attendance app (Student requests > Helper settings > Make helper key):', '') || '').trim();
      if (!/^wa_[a-f0-9]{48}$/.test(k)) { say('No helper key yet. Click Key.'); return ''; }
      S.set('key', k);
      say('Key saved.');
    }
    return k;
  }

  function call(body) {
    return new Promise((resolve, reject) => GM_xmlhttpRequest({
      method: 'POST', url: S.get('server', SERVER_DEFAULT), headers: { 'content-type': 'application/json' },
      data: JSON.stringify(Object.assign({ helperKey: S.get('key', '') }, body)), timeout: 30000,
      onload: r => { try { resolve(JSON.parse(r.responseText)); } catch (e) { reject(new Error('bad answer from the server')); } },
      onerror: () => reject(new Error('cannot reach the server')), ontimeout: () => reject(new Error('the server did not answer'))
    }));
  }

  // what this browser sent (never the same request twice, even if the tab closed before the server heard)
  const doneList = () => { const d = S.get('done', {}), old = Date.now() - 8 * 86400000; for (const k in d) if (d[k] < old) delete d[k]; return d; };

  /* ---------- WhatsApp Web's own screen: the send button, or "this number is not on WhatsApp" ---------- */
  const sendButton = () => {
    const ic = document.querySelector('footer span[data-icon="send"], footer span[data-icon="wds-ic-send-filled"], footer [data-icon*="send"]');
    return ic ? ic.closest('button,[role="button"]') : document.querySelector('footer button[aria-label="Send"]');
  };
  const invalidNumber = () => /phone number shared via url is invalid|is not on whatsapp/i.test((document.querySelector('[role="dialog"]') || {}).textContent || '');
  const composeText = () => { const c = document.querySelector('footer [contenteditable="true"]'); return c ? c.textContent.trim() : ''; };

  /* ---------- step 3 and 4: the chat is open with the message filled in ---------- */
  async function finishSend(job) {
    const done = (sent, reason) => call({ action: 'waDone', rid: job.rid, claim: job.claim, sent, reason }).catch(e => say('Could not tell the server: ' + e.message));
    S.set('job', null);
    if (doneList()[job.rid]) { await done(true); return; }
    say('Opening the chat...');
    let btn = null;
    for (let i = 0; i < 90 && !btn; i++) {
      await sleep(1000);
      if (invalidNumber()) { say('+' + job.to + ' has no WhatsApp. Send that key by hand.'); await done(false, 'no WhatsApp on this number'); return; }
      btn = sendButton();
    }
    if (!btn) { say('The chat did not open. It will be tried once more later.'); await done(false, 'chat did not open'); return; }
    // a person reads before pressing send
    await sleep(rand(4000, 10000));
    if (paused()) { say('Paused before sending.'); await done(false, 'paused before sending'); return; }
    btn.click();
    for (let i = 0; i < 10 && composeText(); i++) await sleep(1000);
    if (composeText()) { say('Send did not go through. It will be tried once more later.'); await done(false, 'send button did not work'); return; }
    const d = doneList(); d[job.rid] = Date.now(); S.set('done', d);
    await done(true);
    say('Sent a key to +' + job.to.slice(0, 4) + '*****' + job.to.slice(-2) + '. Next in a few minutes.');
  }

  /* ---------- steps 1 and 2: ask the server, open the chat ---------- */
  let running = false;
  async function loop() {
    if (running) return; running = true;
    try {
      while (!paused()) {
        if (!askKey(false)) return;
        let r;
        try { r = await call({ action: 'waNext' }); } catch (e) { say(e.message + '. Trying again in 5 minutes.'); await sleep(300000); continue; }
        if (!r.ok) {
          if (r.reason === 'key') { say('The helper key is not right. Click Key and paste a new one.'); S.set('key', ''); return; }
          say(r.reason === 'off' ? 'Sending is off in Student requests. Checking every 5 minutes.' : (r.message || 'The server said no.'));
          await sleep(300000); continue;
        }
        if (r.wait) { say(r.why + ' Next look in about ' + (Math.round(r.wait / 60) || 1) + ' min.'); await sleep(r.wait * 1000 + rand(5000, 30000)); continue; }
        if (!/^94\d{9}$/.test(String(r.to || '')) || typeof r.text !== 'string' || r.text.length > 1000) {
          await call({ action: 'waDone', rid: r.rid, claim: r.claim, sent: false, reason: 'bad request from server' }); continue;
        }
        // the page reloads to open the chat; the job is kept so the script finishes it after the reload
        S.set('job', { rid: r.rid, claim: r.claim, to: r.to, at: Date.now() });
        say('Sending a key to +' + r.to.slice(0, 4) + '*****' + r.to.slice(-2) + '...');
        await sleep(rand(2000, 5000));
        location.href = 'https://web.whatsapp.com/send?phone=' + r.to + '&text=' + encodeURIComponent(r.text);
        return;
      }
      say('Paused. Nothing is sent.');
    } finally { running = false; }
  }

  async function start() {
    // wait for WhatsApp Web to finish loading (the chat list, or the QR to link the phone)
    for (let i = 0; i < 120 && !document.querySelector('#side, #pane-side, canvas[aria-label]'); i++) await sleep(1000);
    if (!document.querySelector('#side, #pane-side')) { say('Link this browser to WhatsApp first (scan the QR), then reload.'); return; }
    const job = S.get('job', null);
    if (job && Date.now() - job.at < 9 * 60000) await finishSend(job);
    else if (job) S.set('job', null);
    if (paused()) { say('Paused. Click Start to send keys.'); return; }
    // a person never sends the next one straight away
    if (job) await sleep(rand(60000, 180000));
    loop();
  }
  say('Waiting for WhatsApp Web...');
  start();
})();
