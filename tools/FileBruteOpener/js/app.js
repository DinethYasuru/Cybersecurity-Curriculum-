/* Dashboard UI wiring. Depends on every other js/*.js module (loaded as plain scripts
   before this one in index.html) plus the DOM defined there. */

const state = {
  file: null,        // { name, size, bytes }
  identification: null,
  pdfInfo: null,
  zipAnalysis: null,
  officeInfo: null,
  history: [],
  activeSearch: null,
  calibratedRate: null,   // candidates/sec/worker, measured live on the currently loaded file
  calibratedFormat: null,
};

const el = (id) => document.getElementById(id);

function nowStamp() { return new Date().toLocaleString(); }

function addHistory(entry) {
  state.history.unshift({ id: Date.now() + '-' + Math.random().toString(36).slice(2), time: nowStamp(), ...entry });
  renderHistory();
}

/* ---------- File loading & identification ---------- */

function setupDropzone() {
  const zone = el('dropzone');
  const input = el('fileInput');
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.classList.remove('drag');
    if (e.dataTransfer.files.length) loadFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => { if (input.files.length) loadFile(input.files[0]); });
  el('clearFileBtn').addEventListener('click', resetFileState);
}

async function loadFile(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  state.file = { name: file.name, size: buf.length, bytes: buf };
  el('dropzone').textContent = `Loaded: ${file.name} (${buf.length.toLocaleString()} bytes) — click to choose a different file`;
  el('clearFileBtn').disabled = false;

  const result = await identifyFile(buf);
  state.identification = result;
  renderIdentification(result);
  addHistory({ action: 'identify', fileName: file.name, detail: result.format, result: result.encrypted ? 'encrypted' : (result.encrypted === false ? 'not encrypted' : 'unknown') });

  applyVerifiableState(buf, result);
  updateActionPanelsVisibility();
}

/** Fully resets everything tied to the currently loaded file - dropzone, identification,
 * and the verify/search panels (including cancelling any in-flight search) - so starting
 * over with a different file doesn't require a page reload or leave stale results showing. */
function resetFileState() {
  if (state.activeSearch) { state.activeSearch.cancel(); state.activeSearch = null; }
  state.file = null;
  state.identification = null;
  state.pdfInfo = null; state.zipAnalysis = null; state.officeInfo = null;
  state.calibratedRate = null; state.calibratedFormat = null;

  el('dropzone').textContent = 'Drop a file here, or click to choose one';
  el('fileInput').value = '';
  el('clearFileBtn').disabled = true;

  el('panel-identify').classList.add('hidden');
  el('identify-body').innerHTML = '';

  el('panel-verify').classList.add('hidden');
  el('panel-search').classList.add('hidden');
  clearVerifyPanel();
  clearSearchPanel();
}

function clearVerifyPanel() {
  el('verifyPassword').value = '';
  el('verify-result').innerHTML = '';
}

function clearSearchPanel() {
  el('dictInput').value = '';
  el('maskLength').value = 4;
  el('search-result').innerHTML = '';
  el('search-estimate').textContent = '';
  el('searchProgressWrap').classList.add('hidden');
  el('progress-fill').style.width = '0%';
  el('progress-stats').textContent = '';
}

/** Sets whichever of state.{pdfInfo,zipAnalysis,officeInfo} applies, based on the
 * identification result - shared between loading a dropped file and loading a
 * generated/sample one. Office is only set for schemes with password verification actually
 * implemented: "standard" always, and "agile" only when its XML parsed cleanly and its
 * hashAlgorithm is one sha1.js/sha2.js implements (see js/office-auth.js). */
function applyVerifiableState(buf, result) {
  state.pdfInfo = null; state.zipAnalysis = null; state.officeInfo = null;
  if (result.format === 'PDF' && result.encrypted) {
    state.pdfInfo = extractPdfEncryptionInfo(buf);
  } else if (result.format.startsWith('ZIP') && result.encrypted) {
    state.zipAnalysis = analyzeZip(buf);
  } else if (typeof extractOfficeEncryptionInfo === 'function') {
    const officeInfo = extractOfficeEncryptionInfo(buf);
    if (officeInfo && officeInfo.scheme === 'standard') state.officeInfo = officeInfo;
    else if (officeInfo && officeInfo.scheme === 'agile' && !officeInfo.parseError && officeInfo.hashSupported) state.officeInfo = officeInfo;
  }
}

function badge(text, cls) { return `<span class="badge ${cls}">${text}</span>`; }

function renderIdentification(r) {
  el('panel-identify').classList.remove('hidden');
  const encBadge = r.encrypted === true ? badge('Encrypted', 'warn') : (r.encrypted === false ? badge('Not encrypted', 'ok') : badge('Unknown', 'neutral'));
  let detailHtml = '';
  if (r.encryptionDetail) detailHtml = `<dt>Encryption detail</dt><dd>${JSON.stringify(r.encryptionDetail)}</dd>`;
  el('identify-body').innerHTML = `
    <div class="tag-row">${badge(r.format, 'neutral')} ${encBadge} ${badge('Confidence: ' + r.confidence, 'neutral')}</div>
    <dl class="kv">
      <dt>Size</dt><dd>${r.size.toLocaleString()} bytes</dd>
      <dt>Entropy</dt><dd>${r.entropy.toFixed(3)} bits/byte</dd>
      <dt>SHA-256</dt><dd class="mono">${r.sha256 || 'n/a'}</dd>
      ${detailHtml}
    </dl>
    <div class="notes">${r.notes.join(' ')}</div>
  `;
}

function verifiableFormatApplicable() {
  return !!state.pdfInfo || (!!state.zipAnalysis && state.zipAnalysis.applicable) || !!state.officeInfo;
}

function updateActionPanelsVisibility() {
  const applicable = verifiableFormatApplicable();
  el('panel-verify').classList.toggle('hidden', !applicable);
  el('panel-search').classList.toggle('hidden', !applicable);
  el('verify-result').innerHTML = '';
  el('search-result').innerHTML = '';
  state.calibratedRate = null;
  el('search-estimate').textContent = '';
  if (applicable) calibrateCurrentFile(); // async; updates search-estimate when done
}

/* ---------- Known-password verification ---------- */

function setupVerifyPanel() {
  el('clearVerifyBtn').addEventListener('click', clearVerifyPanel);
  el('verifyBtn').addEventListener('click', async () => {
    const pw = el('verifyPassword').value;
    el('verifyBtn').disabled = true;
    try {
      let result;
      if (state.pdfInfo) result = await verifyPdfPassword(state.file.bytes, pw);
      else if (state.officeInfo) result = await verifyOfficePassword(state.file.bytes, pw);
      else result = await verifyZipPassword(state.file.bytes, pw);
      renderVerifyResult(result, pw);
      addHistory({ action: 'verify', fileName: state.file.name, detail: `password attempt (len ${pw.length})`, result: result.valid ? 'valid' : 'invalid' });
    } finally {
      el('verifyBtn').disabled = false;
    }
  });
}

function renderVerifyResult(result, pw) {
  const box = el('verify-result');
  if (result.valid) {
    box.innerHTML = `<div class="result-box ok">✓ Password is <strong>correct</strong>${result.matchedAs ? ` (matched as ${result.matchedAs} password)` : ''}.</div>`;
  } else {
    box.innerHTML = `<div class="result-box bad">✗ Password is incorrect.</div>`;
  }
}

/* ---------- Candidate search (dictionary / mask) ---------- */

// These are sanity ceilings only - preventing a textarea paste or mask typo from trying to
// hold billions of candidates in memory - not a judgment about how long a search "should"
// take. How long it *will* take is shown live via estimateRate() below instead, because a
// single flat number can't mean the same thing across formats that differ by 1000x in speed
// (compare PDF/ZIP's thousands/candidates/sec to Office's mandatory-slow ~2-3/sec).
const ABSOLUTE_MAX_MASK_KEYSPACE = 2_000_000_000;
const ABSOLUTE_MAX_DICT_SIZE = 5_000_000;

const CONFIRM_THRESHOLD_SECONDS = 120; // beyond this, ask before committing to a long search

function formatDuration(seconds) {
  if (!isFinite(seconds) || seconds < 0) return 'unknown';
  if (seconds < 1) return '<1 second';
  if (seconds < 60) return `${Math.ceil(seconds)} second${seconds >= 2 ? 's' : ''}`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(1)} minute${minutes >= 2 ? 's' : ''}`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)} hour${hours >= 2 ? 's' : ''}`;
  const days = hours / 24;
  if (days < 365) return `${days.toFixed(1)} day${days >= 2 ? 's' : ''}`;
  return `${(days / 365).toFixed(1)} years`;
}

/** Measures real single-worker throughput for the currently loaded file + format, by timing
 * a handful of dummy candidate checks through the exact same code path a search worker uses
 * (testCandidate, from worker-pool.js). Cheap for PDF/ZIP (sub-millisecond each); for Office
 * this costs a couple of seconds up front (5 candidates x ~400ms), which is fine since it's
 * only measured once per loaded file, not once per search attempt. */
async function estimateRate(format, payload, sampleSize = 5) {
  const start = performance.now();
  for (let i = 0; i < sampleSize; i++) await testCandidate(format, 'calibration-probe-' + i, payload);
  const elapsed = (performance.now() - start) / 1000;
  return sampleSize / elapsed;
}

async function calibrateCurrentFile() {
  if (!verifiableFormatApplicable()) { state.calibratedRate = null; return; }
  const { format, payload } = buildSearchPayload();
  el('search-estimate').textContent = 'Measuring throughput for this file…';
  state.calibratedRate = await estimateRate(format, payload);
  state.calibratedFormat = format;
  updateSearchEstimate();
}

function currentTotalCandidates() {
  const mode = el('searchMode').value;
  if (mode === 'dict') {
    return el('dictInput').value.split('\n').map(s => s.trim()).filter(Boolean).length;
  }
  const charset = el('maskCharset').value;
  const length = parseInt(el('maskLength').value, 10);
  if (!charset || !length || length < 1) return 0;
  return maskKeyspaceSize(charset.length, length);
}

function updateSearchEstimate() {
  const box = el('search-estimate');
  if (state.calibratedRate == null) { box.textContent = ''; return; }
  const total = currentTotalCandidates();
  const numWorkers = parseInt(el('numWorkers').value, 10) || 1;
  const aggregateRate = state.calibratedRate * numWorkers;
  const seconds = total / aggregateRate;
  box.textContent = `Measured ~${state.calibratedRate.toFixed(state.calibratedRate < 10 ? 1 : 0)} candidates/sec/worker for this file. `
    + `${total.toLocaleString()} candidates across ${numWorkers} worker${numWorkers > 1 ? 's' : ''} -> estimated time: ${formatDuration(seconds)}.`;
}

function updateWorkersNote() {
  const cores = navigator.hardwareConcurrency || null;
  const workers = parseInt(el('numWorkers').value, 10);
  const note = el('numWorkersNote');
  if (!cores) { note.textContent = ''; return; }
  note.textContent = workers > cores
    ? `Your machine reports ${cores} logical cores - more than ${cores} workers likely won't go faster (and may go slightly slower from contention).`
    : `Your machine reports ${cores} logical cores.`;
}

function setupSearchPanel() {
  el('clearSearchBtn').addEventListener('click', () => {
    if (state.activeSearch) state.activeSearch.cancel();
    clearSearchPanel();
  });
  el('searchMode').addEventListener('change', () => {
    const mode = el('searchMode').value;
    el('dict-fields').classList.toggle('hidden', mode !== 'dict');
    el('mask-fields').classList.toggle('hidden', mode !== 'mask');
    updateSearchEstimate();
  });
  el('searchStartBtn').addEventListener('click', startSearch);
  el('searchCancelBtn').addEventListener('click', () => {
    if (state.activeSearch) state.activeSearch.cancel();
  });
  const cores = navigator.hardwareConcurrency || 4;
  el('numWorkers').max = Math.max(16, cores);
  el('numWorkers').value = cores;
  el('numWorkersLabel').textContent = el('numWorkers').value;
  updateWorkersNote();
  el('numWorkers').addEventListener('input', () => {
    el('numWorkersLabel').textContent = el('numWorkers').value;
    updateWorkersNote();
    updateSearchEstimate();
  });
  el('dictInput').addEventListener('input', updateSearchEstimate);
  el('maskCharset').addEventListener('input', updateSearchEstimate);
  el('maskLength').addEventListener('input', updateSearchEstimate);
}

function buildSearchPayload() {
  if (state.pdfInfo) return { format: 'pdf', payload: state.pdfInfo };
  if (state.officeInfo) return { format: 'office', payload: state.officeInfo };
  const analysis = state.zipAnalysis;
  const data = readLocalFileData(state.file.bytes, analysis.target);
  return { format: 'zip', payload: { target: analysis.target, data, aesInfo: analysis.aesInfo } };
}

async function startSearch() {
  const mode = el('searchMode').value;
  const numWorkers = parseInt(el('numWorkers').value, 10);
  const { format, payload } = buildSearchPayload();
  const opts = { format, payload, mode, numWorkers, onProgress: updateSearchProgress };

  let total;
  if (mode === 'dict') {
    const lines = el('dictInput').value.split('\n').map(s => s.trim()).filter(Boolean);
    if (lines.length === 0) { alert('Enter at least one candidate password.'); return; }
    if (lines.length > ABSOLUTE_MAX_DICT_SIZE) { alert(`Dictionary too large (max ${ABSOLUTE_MAX_DICT_SIZE.toLocaleString()} entries - a safety ceiling against pasting something enormous, not a speed judgment).`); return; }
    opts.dict = lines;
    total = lines.length;
  } else {
    const charset = el('maskCharset').value;
    const length = parseInt(el('maskLength').value, 10);
    if (!charset || !length || length < 1) { alert('Provide a charset and a length of at least 1.'); return; }
    const keyspace = Math.pow(charset.length, length);
    if (keyspace > ABSOLUTE_MAX_MASK_KEYSPACE) {
      alert(`Keyspace of ${keyspace.toLocaleString()} candidates exceeds the ${ABSOLUTE_MAX_MASK_KEYSPACE.toLocaleString()} safety ceiling. Narrow the charset or length.`);
      return;
    }
    opts.charset = charset; opts.length = length;
    total = keyspace;
  }

  if (state.calibratedRate != null) {
    const aggregateRate = state.calibratedRate * numWorkers;
    const estimatedSeconds = total / aggregateRate;
    if (estimatedSeconds > CONFIRM_THRESHOLD_SECONDS) {
      const proceed = confirm(
        `At the measured rate for this file (~${state.calibratedRate.toFixed(1)} candidates/sec/worker), ` +
        `testing all ${total.toLocaleString()} candidates with ${numWorkers} worker${numWorkers > 1 ? 's' : ''} ` +
        `will take approximately ${formatDuration(estimatedSeconds)}.\n\nStart anyway?`
      );
      if (!proceed) return;
    }
  }

  searchState = { total, startTime: performance.now() };
  el('searchStartBtn').disabled = true;
  el('searchCancelBtn').disabled = false;
  el('search-result').innerHTML = '';
  el('searchProgressWrap').classList.remove('hidden');
  updateSearchProgress(0);

  const { promise, cancel } = runPasswordSearch(opts);
  state.activeSearch = { cancel };
  const result = await promise;
  state.activeSearch = null;
  el('searchStartBtn').disabled = false;
  el('searchCancelBtn').disabled = true;
  renderSearchResult(result, total);
  addHistory({
    action: 'search', fileName: state.file.name,
    detail: `${mode} search, ${numWorkers} workers, ${result.tested.toLocaleString()} tested in ${(result.elapsedMs / 1000).toFixed(1)}s`,
    result: result.found ? `found: "${result.password}"` : (result.cancelled ? 'cancelled' : 'exhausted - not found')
  });
}

let searchState = null;

function updateSearchProgress(tested) {
  if (!searchState) return;
  const pct = searchState.total ? Math.min(100, (tested / searchState.total) * 100) : 0;
  el('progress-fill').style.width = pct.toFixed(2) + '%';
  const elapsed = (performance.now() - searchState.startTime) / 1000;
  const rate = elapsed > 0 ? tested / elapsed : 0;
  el('progress-stats').textContent = `${tested.toLocaleString()} / ${searchState.total.toLocaleString()} tested — ${rate.toFixed(0)}/s — ${elapsed.toFixed(1)}s elapsed`;
}

function renderSearchResult(result, total) {
  const box = el('search-result');
  if (result.found) {
    box.innerHTML = `<div class="result-box ok">✓ Password found: <strong class="mono">${escapeHtml(result.password)}</strong> (${result.tested.toLocaleString()} candidates tested in ${(result.elapsedMs / 1000).toFixed(1)}s)</div>`;
  } else if (result.cancelled) {
    box.innerHTML = `<div class="result-box bad">Search cancelled after ${result.tested.toLocaleString()} candidates.</div>`;
  } else {
    box.innerHTML = `<div class="result-box bad">No match found across all ${total.toLocaleString()} candidates.</div>`;
  }
}

function escapeHtml(s) { return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

/* ---------- Diagnostics ---------- */

function setupDiagnostics() {
  el('gpuCheckBtn').addEventListener('click', async () => {
    el('gpuResult').textContent = 'Checking…';
    const r = await detectWebGpu();
    el('gpuResult').innerHTML = r.available
      ? `<span class="badge ok">WebGPU available</span> vendor: ${r.vendor}, arch: ${r.architecture}<div class="notes">${r.note}</div>`
      : `<span class="badge neutral">WebGPU unavailable</span><div class="notes">${r.reason}</div>`;
  });

  el('benchBtn').addEventListener('click', async () => {
    const maxWorkers = Math.min(8, navigator.hardwareConcurrency || 4);
    el('benchResult').textContent = 'Running scaling benchmark…';
    const rows = await runCpuScalingBenchmark(maxWorkers, 300, (n, max) => {
      el('benchResult').textContent = `Benchmarking… ${n}/${max} worker configurations tested`;
    });
    el('benchResult').innerHTML = `
      <table><thead><tr><th>Workers</th><th>Hashes/sec</th><th>Scaling vs. 1 worker</th></tr></thead>
      <tbody>${rows.map(r => `<tr><td>${r.workers}</td><td>${r.hashesPerSec.toFixed(0)}</td><td>${(r.hashesPerSec / rows[0].hashesPerSec).toFixed(2)}x</td></tr>`).join('')}</tbody></table>`;
  });

  el('diag-cores').textContent = navigator.hardwareConcurrency || 'unknown';
}

/* ---------- Test file generator ---------- */

function downloadBytes(bytes, filename) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Static files committed under samples/ - generated once with these tools, so the hosted
// (GitHub Pages) site can demonstrate RAR/7z/Office/GPG detection without anyone needing to
// install anything. Loaded from the base64 copies in js/samples-data.js (SAMPLE_DATA_B64),
// which works identically over http(s) and file:// - no fetch() of a sibling file needed,
// so this works on a double-clicked index.html too, with no local server required. See
// local-service/embed-samples.js for how that file is (re)generated from samples/*.
const SAMPLE_FILES = {
  pdf: { path: 'samples/sample.pdf', password: 'test1234' },
  zip: { path: 'samples/sample.zip', password: 'test1234' },
  rar: { path: 'samples/sample.rar', password: 'test1234' },
  '7z': { path: 'samples/sample.7z', password: 'test1234' },
  docx: { path: 'samples/sample-office.docx', password: 'test1234' },
  xlsx: { path: 'samples/sample-office.xlsx', password: 'test1234' },
  pptx: { path: 'samples/sample-office.pptx', password: 'test1234' },
  gpg: { path: 'samples/sample.gpg', password: 'test1234' },
};

function setupGenerator() {
  const pwField = el('genPassword');
  const formatSelect = el('genFormat');

  const updateFormatPanels = () => {
    const [kind, sub] = formatSelect.value.split(':');
    const sampleNote = el('genSampleNote');
    sampleNote.classList.toggle('hidden', kind !== 'sample');
    if (kind === 'sample') {
      sampleNote.textContent = `Pre-generated sample — fixed known password: "${SAMPLE_FILES[sub].password}" (the password field above doesn't apply to these).`;
    }
  };
  formatSelect.addEventListener('change', updateFormatPanels);
  updateFormatPanels();

  el('genBtn').addEventListener('click', async () => {
    const [kind, sub] = formatSelect.value.split(':');
    const pw = pwField.value || 'test1234';
    if (kind === 'pdf') {
      const bytes = await generateEncryptedPdf(sub, pw, pw);
      downloadBytes(bytes, `test-${sub}.pdf`);
      await loadGeneratedIntoAnalyzer(bytes, `test-${sub}.pdf`, pw);
    } else if (kind === 'zip') {
      if (sub === 'zipcrypto') {
        const bytes = await generateZipCryptoZip(pw);
        downloadBytes(bytes, 'test-zipcrypto.zip');
        await loadGeneratedIntoAnalyzer(bytes, 'test-zipcrypto.zip', pw);
      } else {
        const bits = sub === 'aes-128' ? 128 : 256;
        const bytes = await generateWinZipAesZip(pw, bits);
        downloadBytes(bytes, `test-winzip-aes${bits}.zip`);
        await loadGeneratedIntoAnalyzer(bytes, `test-winzip-aes${bits}.zip`, pw);
      }
    } else if (kind === 'sample') {
      const { path: samplePath, password } = SAMPLE_FILES[sub];
      try {
        // Embedded base64 (works over file:// too) is tried first; fetch() is only a
        // fallback for a deployment that strips js/samples-data.js and relies on the
        // committed samples/ files being served alongside it instead.
        let bytes;
        if (typeof SAMPLE_DATA_B64 !== 'undefined' && SAMPLE_DATA_B64[sub]) {
          bytes = base64ToBytes(SAMPLE_DATA_B64[sub]);
        } else {
          const res = await fetch(samplePath);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          bytes = new Uint8Array(await res.arrayBuffer());
        }
        await loadGeneratedIntoAnalyzer(bytes, samplePath.split('/').pop(), password);
      } catch (e) {
        el('search-result').innerHTML = '';
        el('identify-body').innerHTML = `<div class="result-box bad">Could not load the pre-generated sample (${e.message}).
          Download the file from the samples/ folder instead and drop it into the loader above.</div>`;
        el('panel-identify').classList.remove('hidden');
      }
    }
  });
}

async function loadGeneratedIntoAnalyzer(bytes, name, knownPassword) {
  state.file = { name, size: bytes.length, bytes };
  el('dropzone').textContent = `Loaded generated file: ${name} (${bytes.length.toLocaleString()} bytes)`;
  el('clearFileBtn').disabled = false;
  const result = await identifyFile(bytes);
  state.identification = result;
  renderIdentification(result);
  applyVerifiableState(bytes, result);
  updateActionPanelsVisibility();
  el('verifyPassword').value = knownPassword;
  addHistory({ action: 'generate', fileName: name, detail: `known password: "${knownPassword}"`, result: 'generated' });
}

/* ---------- Job history + export ---------- */

function renderHistory() {
  const tbody = el('historyBody');
  tbody.innerHTML = state.history.map(h => `
    <tr>
      <td>${h.time}</td>
      <td>${escapeHtml(h.fileName)}</td>
      <td>${h.action}</td>
      <td>${escapeHtml(h.detail || '')}</td>
      <td>${escapeHtml(h.result || '')}</td>
    </tr>`).join('');
}

function setupHistoryExport() {
  el('clearHistoryBtn').addEventListener('click', () => {
    if (state.history.length === 0) return;
    if (confirm(`Clear all ${state.history.length} job history entries? This cannot be undone.`)) {
      state.history = [];
      renderHistory();
    }
  });
  el('exportJsonBtn').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(state.history, null, 2)], { type: 'application/json' });
    triggerDownload(blob, 'job-history.json');
  });
  el('exportCsvBtn').addEventListener('click', () => {
    const header = 'time,fileName,action,detail,result\n';
    const rows = state.history.map(h => [h.time, h.fileName, h.action, h.detail, h.result]
      .map(v => `"${String(v || '').replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    triggerDownload(blob, 'job-history.csv');
  });
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ---------- Boot ---------- */

window.addEventListener('DOMContentLoaded', () => {
  setupDropzone();
  setupVerifyPanel();
  setupSearchPanel();
  setupDiagnostics();
  setupGenerator();
  setupHistoryExport();
  tryEnableMd5Wasm(); // fire-and-forget; falls back silently to pure JS if unavailable
  tryEnableRc4Wasm();
});
