/* Self-contained Web Worker pool for password verification. The worker script is built at
   runtime from a Blob URL containing the *actual* source of the shared crypto functions
   (via Function.prototype.toString), so there is a single source of truth and no separate
   worker file to fetch - this is what lets the app run from a plain double-clicked
   index.html with no server and no bundler.
   Depends on (main thread globals): strToBytes, concatBytes, CRC32_TABLE, crc32, crc32Final,
   PDF_PAD, MD5_S, MD5_K, MD5_BLOCK, MD5_M, md5Rotl, md5CompressBlock, md5ToOutput, md5,
   rc4, sha1, AES_SBOX, AES_INV_SBOX, AES_RCON, aesGmul, aesKeyExpansion,
   aesAddRoundKey, aesInvSubBytes, aesInvShiftRows, aesInvMixColumns, aesDecryptBlock,
   aesEcbDecrypt,
   computeKeyR234, pdfPadPassword, checkUserPasswordR234, checkOwnerPasswordR234, bytesEqual,
   sha, hash2B, checkUserPasswordR56, checkOwnerPasswordR56, zipCryptoInitKeys,
   zipCryptoDecryptBytes, checkZipCryptoPassword, deriveAesKeyMaterial, checkWinZipAesPassword,
   officeUtf16LeBytes, officeU32leBytes, officeXorRepeating, officeDeriveStandardKey,
   officeCheckStandardPassword, MD5_WASM_BASE64, md5WasmBase64ToBytes, tryEnableMd5Wasm,
   RC4_WASM_BASE64, rc4WasmBase64ToBytes, tryEnableRc4Wasm,
   sha256, sha384, sha512, aesCbcDecrypt, officeAgileHash, officeAgileFixKeyLength,
   officeAgileZeroPad, officeAgileDeriveKey, officeCheckAgilePassword. */

// Captured at script-load time, before app.js's later tryEnableMd5Wasm()/tryEnableRc4Wasm()
// calls can monkey-patch the live `md5`/`rc4` bindings to their WASM-backed replacements.
// Function.prototype.toString() always returns a function's original source (including its
// original name) regardless of which variable currently points to it, so bundling from these
// frozen references - rather than from `md5`/`rc4` themselves, which may by then point to
// anonymous wrappers - guarantees the worker always gets the real, named, pure-JS
// implementations to initialize its own WASM upgrades from.
const ORIGINAL_MD5_FOR_BUNDLE = md5;
const ORIGINAL_RC4_FOR_BUNDLE = rc4;

/* Per-candidate test functions: real top-level functions (not just template-string text) so
 * the main thread can call them too, for live throughput calibration (see estimateRate in
 * app.js) - the calibration then measures exactly what a search worker would actually do. */

function indexToCandidate(index, charset, length) {
  const chars = new Array(length);
  for (let i = length - 1; i >= 0; i--) {
    chars[i] = charset[index % charset.length];
    index = Math.floor(index / charset.length);
  }
  return chars.join('');
}

async function testPdfCandidate(passwordStr, info) {
  const passwordBytes = strToBytes(passwordStr);
  if (info.R >= 5) {
    let ok = await checkUserPasswordR56(passwordBytes, info);
    if (!ok) ok = await checkOwnerPasswordR56(passwordBytes, info);
    return ok;
  }
  let ok = checkUserPasswordR234(passwordBytes, info);
  if (!ok) ok = checkOwnerPasswordR234(passwordBytes, info);
  return ok;
}

async function testZipCandidate(passwordStr, zipPayload) {
  const passwordBytes = strToBytes(passwordStr);
  if (zipPayload.aesInfo) {
    const result = await checkWinZipAesPassword(passwordBytes, zipPayload.target, zipPayload.data, zipPayload.aesInfo);
    return result.valid;
  }
  return checkZipCryptoPassword(passwordBytes, zipPayload.target, zipPayload.data);
}

function testOfficeCandidate(passwordStr, officeInfo) {
  // Deliberately synchronous and slow: both schemes run a mandatory, sequential KDF per
  // candidate by design (ECMA-376 Standard's 50,000-round SHA-1 loop, or Agile's own
  // spinCount - typically 100,000 - run *twice*, once per verifier block key, over
  // SHA-256/384/512) - that's each scheme's own brute-force resistance, not something to
  // optimize away.
  if (officeInfo.scheme === 'agile') return officeCheckAgilePassword(passwordStr, officeInfo);
  return officeCheckStandardPassword(passwordStr, officeInfo);
}

async function testCandidate(format, candidate, payload) {
  if (format === 'pdf') return testPdfCandidate(candidate, payload);
  if (format === 'office') return testOfficeCandidate(candidate, payload);
  return testZipCandidate(candidate, payload);
}

function buildWorkerSource() {
  const fns = [
    strToBytes, concatBytes, aesCbcNoPadEncrypt, crc32, crc32Final, ORIGINAL_RC4_FOR_BUNDLE, sha1,
    md5Rotl, md5CompressBlock, md5ToOutput, ORIGINAL_MD5_FOR_BUNDLE,
    aesGmul, aesKeyExpansion, aesAddRoundKey, aesInvSubBytes, aesInvShiftRows, aesInvMixColumns,
    aesDecryptBlock, aesEcbDecrypt,
    computeKeyR234, pdfPadPassword, checkUserPasswordR234, checkOwnerPasswordR234, bytesEqual,
    sha, hash2B, checkUserPasswordR56, checkOwnerPasswordR56,
    zipCryptoInitKeys, zipCryptoDecryptBytes, checkZipCryptoPassword,
    deriveAesKeyMaterial, checkWinZipAesPassword,
    officeUtf16LeBytes, officeU32leBytes, officeXorRepeating, officeDeriveStandardKey,
    officeCheckStandardPassword,
    sha256Rotr, sha256, sha512Core, sha512, sha384,
    aesCbcDecrypt, officeAgileHash, officeAgileFixKeyLength, officeAgileZeroPad,
    officeAgileDeriveKey, officeCheckAgilePassword,
    indexToCandidate, testPdfCandidate, testZipCandidate, testOfficeCandidate, testCandidate,
    md5WasmBase64ToBytes, tryEnableMd5Wasm, rc4WasmBase64ToBytes, tryEnableRc4Wasm
  ].map(f => f.toString()).join('\n\n');

  const constants = `
const CRC32_TABLE = Uint32Array.from(${JSON.stringify(Array.from(CRC32_TABLE))});
const PDF_PAD = Uint8Array.from(${JSON.stringify(Array.from(PDF_PAD))});
const MD5_S = ${JSON.stringify(MD5_S)};
const MD5_K = Int32Array.from(${JSON.stringify(Array.from(MD5_K))});
const MD5_BLOCK = new Uint8Array(64);
const MD5_M = new Int32Array(16);
const MD5_WASM_BASE64 = ${JSON.stringify(MD5_WASM_BASE64)};
const RC4_WASM_BASE64 = ${JSON.stringify(RC4_WASM_BASE64)};
const AES_SBOX = Uint8Array.from(${JSON.stringify(Array.from(AES_SBOX))});
const AES_INV_SBOX = Uint8Array.from(${JSON.stringify(Array.from(AES_INV_SBOX))});
const AES_RCON = Uint8Array.from(${JSON.stringify(Array.from(AES_RCON))});
const SHA256_K = Uint32Array.from(${JSON.stringify(Array.from(SHA256_K))});
const SHA512_K = ${JSON.stringify(SHA512_K)};
const OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_INPUT = Uint8Array.from(${JSON.stringify(Array.from(OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_INPUT))});
const OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_VALUE = Uint8Array.from(${JSON.stringify(Array.from(OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_VALUE))});
`;

  const workerMain = `
let cancelled = false;
// Started immediately; awaited before the first real message, so every candidate check in
// this worker's lifetime uses whichever (WASM or JS fallback) ends up active.
const wasmInit = Promise.all([tryEnableMd5Wasm(), tryEnableRc4Wasm()]);

self.onmessage = async function(ev) {
  const msg = ev.data;
  if (msg.type === 'cancel') { cancelled = true; return; }
  await wasmInit;

  if (msg.type === 'bench') {
    cancelled = false;
    try {
      const start = performance.now();
      let count = 0;
      const probe = strToBytes('benchmark-probe-password');
      while (performance.now() - start < msg.durationMs) { md5(probe); count++; }
      self.postMessage({ type: 'benchResult', id: msg.id, count });
    } catch (err) {
      // Without this, a bug in the hot path hangs the caller's promise forever instead of
      // surfacing a clear error - cost real debugging time once already (a missing bundled
      // helper threw a ReferenceError here with nothing watching for it).
      self.postMessage({ type: 'benchError', id: msg.id, message: String(err && err.message || err) });
    }
    return;
  }

  if (msg.type === 'search') {
    cancelled = false;
    const { chunkId, format, payload, mode } = msg;
    let tested = 0;
    const REPORT_EVERY = format === 'office' ? 1 : 200; // office is ~2-3/sec/worker (50,000-round KDF); report every candidate
    try {
      if (mode === 'dict') {
        for (const candidate of msg.candidates) {
          if (cancelled) break;
          const ok = await testCandidate(format, candidate, payload);
          tested++;
          if (ok) { self.postMessage({ type: 'found', chunkId, password: candidate, tested }); return; }
          if (tested % REPORT_EVERY === 0) self.postMessage({ type: 'progress', chunkId, tested });
        }
      } else { // mask mode
        for (let idx = msg.start; idx < msg.end; idx++) {
          if (cancelled) break;
          const candidate = indexToCandidate(idx, msg.charset, msg.length);
          const ok = await testCandidate(format, candidate, payload);
          tested++;
          if (ok) { self.postMessage({ type: 'found', chunkId, password: candidate, tested }); return; }
          if (tested % REPORT_EVERY === 0) self.postMessage({ type: 'progress', chunkId, tested });
        }
      }
      self.postMessage({ type: 'done', chunkId, tested });
    } catch (err) {
      self.postMessage({ type: 'error', chunkId, message: String(err && err.message || err) });
    }
  }
};
`;

  return constants + '\n' + fns + '\n' + workerMain;
}

let cachedWorkerUrl = null;
function getWorkerUrl() {
  if (cachedWorkerUrl) return cachedWorkerUrl;
  const blob = new Blob([buildWorkerSource()], { type: 'application/javascript' });
  cachedWorkerUrl = URL.createObjectURL(blob);
  return cachedWorkerUrl;
}

function createWorkerPool(n) {
  const url = getWorkerUrl();
  const workers = [];
  for (let i = 0; i < n; i++) workers.push(new Worker(url));
  return {
    workers,
    terminate() { for (const w of workers) w.terminate(); }
  };
}

/* ---------- Candidate space helpers ---------- */

function maskKeyspaceSize(charsetLen, length) { return Math.pow(charsetLen, length); }

function splitRange(total, n) {
  const ranges = [];
  const base = Math.floor(total / n);
  let start = 0;
  for (let i = 0; i < n; i++) {
    const extra = i < (total % n) ? 1 : 0;
    const size = base + extra;
    ranges.push([start, start + size]);
    start += size;
  }
  return ranges;
}

function splitList(list, n) {
  const chunks = Array.from({ length: n }, () => []);
  for (let i = 0; i < list.length; i++) chunks[i % n].push(list[i]);
  return chunks;
}

/**
 * Starts a finite password search (dictionary list, or a bounded charset^length mask) across
 * a worker pool. Returns { promise, cancel }; promise resolves to
 * { found: bool, password?, cancelled?, tested, elapsedMs }.
 */
function runPasswordSearch({ format, payload, mode, dict, charset, length, numWorkers, onProgress }) {
  let cancelFn = () => {};
  const promise = new Promise((resolve) => {
    const n = Math.max(1, numWorkers | 0);
    const pool = createWorkerPool(n);
    const start = performance.now();
    let totalTested = 0;
    let finished = 0;
    let settled = false;
    const perChunkTested = new Array(n).fill(0);

    function finishAll(result) {
      if (settled) return;
      settled = true;
      for (const w of pool.workers) w.postMessage({ type: 'cancel' });
      setTimeout(() => pool.terminate(), 50);
      resolve({ ...result, tested: totalTested, elapsedMs: performance.now() - start });
    }
    cancelFn = () => finishAll({ found: false, cancelled: true });

    pool.workers.forEach((w, chunkId) => {
      w.onmessage = (ev) => {
        const msg = ev.data;
        if (msg.type === 'progress' || msg.type === 'done' || msg.type === 'found') {
          totalTested += (msg.tested - perChunkTested[chunkId]);
          perChunkTested[chunkId] = msg.tested;
          if (onProgress) onProgress(totalTested);
        }
        if (msg.type === 'found') finishAll({ found: true, password: msg.password });
        else if (msg.type === 'error') { finished++; if (finished === n) finishAll({ found: false, error: msg.message }); }
        else if (msg.type === 'done') { finished++; if (finished === n) finishAll({ found: false }); }
      };
    });

    if (mode === 'dict') {
      const chunks = splitList(dict, n);
      pool.workers.forEach((w, i) => w.postMessage({ type: 'search', chunkId: i, format, payload, mode: 'dict', candidates: chunks[i] }));
    } else {
      const total = maskKeyspaceSize(charset.length, length);
      const ranges = splitRange(total, n);
      pool.workers.forEach((w, i) => w.postMessage({ type: 'search', chunkId: i, format, payload, mode: 'mask', charset, length, start: ranges[i][0], end: ranges[i][1] }));
    }
  });
  return { promise, cancel: () => cancelFn() };
}

if (typeof module !== 'undefined') module.exports = { buildWorkerSource, createWorkerPool, runPasswordSearch, maskKeyspaceSize, splitRange, splitList };
