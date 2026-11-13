/* Shared byte/hex helpers, CRC32, and Shannon entropy. No external deps. */

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function strToBytes(str) {
  // Latin-1 byte mapping; PDF/ZIP passwords are treated as raw byte strings.
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

function concatBytes(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function u32le(bytes, off) {
  return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 0;
}
function u16le(bytes, off) {
  return bytes[off] | (bytes[off + 1] << 8);
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes, crc = 0xFFFFFFFF) {
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  }
  return crc >>> 0;
}
function crc32Final(bytes) {
  return (crc32(bytes) ^ 0xFFFFFFFF) >>> 0;
}

/** Shannon entropy in bits/byte, over at most `sampleSize` bytes. */
function shannonEntropy(bytes, sampleSize = 65536) {
  const n = Math.min(bytes.length, sampleSize);
  if (n === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < n; i++) counts[bytes[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / n;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** AES-CBC encrypt with a zero-length logical padding: Web Crypto always appends a full
 * PKCS7 padding block, so for inputs that are already a multiple of 16 bytes we just drop
 * that extra block. Used wherever a spec calls for "raw" CBC encryption (PDF R6 key
 * wrapping/hardening, WinZip AES-CTR keystream blocks via single-block "ECB"). */
async function aesCbcNoPadEncrypt(keyBytes, ivBytes, plaintextBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  const full = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, plaintextBytes));
  return full.slice(0, plaintextBytes.length);
}

if (typeof module !== 'undefined') {
  module.exports = { bytesToHex, strToBytes, concatBytes, u32le, u16le, crc32, crc32Final, shannonEntropy, CRC32_TABLE, aesCbcNoPadEncrypt };
}
