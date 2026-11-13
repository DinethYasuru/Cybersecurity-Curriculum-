/* Minimal, dependency-free MD5 implementation operating on Uint8Array -> Uint8Array(16).
   Needed because the PDF Standard Security Handler (R2-R4) key derivation is defined
   in terms of MD5, which the Web Crypto API does not provide.

   Performance note: PDF R3/R4 key derivation calls this 50+ times per password candidate
   (the mandatory iterated-hash step), almost always on inputs well under 55 bytes - that
   loop is the actual CPU bottleneck for a PDF/ZIP mask search. The constants below are
   module-level (not re-built on every call, as a naive version would), and short inputs
   take a direct single-block path with no concatBytes allocation chain. */

function md5Rotl(x, c) { return (x << c) | (x >>> (32 - c)); }

const MD5_S = [
  7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
  5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
  4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
  6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
];
const MD5_K = new Int32Array([
  -680876936,-389564586,606105819,-1044525330,-176418897,1200080426,-1473231341,-45705983,
  1770035416,-1958414417,-42063,-1990404162,1804603682,-40341101,-1502002290,1236535329,
  -165796510,-1069501632,643717713,-373897302,-701558691,38016083,-660478335,-405537848,
  568446438,-1019803690,-187363961,1163531501,-1444681467,-51403784,1735328473,-1926607734,
  -378558,-2022574463,1839030562,-35309556,-1530992060,1272893353,-155497632,-1094730640,
  681279174,-358537222,-722521979,76029189,-640364487,-421815835,530742520,-995338651,
  -198630844,1126891415,-1416354905,-57434055,1700485571,-1894986606,-1051523,-2054922799,
  1873313359,-30611744,-1560198380,1309151649,-145523070,-1120210379,718787259,-343485551
]);

// Reused scratch buffer for the common (<=55 byte) single-block case. Safe to share across
// calls because everything here runs synchronously, single-threaded, within one worker.
const MD5_BLOCK = new Uint8Array(64);
const MD5_M = new Int32Array(16);

function md5CompressBlock(block, a0, b0, c0, d0) {
  for (let j = 0; j < 16; j++) {
    MD5_M[j] = block[j*4] | (block[j*4+1] << 8) | (block[j*4+2] << 16) | (block[j*4+3] << 24);
  }
  let A = a0, B = b0, C = c0, D = d0;
  for (let i = 0; i < 64; i++) {
    let F, g;
    if (i < 16) { F = (B & C) | (~B & D); g = i; }
    else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) % 16; }
    else if (i < 48) { F = B ^ C ^ D; g = (3*i + 5) % 16; }
    else { F = C ^ (B | ~D); g = (7*i) % 16; }
    F = (F + A + MD5_K[i] + MD5_M[g]) | 0;
    A = D; D = C; C = B;
    B = (B + md5Rotl(F, MD5_S[i])) | 0;
  }
  return [(a0 + A) | 0, (b0 + B) | 0, (c0 + C) | 0, (d0 + D) | 0];
}

function md5ToOutput(a0, b0, c0, d0) {
  const out = new Uint8Array(16);
  const dv = new DataView(out.buffer);
  dv.setInt32(0, a0, true); dv.setInt32(4, b0, true);
  dv.setInt32(8, c0, true); dv.setInt32(12, d0, true);
  return out;
}

function md5(bytes) {
  const len = bytes.length;

  if (len <= 55) {
    MD5_BLOCK.fill(0);
    MD5_BLOCK.set(bytes);
    MD5_BLOCK[len] = 0x80;
    const bits = len * 8;
    const dv = new DataView(MD5_BLOCK.buffer, 56, 8);
    dv.setUint32(0, bits >>> 0, true);
    dv.setUint32(4, 0, true); // bits/8 never approaches 2^32 for our inputs
    const [a, b, c, d] = md5CompressBlock(MD5_BLOCK, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
    return md5ToOutput(a, b, c, d);
  }

  // General multi-block path (rare in this app's hot loops, but needed for correctness on
  // longer inputs, e.g. PDF's initial Algorithm-2 key-derivation hash).
  const msgLenBits = len * 8;
  const withOne = concatBytes(bytes, Uint8Array.from([0x80]));
  const padLen = (56 - (withOne.length % 64) + 64) % 64;
  const padded = concatBytes(withOne, new Uint8Array(padLen), new Uint8Array(8));
  const dv = new DataView(padded.buffer, padded.byteOffset + padded.length - 8, 8);
  dv.setUint32(0, msgLenBits >>> 0, true);
  dv.setUint32(4, Math.floor(msgLenBits / 0x100000000), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    [a0, b0, c0, d0] = md5CompressBlock(padded.subarray(chunk, chunk + 64), a0, b0, c0, d0);
  }
  return md5ToOutput(a0, b0, c0, d0);
}

if (typeof module !== 'undefined') module.exports = { md5 };
