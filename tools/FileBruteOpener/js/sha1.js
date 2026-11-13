/* Minimal, dependency-free, synchronous SHA-1 (Uint8Array -> Uint8Array(20)). The Web Crypto
 * API's crypto.subtle.digest is async, and the ECMA-376 "Standard" Office encryption key
 * derivation calls for exactly 50,000 sequential SHA-1 iterations per password candidate -
 * 50,000 awaited crypto.subtle calls per candidate makes multi-candidate search impractically
 * slow (promise/microtask overhead dominates), so this runs synchronously in a tight loop. */

function sha1(bytes) {
  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

  const msgLenBits = bytes.length * 8;
  const withOne = concatBytes(bytes, Uint8Array.from([0x80]));
  const padLen = (56 - (withOne.length % 64) + 64) % 64;
  const padded = concatBytes(withOne, new Uint8Array(padLen), new Uint8Array(8));
  const dv = new DataView(padded.buffer, padded.byteOffset + padded.length - 8, 8);
  dv.setUint32(0, Math.floor(msgLenBits / 0x100000000), false);
  dv.setUint32(4, msgLenBits >>> 0, false);

  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    const w = new Uint32Array(80);
    for (let j = 0; j < 16; j++) {
      w[j] = (padded[chunk+j*4] << 24) | (padded[chunk+j*4+1] << 16) | (padded[chunk+j*4+2] << 8) | padded[chunk+j*4+3];
    }
    for (let j = 16; j < 80; j++) w[j] = rotl(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);

    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let j = 0; j < 80; j++) {
      let f, k;
      if (j < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (j < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      const temp = (rotl(a, 5) + f + e + k + w[j]) >>> 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, h0, false); outDv.setUint32(4, h1, false); outDv.setUint32(8, h2, false);
  outDv.setUint32(12, h3, false); outDv.setUint32(16, h4, false);
  return out;
}

if (typeof module !== 'undefined') module.exports = { sha1 };
