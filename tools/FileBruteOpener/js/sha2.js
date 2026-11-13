/* Dependency-free, synchronous SHA-256 and SHA-512 (FIPS 180-4). Needed alongside sha1.js
 * because Office's "Agile" encryption key derivation (MS-OFFCRYPTO 2.3.4.7-2.3.4.9) runs a
 * mandatory spinCount-iteration (typically 100,000) hash loop per candidate password, and
 * crypto.subtle.digest() is async - one await per round would be far too slow (same reason
 * sha1.js exists instead of using Web Crypto's SHA-1). hashAlgorithm in a real Agile file is
 * usually "SHA512" (Office's own default) but the spec also allows "SHA1" (sha1.js already
 * covers that) and "SHA256"/"SHA384" - SHA-384 is simply SHA-512 with a different initial
 * hash value and truncated output, included here for completeness. */

/* ---------- SHA-256 ---------- */

const SHA256_K = Uint32Array.from([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function sha256Rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function sha256(message) {
  const h = Uint32Array.from([
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  ]);
  const bitLen = message.length * 8;
  const mod = (message.length + 1) % 64;
  const padLen = (mod <= 56) ? 56 - mod : 120 - mod;
  const padded = new Uint8Array(message.length + 1 + padLen + 8);
  padded.set(message, 0);
  padded[message.length] = 0x80;
  // bitLen as a 64-bit big-endian integer; messages here are always far under 2^32 bits.
  const dv = new DataView(padded.buffer, padded.byteOffset + padded.length - 8, 8);
  dv.setUint32(0, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = (padded[off + i*4] << 24) | (padded[off + i*4+1] << 16) | (padded[off + i*4+2] << 8) | padded[off + i*4+3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = sha256Rotr(w[i-15], 7) ^ sha256Rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = sha256Rotr(w[i-2], 17) ^ sha256Rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = sha256Rotr(e,6) ^ sha256Rotr(e,11) ^ sha256Rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = sha256Rotr(a,2) ^ sha256Rotr(a,13) ^ sha256Rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h[0] = (h[0]+a)>>>0; h[1] = (h[1]+b)>>>0; h[2] = (h[2]+c)>>>0; h[3] = (h[3]+d)>>>0;
    h[4] = (h[4]+e)>>>0; h[5] = (h[5]+f)>>>0; h[6] = (h[6]+g)>>>0; h[7] = (h[7]+hh)>>>0;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i*4] = (h[i] >>> 24) & 0xff; out[i*4+1] = (h[i] >>> 16) & 0xff;
    out[i*4+2] = (h[i] >>> 8) & 0xff; out[i*4+3] = h[i] & 0xff;
  }
  return out;
}

/* ---------- SHA-512 / SHA-384 (shared compression function, 64-bit words as {hi,lo} pairs) ---------- */

// K constants as [hi, lo] 32-bit halves of each 64-bit round constant.
const SHA512_K = [
  [0x428a2f98,0xd728ae22],[0x71374491,0x23ef65cd],[0xb5c0fbcf,0xec4d3b2f],[0xe9b5dba5,0x8189dbbc],
  [0x3956c25b,0xf348b538],[0x59f111f1,0xb605d019],[0x923f82a4,0xaf194f9b],[0xab1c5ed5,0xda6d8118],
  [0xd807aa98,0xa3030242],[0x12835b01,0x45706fbe],[0x243185be,0x4ee4b28c],[0x550c7dc3,0xd5ffb4e2],
  [0x72be5d74,0xf27b896f],[0x80deb1fe,0x3b1696b1],[0x9bdc06a7,0x25c71235],[0xc19bf174,0xcf692694],
  [0xe49b69c1,0x9ef14ad2],[0xefbe4786,0x384f25e3],[0x0fc19dc6,0x8b8cd5b5],[0x240ca1cc,0x77ac9c65],
  [0x2de92c6f,0x592b0275],[0x4a7484aa,0x6ea6e483],[0x5cb0a9dc,0xbd41fbd4],[0x76f988da,0x831153b5],
  [0x983e5152,0xee66dfab],[0xa831c66d,0x2db43210],[0xb00327c8,0x98fb213f],[0xbf597fc7,0xbeef0ee4],
  [0xc6e00bf3,0x3da88fc2],[0xd5a79147,0x930aa725],[0x06ca6351,0xe003826f],[0x14292967,0x0a0e6e70],
  [0x27b70a85,0x46d22ffc],[0x2e1b2138,0x5c26c926],[0x4d2c6dfc,0x5ac42aed],[0x53380d13,0x9d95b3df],
  [0x650a7354,0x8baf63de],[0x766a0abb,0x3c77b2a8],[0x81c2c92e,0x47edaee6],[0x92722c85,0x1482353b],
  [0xa2bfe8a1,0x4cf10364],[0xa81a664b,0xbc423001],[0xc24b8b70,0xd0f89791],[0xc76c51a3,0x0654be30],
  [0xd192e819,0xd6ef5218],[0xd6990624,0x5565a910],[0xf40e3585,0x5771202a],[0x106aa070,0x32bbd1b8],
  [0x19a4c116,0xb8d2d0c8],[0x1e376c08,0x5141ab53],[0x2748774c,0xdf8eeb99],[0x34b0bcb5,0xe19b48a8],
  [0x391c0cb3,0xc5c95a63],[0x4ed8aa4a,0xe3418acb],[0x5b9cca4f,0x7763e373],[0x682e6ff3,0xd6b2b8a3],
  [0x748f82ee,0x5defb2fc],[0x78a5636f,0x43172f60],[0x84c87814,0xa1f0ab72],[0x8cc70208,0x1a6439ec],
  [0x90befffa,0x23631e28],[0xa4506ceb,0xde82bde9],[0xbef9a3f7,0xb2c67915],[0xc67178f2,0xe372532b],
  [0xca273ece,0xea26619c],[0xd186b8c7,0x21c0c207],[0xeada7dd6,0xcde0eb1e],[0xf57d4f7f,0xee6ed178],
  [0x06f067aa,0x72176fba],[0x0a637dc5,0xa2c898a6],[0x113f9804,0xbef90dae],[0x1b710b35,0x131c471b],
  [0x28db77f5,0x23047d84],[0x32caab7b,0x40c72493],[0x3c9ebe0a,0x15c9bebc],[0x431d67c4,0x9c100d4c],
  [0x4cc5d4be,0xcb3e42b6],[0x597f299c,0xfc657e2a],[0x5fcb6fab,0x3ad6faec],[0x6c44198c,0x4a475817]
];

function sha512Core(message, hInit, outBytes) {
  const h = hInit.map(([hi, lo]) => ({ hi, lo }));
  const bitLenHi = Math.floor(message.length / 0x20000000); // (len*8) >>> 32, len*8 overflows 32 bits well before 2^29 bytes
  const bitLenLo = (message.length * 8) >>> 0;
  const mod = (message.length + 1) % 128;
  const padLen = (mod <= 112) ? 112 - mod : 240 - mod;
  const padded = new Uint8Array(message.length + 1 + padLen + 16);
  padded.set(message, 0);
  padded[message.length] = 0x80;
  const dv = new DataView(padded.buffer, padded.byteOffset + padded.length - 16, 16);
  dv.setUint32(0, 0, false); dv.setUint32(4, bitLenHi, false);
  dv.setUint32(8, 0, false); dv.setUint32(12, bitLenLo, false);

  const wHi = new Uint32Array(80), wLo = new Uint32Array(80);

  function add2(aHi, aLo, bHi, bLo) {
    let lo = (aLo + bLo) >>> 0;
    const carry = (lo < (aLo >>> 0)) ? 1 : 0; // unsigned overflow check
    let hi = (aHi + bHi + carry) >>> 0;
    return [hi, lo];
  }
  function add4(a,b,c,d) { let r = add2(a[0],a[1],b[0],b[1]); r = add2(r[0],r[1],c[0],c[1]); return add2(r[0],r[1],d[0],d[1]); }
  function add5(a,b,c,d,e) { let r = add4(a,b,c,d); return add2(r[0],r[1],e[0],e[1]); }

  function rotr(hi, lo, n) {
    if (n === 0) return [hi, lo];
    if (n < 32) return [ ((hi >>> n) | (lo << (32-n))) >>> 0, ((lo >>> n) | (hi << (32-n))) >>> 0 ];
    if (n === 32) return [lo, hi];
    const m = n - 32;
    return [ ((lo >>> m) | (hi << (32-m))) >>> 0, ((hi >>> m) | (lo << (32-m))) >>> 0 ];
  }
  function shr(hi, lo, n) {
    if (n === 0) return [hi, lo];
    if (n < 32) return [ (hi >>> n) >>> 0, ((lo >>> n) | (hi << (32-n))) >>> 0 ];
    if (n >= 64) return [0, 0];
    return [0, (hi >>> (n-32)) >>> 0];
  }
  function xor2(a, b) { return [(a[0]^b[0])>>>0, (a[1]^b[1])>>>0]; }

  for (let off = 0; off < padded.length; off += 128) {
    for (let i = 0; i < 16; i++) {
      const p = off + i*8;
      wHi[i] = (padded[p]<<24 | padded[p+1]<<16 | padded[p+2]<<8 | padded[p+3]) >>> 0;
      wLo[i] = (padded[p+4]<<24 | padded[p+5]<<16 | padded[p+6]<<8 | padded[p+7]) >>> 0;
    }
    for (let i = 16; i < 80; i++) {
      const w15 = [wHi[i-15], wLo[i-15]], w2 = [wHi[i-2], wLo[i-2]];
      const s0 = xor2(xor2(rotr(w15[0],w15[1],1), rotr(w15[0],w15[1],8)), shr(w15[0],w15[1],7));
      const s1 = xor2(xor2(rotr(w2[0],w2[1],19), rotr(w2[0],w2[1],61)), shr(w2[0],w2[1],6));
      const sum = add4([wHi[i-16],wLo[i-16]], s0, [wHi[i-7],wLo[i-7]], s1);
      wHi[i] = sum[0]; wLo[i] = sum[1];
    }
    let a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (let i = 0; i < 80; i++) {
      const S1 = xor2(xor2(rotr(e.hi,e.lo,14), rotr(e.hi,e.lo,18)), rotr(e.hi,e.lo,41));
      const ch = [ ((e.hi & f.hi) ^ (~e.hi & g.hi)) >>> 0, ((e.lo & f.lo) ^ (~e.lo & g.lo)) >>> 0 ];
      const temp1 = add5([hh.hi,hh.lo], S1, ch, SHA512_K[i], [wHi[i],wLo[i]]);
      const S0 = xor2(xor2(rotr(a.hi,a.lo,28), rotr(a.hi,a.lo,34)), rotr(a.hi,a.lo,39));
      const maj = [ ((a.hi & b.hi) ^ (a.hi & c.hi) ^ (b.hi & c.hi)) >>> 0, ((a.lo & b.lo) ^ (a.lo & c.lo) ^ (b.lo & c.lo)) >>> 0 ];
      const temp2 = add2(S0[0], S0[1], maj[0], maj[1]);
      hh = g; g = f; f = e;
      const dPlusT1 = add2(d.hi, d.lo, temp1[0], temp1[1]);
      e = { hi: dPlusT1[0], lo: dPlusT1[1] };
      d = c; c = b; b = a;
      const t1PlusT2 = add2(temp1[0], temp1[1], temp2[0], temp2[1]);
      a = { hi: t1PlusT2[0], lo: t1PlusT2[1] };
    }
    const vals = [a,b,c,d,e,f,g,hh];
    for (let i = 0; i < 8; i++) {
      const r = add2(h[i].hi, h[i].lo, vals[i].hi, vals[i].lo);
      h[i].hi = r[0]; h[i].lo = r[1];
    }
  }
  const out = new Uint8Array(outBytes);
  for (let i = 0; i * 8 < outBytes; i++) {
    out[i*8]   = (h[i].hi>>>24)&0xff; out[i*8+1] = (h[i].hi>>>16)&0xff;
    out[i*8+2] = (h[i].hi>>>8)&0xff;  out[i*8+3] = h[i].hi&0xff;
    out[i*8+4] = (h[i].lo>>>24)&0xff; out[i*8+5] = (h[i].lo>>>16)&0xff;
    out[i*8+6] = (h[i].lo>>>8)&0xff;  out[i*8+7] = h[i].lo&0xff;
  }
  return out;
}

function sha512(message) {
  return sha512Core(message, [
    [0x6a09e667,0xf3bcc908],[0xbb67ae85,0x84caa73b],[0x3c6ef372,0xfe94f82b],[0xa54ff53a,0x5f1d36f1],
    [0x510e527f,0xade682d1],[0x9b05688c,0x2b3e6c1f],[0x1f83d9ab,0xfb41bd6b],[0x5be0cd19,0x137e2179]
  ], 64);
}

function sha384(message) {
  return sha512Core(message, [
    [0xcbbb9d5d,0xc1059ed8],[0x629a292a,0x367cd507],[0x9159015a,0x3070dd17],[0x152fecd8,0xf70e5939],
    [0x67332667,0xffc00b31],[0x8eb44a87,0x68581511],[0xdb0c2e0d,0x64f98fa7],[0x47b5481d,0xbefa4fa4]
  ], 48);
}

if (typeof module !== 'undefined') module.exports = { sha256, sha512, sha384 };
