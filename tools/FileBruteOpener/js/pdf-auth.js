/* PDF Standard Security Handler: parsing of the /Encrypt dictionary and password
   authentication for revisions 2-6 (ISO 32000-1 Algorithm 2/2.A, ISO 32000-2 Algorithm 2.A/2.B).
   Depends on: utils.js (concatBytes, u32le), md5.js (md5), rc4.js (rc4). */

const PDF_PAD = Uint8Array.from([
  0x28,0xBF,0x4E,0x5E,0x4E,0x75,0x8A,0x41,0x64,0x00,0x4E,0x56,0xFF,0xFA,0x01,0x08,
  0x2E,0x2E,0x00,0xB6,0xD0,0x68,0x3E,0x80,0x2F,0x0C,0xA9,0xFE,0x64,0x53,0x69,0x7A
]);

/* ---------- Minimal PDF object tokenizer/parser (subset: dicts, arrays, strings,
   names, numbers, references) - enough to read the trailer and /Encrypt dict reliably,
   handling escaped parentheses/backslashes correctly. ---------- */

function pdfParseValue(bytes, pos) {
  pos = pdfSkipWs(bytes, pos);
  const c = bytes[pos];
  if (c === 0x2F) return pdfParseName(bytes, pos);          // /Name
  if (c === 0x28) return pdfParseLiteralString(bytes, pos);  // (string)
  if (c === 0x3C) {
    if (bytes[pos + 1] === 0x3C) return pdfParseDict(bytes, pos); // <<dict>>
    return pdfParseHexString(bytes, pos);                   // <hex>
  }
  if (c === 0x5B) return pdfParseArray(bytes, pos);          // [array]
  if ((c >= 0x30 && c <= 0x39) || c === 0x2B || c === 0x2D || c === 0x2E) {
    return pdfParseNumberOrRef(bytes, pos);
  }
  if (c === 0x74 && matchKeyword(bytes, pos, 'true')) return { value: true, end: pos + 4 };
  if (c === 0x66 && matchKeyword(bytes, pos, 'false')) return { value: false, end: pos + 5 };
  if (c === 0x6E && matchKeyword(bytes, pos, 'null')) return { value: null, end: pos + 4 };
  return { value: undefined, end: pos + 1 };
}

function matchKeyword(bytes, pos, kw) {
  for (let i = 0; i < kw.length; i++) if (bytes[pos + i] !== kw.charCodeAt(i)) return false;
  return true;
}

function pdfIsWs(b) { return b === 0x20 || b === 0x0A || b === 0x0D || b === 0x09 || b === 0x0C || b === 0x00; }
function pdfIsDelim(b) { return b === 0x28 || b === 0x29 || b === 0x3C || b === 0x3E || b === 0x5B || b === 0x5D || b === 0x7B || b === 0x7D || b === 0x2F || b === 0x25; }

function pdfSkipWs(bytes, pos) {
  while (pos < bytes.length) {
    if (pdfIsWs(bytes[pos])) { pos++; continue; }
    if (bytes[pos] === 0x25) { while (pos < bytes.length && bytes[pos] !== 0x0A && bytes[pos] !== 0x0D) pos++; continue; }
    break;
  }
  return pos;
}

function pdfParseName(bytes, pos) {
  pos++; // skip '/'
  let name = '';
  while (pos < bytes.length && !pdfIsWs(bytes[pos]) && !pdfIsDelim(bytes[pos])) {
    if (bytes[pos] === 0x23 && pos + 2 < bytes.length) { // #xx hex escape
      name += String.fromCharCode(parseInt(String.fromCharCode(bytes[pos+1], bytes[pos+2]), 16));
      pos += 3;
    } else { name += String.fromCharCode(bytes[pos]); pos++; }
  }
  return { value: { type: 'name', name }, end: pos };
}

function pdfParseLiteralString(bytes, pos) {
  pos++; // skip '('
  let depth = 1;
  const out = [];
  while (pos < bytes.length && depth > 0) {
    const c = bytes[pos];
    if (c === 0x5C) { // backslash escape
      const n = bytes[pos + 1];
      if (n === 0x6E) { out.push(0x0A); pos += 2; }
      else if (n === 0x72) { out.push(0x0D); pos += 2; }
      else if (n === 0x74) { out.push(0x09); pos += 2; }
      else if (n === 0x62) { out.push(0x08); pos += 2; }
      else if (n === 0x66) { out.push(0x0C); pos += 2; }
      else if (n === 0x28) { out.push(0x28); pos += 2; }
      else if (n === 0x29) { out.push(0x29); pos += 2; }
      else if (n === 0x5C) { out.push(0x5C); pos += 2; }
      else if (n === 0x0D) { pos += (bytes[pos+2] === 0x0A) ? 3 : 2; } // line continuation
      else if (n === 0x0A) { pos += 2; }
      else if (n >= 0x30 && n <= 0x37) { // octal, up to 3 digits
        let oct = ''; let p = pos + 1;
        while (oct.length < 3 && bytes[p] >= 0x30 && bytes[p] <= 0x37) { oct += String.fromCharCode(bytes[p]); p++; }
        out.push(parseInt(oct, 8) & 0xFF);
        pos = p;
      } else { out.push(n); pos += 2; }
      continue;
    }
    if (c === 0x28) { depth++; out.push(c); pos++; continue; }
    if (c === 0x29) { depth--; pos++; if (depth === 0) break; out.push(c); continue; }
    out.push(c); pos++;
  }
  return { value: { type: 'string', bytes: Uint8Array.from(out) }, end: pos };
}

function pdfParseHexString(bytes, pos) {
  pos++; // skip '<'
  let hex = '';
  while (pos < bytes.length && bytes[pos] !== 0x3E) {
    const c = bytes[pos];
    if (!pdfIsWs(c)) hex += String.fromCharCode(c);
    pos++;
  }
  pos++; // skip '>'
  if (hex.length % 2 === 1) hex += '0';
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return { value: { type: 'string', bytes: out }, end: pos };
}

function pdfParseArray(bytes, pos) {
  pos++; // skip '['
  const arr = [];
  pos = pdfSkipWs(bytes, pos);
  while (pos < bytes.length && bytes[pos] !== 0x5D) {
    const r = pdfParseValue(bytes, pos);
    arr.push(r.value);
    pos = pdfSkipWs(bytes, r.end);
  }
  pos++; // skip ']'
  return { value: { type: 'array', items: arr }, end: pos };
}

function pdfParseDict(bytes, pos) {
  pos += 2; // skip '<<'
  const dict = {};
  pos = pdfSkipWs(bytes, pos);
  while (pos < bytes.length && !(bytes[pos] === 0x3E && bytes[pos + 1] === 0x3E)) {
    const keyR = pdfParseName(bytes, pos);
    pos = pdfSkipWs(bytes, keyR.end);
    const valR = pdfParseValue(bytes, pos);
    dict[keyR.value.name] = valR.value;
    pos = pdfSkipWs(bytes, valR.end);
  }
  pos += 2; // skip '>>'
  return { value: { type: 'dict', dict }, end: pos };
}

function pdfParseNumberOrRef(bytes, pos) {
  const start = pos;
  while (pos < bytes.length && (bytes[pos] >= 0x30 && bytes[pos] <= 0x39 || bytes[pos] === 0x2B || bytes[pos] === 0x2D || bytes[pos] === 0x2E)) pos++;
  const numStr = String.fromCharCode(...bytes.slice(start, pos));
  // lookahead for "<int> <int> R" reference pattern
  if (/^\d+$/.test(numStr)) {
    let p2 = pdfSkipWs(bytes, pos);
    const start2 = p2;
    while (p2 < bytes.length && bytes[p2] >= 0x30 && bytes[p2] <= 0x39) p2++;
    if (p2 > start2) {
      const genStr = String.fromCharCode(...bytes.slice(start2, p2));
      let p3 = pdfSkipWs(bytes, p2);
      if (bytes[p3] === 0x52 && (p3 + 1 >= bytes.length || pdfIsWs(bytes[p3+1]) || pdfIsDelim(bytes[p3+1]))) {
        return { value: { type: 'ref', num: parseInt(numStr, 10), gen: parseInt(genStr, 10) }, end: p3 + 1 };
      }
    }
  }
  return { value: { type: 'number', value: parseFloat(numStr) }, end: pos };
}

/* ---------- Locate and parse the /Encrypt dictionary + /ID from a PDF byte buffer ---------- */

function bytesIndexOfAll(bytes, needle) {
  const idxs = [];
  const n0 = needle.charCodeAt(0);
  for (let i = 0; i <= bytes.length - needle.length; i++) {
    if (bytes[i] !== n0) continue;
    let ok = true;
    for (let j = 1; j < needle.length; j++) if (bytes[i + j] !== needle.charCodeAt(j)) { ok = false; break; }
    if (ok) idxs.push(i);
  }
  return idxs;
}

function findObjectDict(bytes, num, gen) {
  const marker = `${num} ${gen} obj`;
  const positions = bytesIndexOfAll(bytes, marker);
  for (const pos of positions) {
    let p = pdfSkipWs(bytes, pos + marker.length);
    if (bytes[p] === 0x3C && bytes[p + 1] === 0x3C) {
      return pdfParseDict(bytes, p).value;
    }
  }
  return null;
}

function resolveMaybeRef(bytes, val) {
  if (val && val.type === 'ref') {
    const d = findObjectDict(bytes, val.num, val.gen);
    return d;
  }
  return val;
}

function extractPdfEncryptionInfo(bytes) {
  const trailerPositions = bytesIndexOfAll(bytes, 'trailer');
  let trailerDict = null;
  for (let i = trailerPositions.length - 1; i >= 0; i--) {
    let p = pdfSkipWs(bytes, trailerPositions[i] + 'trailer'.length);
    if (bytes[p] === 0x3C && bytes[p + 1] === 0x3C) { trailerDict = pdfParseDict(bytes, p).value; break; }
  }
  // Fallback: look for a cross-reference stream style trailer embedded in an object
  // (xref streams carry /Encrypt directly in the stream dict) - scan for "/Encrypt" occurrences.
  let encryptDictVal = null;
  let idArray = null;

  if (trailerDict) {
    const encRef = trailerDict.dict['Encrypt'];
    if (encRef) {
      const resolved = encRef.type === 'ref' ? findObjectDict(bytes, encRef.num, encRef.gen) : encRef;
      encryptDictVal = resolved;
    }
    const idVal = trailerDict.dict['ID'];
    if (idVal && idVal.type === 'array') idArray = idVal.items;
  }

  if (!encryptDictVal) {
    const pos = bytesIndexOfAll(bytes, '/Encrypt');
    for (const p of pos) {
      let q = pdfSkipWs(bytes, p + '/Encrypt'.length);
      const r = pdfParseValue(bytes, q);
      const resolved = resolveMaybeRef(bytes, r.value);
      if (resolved && resolved.type === 'dict') { encryptDictVal = resolved; break; }
    }
  }
  if (!idArray) {
    const pos = bytesIndexOfAll(bytes, '/ID');
    for (const p of pos) {
      let q = pdfSkipWs(bytes, p + '/ID'.length);
      if (bytes[q] === 0x5B) { idArray = pdfParseArray(bytes, q).value.items; break; }
    }
  }

  if (!encryptDictVal) return null;
  const d = encryptDictVal.dict;
  const get = (k) => d[k];
  const num = (k, def) => (get(k) && get(k).type === 'number') ? get(k).value : def;
  const str = (k) => (get(k) && get(k).type === 'string') ? get(k).bytes : null;

  const V = num('V', 1);
  const R = num('R', 2);
  const O = str('O');
  const U = str('U');
  const P = num('P', 0);
  const length = num('Length', 40);
  const encryptMetadata = get('EncryptMetadata') ? get('EncryptMetadata').value !== false : true;
  const UE = str('UE');
  const OE = str('OE');

  let idBytes = new Uint8Array(0);
  if (idArray && idArray.length > 0 && idArray[0] && idArray[0].type === 'string') idBytes = idArray[0].bytes;

  // Determine crypt filter algorithm for V>=4 (AESV2/AESV3 vs RC4/Identity)
  let cfm = null;
  const cf = get('CF');
  const stmF = get('StmF');
  if (cf && cf.type === 'dict' && stmF && stmF.type === 'name') {
    const filterDict = cf.dict[stmF.name];
    if (filterDict && filterDict.type === 'dict') {
      const cfmName = filterDict.dict['CFM'];
      if (cfmName && cfmName.type === 'name') cfm = cfmName.name;
    }
  }

  return { V, R, O, U, P: P | 0, length, encryptMetadata, idBytes, cfm, UE, OE };
}

/* ---------- Algorithm 2: compute RC4/AES-128 (R2-R4) file encryption key from a password ---------- */

function pdfPadPassword(passwordBytes) {
  if (passwordBytes.length >= 32) return passwordBytes.slice(0, 32);
  return concatBytes(passwordBytes, PDF_PAD.slice(0, 32 - passwordBytes.length));
}

function computeKeyR234(passwordBytes, O, P, idBytes, keyLenBytes, R, encryptMetadata) {
  const padded = pdfPadPassword(passwordBytes);
  const pBytes = new Uint8Array(4);
  const pDv = new DataView(pBytes.buffer);
  pDv.setInt32(0, P, true);
  let input = concatBytes(padded, O, pBytes, idBytes);
  if (R >= 4 && !encryptMetadata) input = concatBytes(input, Uint8Array.from([0xFF, 0xFF, 0xFF, 0xFF]));
  let digest = md5(input);
  if (R >= 3) {
    for (let i = 0; i < 50; i++) digest = md5(digest.slice(0, keyLenBytes));
  }
  return digest.slice(0, keyLenBytes);
}

function checkUserPasswordR234(passwordBytes, info) {
  const keyLen = info.V === 1 ? 5 : (info.length / 8);
  const key = computeKeyR234(passwordBytes, info.O, info.P, info.idBytes, keyLen, info.R, info.encryptMetadata);
  if (info.R === 2) {
    const computedU = rc4(key, PDF_PAD);
    return bytesEqual(computedU, info.U.slice(0, 32));
  } else {
    let hash = md5(concatBytes(PDF_PAD, info.idBytes));
    let val = rc4(key, hash);
    for (let i = 1; i <= 19; i++) {
      const roundKey = key.map(b => b ^ i);
      val = rc4(roundKey, val);
    }
    return bytesEqual(val.slice(0, 16), info.U.slice(0, 16));
  }
}

function checkOwnerPasswordR234(passwordBytes, info) {
  // Owner password: derive RC4 key from padded owner password (no O/ID mixed in for this stage),
  // decrypt O to recover the user password, then validate that as the user password.
  const padded = pdfPadPassword(passwordBytes);
  let digest = md5(padded);
  if (info.R >= 3) for (let i = 0; i < 50; i++) digest = md5(digest);
  const keyLen = info.V === 1 ? 5 : (info.length / 8);
  const ownerKey = digest.slice(0, keyLen);
  let userPwPadded;
  if (info.R === 2) {
    userPwPadded = rc4(ownerKey, info.O);
  } else {
    let val = info.O.slice(0, 32);
    for (let i = 19; i >= 0; i--) {
      const roundKey = ownerKey.map(b => b ^ i);
      val = rc4(roundKey, val);
    }
    userPwPadded = val;
  }
  return checkUserPasswordR234(userPwPadded, info);
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* ---------- Algorithm 2.A / 2.B (R5/R6, AES-256, ISO 32000-2) ---------- */

async function sha(bytes, alg) { return new Uint8Array(await crypto.subtle.digest(alg, bytes)); }

async function hash2B(passwordBytes, salt, udata, revision) {
  let K = await sha(concatBytes(passwordBytes, salt, udata), 'SHA-256');
  if (revision < 6) return K; // R5: single SHA-256 round, no hardening
  let round = 0;
  while (true) {
    const unit = concatBytes(passwordBytes, K, udata);
    let K1 = new Uint8Array(0);
    for (let i = 0; i < 64; i++) K1 = concatBytes(K1, unit);
    const E = await aesCbcNoPadEncrypt(K.slice(0, 16), K.slice(16, 32), K1);
    let sum = 0;
    for (let i = 0; i < 16; i++) sum += E[i];
    const mod = sum % 3;
    if (mod === 0) K = await sha(E, 'SHA-256');
    else if (mod === 1) K = await sha(E, 'SHA-384');
    else K = await sha(E, 'SHA-512');
    round++;
    if (round >= 64 && E[E.length - 1] <= round - 32) break;
  }
  return K.slice(0, 32);
}

async function checkUserPasswordR56(passwordBytes, info) {
  if (!info.U || info.U.length < 48) return false;
  const hashVal = info.U.slice(0, 32);
  const validationSalt = info.U.slice(32, 40);
  const computed = await hash2B(passwordBytes, validationSalt, new Uint8Array(0), info.R);
  return bytesEqual(computed, hashVal);
}

async function checkOwnerPasswordR56(passwordBytes, info) {
  if (!info.O || info.O.length < 48 || !info.U) return false;
  const hashVal = info.O.slice(0, 32);
  const validationSalt = info.O.slice(32, 40);
  const udata = info.U.slice(0, 48);
  const computed = await hash2B(passwordBytes, validationSalt, udata, info.R);
  return bytesEqual(computed, hashVal);
}

/* ---------- Encryption-side helpers (Algorithms 3/4/5 and R6 key wrapping), used only by
   the test-file generator to build a correctly-encrypted document from scratch. ---------- */

function computeO_R234(ownerPasswordBytes, userPasswordBytes, keyLenBytes, R) {
  const paddedOwner = pdfPadPassword(ownerPasswordBytes);
  let digest = md5(paddedOwner);
  if (R >= 3) for (let i = 0; i < 50; i++) digest = md5(digest);
  const ownerKey = digest.slice(0, keyLenBytes);
  const paddedUser = pdfPadPassword(userPasswordBytes);
  if (R === 2) return rc4(ownerKey, paddedUser);
  let val = rc4(ownerKey, paddedUser);
  for (let i = 1; i <= 19; i++) val = rc4(ownerKey.map(b => b ^ i), val);
  return val;
}

function computeU_R234(fileKey, idBytes, R) {
  if (R === 2) return rc4(fileKey, PDF_PAD);
  const hash = md5(concatBytes(PDF_PAD, idBytes));
  let val = rc4(fileKey, hash);
  for (let i = 1; i <= 19; i++) val = rc4(fileKey.map(b => b ^ i), val);
  return concatBytes(val, new Uint8Array(16)); // trailing 16 bytes: spec says contents don't matter
}

/** Builds U/UE/O/OE for R6 (AES-256) around a given 32-byte random file encryption key. */
async function computeR6Values(userPasswordBytes, ownerPasswordBytes, fileKey) {
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
  const validationSaltU = rand(8), keySaltU = rand(8);
  const hashU = await hash2B(userPasswordBytes, validationSaltU, new Uint8Array(0), 6);
  const U = concatBytes(hashU, validationSaltU, keySaltU);
  const intermediateU = await hash2B(userPasswordBytes, keySaltU, new Uint8Array(0), 6);
  const UE = await aesCbcNoPadEncrypt(intermediateU, new Uint8Array(16), fileKey);

  const validationSaltO = rand(8), keySaltO = rand(8);
  const hashO = await hash2B(ownerPasswordBytes, validationSaltO, U, 6);
  const O = concatBytes(hashO, validationSaltO, keySaltO);
  const intermediateO = await hash2B(ownerPasswordBytes, keySaltO, U, 6);
  const OE = await aesCbcNoPadEncrypt(intermediateO, new Uint8Array(16), fileKey);

  return { U, UE, O, OE };
}

function pdfObjectKey(fileKey, objNum, gen, isAes) {
  const numBytes = Uint8Array.from([objNum & 0xff, (objNum >> 8) & 0xff, (objNum >> 16) & 0xff]);
  const genBytes = Uint8Array.from([gen & 0xff, (gen >> 8) & 0xff]);
  let input = concatBytes(fileKey, numBytes, genBytes);
  if (isAes) input = concatBytes(input, Uint8Array.from([0x73, 0x41, 0x6C, 0x54])); // "sAlT"
  const digest = md5(input);
  return digest.slice(0, Math.min(fileKey.length + 5, 16));
}

/* ---------- Top-level entry point ---------- */

async function verifyPdfPassword(pdfBytes, passwordStr) {
  const info = extractPdfEncryptionInfo(pdfBytes);
  if (!info) return { applicable: false };
  const passwordBytes = strToBytes(passwordStr);
  let userOk = false, ownerOk = false;
  if (info.R >= 5) {
    userOk = await checkUserPasswordR56(passwordBytes, info);
    if (!userOk) ownerOk = await checkOwnerPasswordR56(passwordBytes, info);
  } else {
    userOk = checkUserPasswordR234(passwordBytes, info);
    if (!userOk) ownerOk = checkOwnerPasswordR234(passwordBytes, info);
  }
  return {
    applicable: true, revision: info.R, v: info.V, cfm: info.cfm,
    valid: userOk || ownerOk, matchedAs: userOk ? 'user' : (ownerOk ? 'owner' : null)
  };
}

if (typeof module !== 'undefined') {
  module.exports = {
    extractPdfEncryptionInfo, verifyPdfPassword, checkUserPasswordR234, checkOwnerPasswordR234,
    checkUserPasswordR56, checkOwnerPasswordR56, computeKeyR234, pdfPadPassword, PDF_PAD, hash2B,
    pdfParseDict, pdfParseValue, pdfParseLiteralString,
    computeO_R234, computeU_R234, computeR6Values, pdfObjectKey
  };
}
