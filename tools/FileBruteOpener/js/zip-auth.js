/* ZIP encryption parsing + password verification: classic ZipCrypto (PKWARE traditional
   stream cipher) and WinZip AE-1/AE-2 (PBKDF2-HMAC-SHA1 + AES + HMAC-SHA1 authentication).
   Depends on: utils.js (u16le, u32le, crc32Final, concatBytes). No ZIP64 support (adequate
   for an educational tool; files >4GB or with >65535 entries are flagged unsupported). */

const ZIP_LFH_SIG = 0x04034b50, ZIP_CDH_SIG = 0x02014b50, ZIP_EOCD_SIG = 0x06054b50;

function findLastSignature(bytes, sig) {
  const b0 = sig & 0xff, b1 = (sig >> 8) & 0xff, b2 = (sig >> 16) & 0xff, b3 = (sig >> 24) & 0xff;
  for (let i = bytes.length - 4; i >= 0; i--) {
    if (bytes[i] === b0 && bytes[i+1] === b1 && bytes[i+2] === b2 && bytes[i+3] === b3) return i;
  }
  return -1;
}

function parseZipCentralDirectory(bytes) {
  const eocdPos = findLastSignature(bytes, ZIP_EOCD_SIG);
  if (eocdPos < 0) return null;
  const cdOffset = u32le(bytes, eocdPos + 16);
  const cdCount = u16le(bytes, eocdPos + 10);
  const entries = [];
  let pos = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (u32le(bytes, pos) !== ZIP_CDH_SIG) break;
    const flags = u16le(bytes, pos + 8);
    const method = u16le(bytes, pos + 10);
    const modTime = u16le(bytes, pos + 12);
    const crc = u32le(bytes, pos + 16);
    const compSize = u32le(bytes, pos + 20);
    const uncompSize = u32le(bytes, pos + 24);
    const nameLen = u16le(bytes, pos + 28);
    const extraLen = u16le(bytes, pos + 30);
    const commentLen = u16le(bytes, pos + 32);
    const localHeaderOffset = u32le(bytes, pos + 42);
    const nameBytes = bytes.slice(pos + 46, pos + 46 + nameLen);
    const extraBytes = bytes.slice(pos + 46 + nameLen, pos + 46 + nameLen + extraLen);
    const fileName = String.fromCharCode(...nameBytes);
    entries.push({ fileName, flags, method, modTime, crc, compSize, uncompSize, localHeaderOffset, extraBytes });
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function parseAesExtraField(extraBytes) {
  let pos = 0;
  while (pos + 4 <= extraBytes.length) {
    const id = u16le(extraBytes, pos);
    const size = u16le(extraBytes, pos + 2);
    if (id === 0x9901) {
      const versionNumber = u16le(extraBytes, pos + 4);
      const vendor = String.fromCharCode(extraBytes[pos+6], extraBytes[pos+7]);
      const strength = extraBytes[pos + 8];
      const actualMethod = u16le(extraBytes, pos + 9);
      return { versionNumber, vendor, strength, actualMethod };
    }
    pos += 4 + size;
  }
  return null;
}

/** Returns the raw (still-encrypted) data bytes for a central-directory entry, by reading
 * past its local file header (whose field lengths can differ slightly from the central dir). */
function readLocalFileData(bytes, entry) {
  const pos = entry.localHeaderOffset;
  if (u32le(bytes, pos) !== ZIP_LFH_SIG) return null;
  const nameLen = u16le(bytes, pos + 26);
  const extraLen = u16le(bytes, pos + 28);
  const dataStart = pos + 30 + nameLen + extraLen;
  return bytes.slice(dataStart, dataStart + entry.compSize);
}

function isEncrypted(entry) { return (entry.flags & 0x0001) !== 0; }
function isAesEntry(entry) { return entry.method === 99; }

/* ---------- ZipCrypto (PKWARE traditional encryption) ---------- */

/** Returns a mutable key-state object (not a frozen snapshot): `update` mutates `state`
 * in place, so callers that read `ks.state.key2` on each byte always see the live value. */
function zipCryptoInitKeys(passwordBytes) {
  const state = { key0: 0x12345678, key1: 0x23456789, key2: 0x34567890 };
  const update = (c) => {
    state.key0 = (CRC32_TABLE[(state.key0 ^ c) & 0xff] ^ (state.key0 >>> 8)) >>> 0;
    state.key1 = (state.key1 + (state.key0 & 0xff)) >>> 0;
    state.key1 = (Math.imul(state.key1, 134775813) + 1) >>> 0;
    state.key2 = (CRC32_TABLE[(state.key2 ^ (state.key1 >>> 24)) & 0xff] ^ (state.key2 >>> 8)) >>> 0;
  };
  for (let i = 0; i < passwordBytes.length; i++) update(passwordBytes[i]);
  return { state, update };
}

function zipCryptoDecryptBytes(passwordBytes, data) {
  const ks = zipCryptoInitKeys(passwordBytes);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const temp = (ks.state.key2 | 2) & 0xffff;
    const decryptByte = ((Math.imul(temp, temp ^ 1) >>> 8) & 0xff);
    const plain = data[i] ^ decryptByte;
    out[i] = plain;
    ks.update(plain);
  }
  return out;
}

/** Encrypt-side counterpart used only by the test generator. Mechanically the same stream
 * cipher as decryption (XOR with the same keystream byte), but the internal key-update step
 * must advance using the plaintext byte, which here is already known rather than computed. */
function zipCryptoEncryptBytes(passwordBytes, data) {
  const ks = zipCryptoInitKeys(passwordBytes);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const temp = (ks.state.key2 | 2) & 0xffff;
    const decryptByte = ((Math.imul(temp, temp ^ 1) >>> 8) & 0xff);
    out[i] = data[i] ^ decryptByte;
    ks.update(data[i]);
  }
  return out;
}

/** The classic 2-byte header check (~1/65536 false-positive rate) is all that's available
 * for a compressed (DEFLATE) entry without implementing inflate. For a STORE-method entry,
 * though, the full content is right there once decrypted, so we also verify its real CRC-32
 * against the entry's stored CRC-32 - that's a definitive 32-bit check, not a probabilistic
 * one, and it's what actually matters for this app's own STORE-based generated test files. */
function checkZipCryptoPassword(passwordBytes, entry, encryptedData) {
  if (encryptedData.length < 12) return false;
  const decrypted = zipCryptoDecryptBytes(passwordBytes, encryptedData);
  const header = decrypted.slice(0, 12);
  const bit3 = (entry.flags & 0x0008) !== 0;
  let expectedHigh, expectedHigh2;
  if (bit3) {
    expectedHigh = (entry.modTime >> 8) & 0xff;
    expectedHigh2 = entry.modTime & 0xff;
  } else {
    expectedHigh = (entry.crc >>> 24) & 0xff;
    expectedHigh2 = (entry.crc >>> 16) & 0xff;
  }
  if (header[11] !== expectedHigh || header[10] !== expectedHigh2) return false;
  if (entry.method === 0) return crc32Final(decrypted.slice(12)) === entry.crc;
  return true;
}

/* ---------- WinZip AES (AE-1 / AE-2) ---------- */

async function deriveAesKeyMaterial(passwordBytes, salt, keyLenBytes) {
  const keyMaterial = await crypto.subtle.importKey('raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
  const dkLenBits = (keyLenBytes * 2 + 2) * 8;
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-1' }, keyMaterial, dkLenBits));
  return {
    encKey: bits.slice(0, keyLenBytes),
    authKey: bits.slice(keyLenBytes, keyLenBytes * 2),
    pv: bits.slice(keyLenBytes * 2, keyLenBytes * 2 + 2)
  };
}

async function checkWinZipAesPassword(passwordBytes, entry, encryptedData, aesInfo) {
  const keyLenBytes = aesInfo.strength === 1 ? 16 : (aesInfo.strength === 2 ? 24 : 32);
  const saltLen = keyLenBytes / 2;
  if (encryptedData.length < saltLen + 2 + 10) return { valid: false };
  const salt = encryptedData.slice(0, saltLen);
  const storedPv = encryptedData.slice(saltLen, saltLen + 2);
  const cipherAndAuth = encryptedData.slice(saltLen + 2);
  const cipherText = cipherAndAuth.slice(0, cipherAndAuth.length - 10);
  const storedAuthCode = cipherAndAuth.slice(cipherAndAuth.length - 10);

  const { authKey, pv } = await deriveAesKeyMaterial(passwordBytes, salt, keyLenBytes);
  const pvMatch = pv[0] === storedPv[0] && pv[1] === storedPv[1];
  if (!pvMatch) return { valid: false };

  const hmacKey = await crypto.subtle.importKey('raw', authKey, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, cipherText));
  let authOk = true;
  for (let i = 0; i < 10; i++) if (mac[i] !== storedAuthCode[i]) { authOk = false; break; }
  return { valid: pvMatch && authOk, pvOnlyMatch: pvMatch };
}

/* ---------- Top-level entry point ---------- */

function analyzeZip(zipBytes) {
  const entries = parseZipCentralDirectory(zipBytes);
  if (!entries) return { applicable: false };
  const encrypted = entries.filter(isEncrypted);
  if (encrypted.length === 0) return { applicable: false, encryptedEntries: 0 };
  const target = encrypted[0];
  const aesInfo = isAesEntry(target) ? parseAesExtraField(target.extraBytes) : null;
  return { applicable: true, encryptedEntries: encrypted.length, target, aesInfo, allEntries: entries };
}

async function verifyZipPassword(zipBytes, passwordStr) {
  const analysis = analyzeZip(zipBytes);
  if (!analysis.applicable) return { applicable: false };
  const passwordBytes = strToBytes(passwordStr);
  const data = readLocalFileData(zipBytes, analysis.target);
  if (!data) return { applicable: true, valid: false, error: 'local header mismatch' };

  if (analysis.aesInfo) {
    const result = await checkWinZipAesPassword(passwordBytes, analysis.target, data, analysis.aesInfo);
    return {
      applicable: true, type: 'WinZip AES', strengthBits: analysis.aesInfo.strength === 1 ? 128 : (analysis.aesInfo.strength === 2 ? 192 : 256),
      aeVersion: analysis.aesInfo.versionNumber, entryName: analysis.target.fileName, valid: result.valid
    };
  } else {
    const valid = checkZipCryptoPassword(passwordBytes, analysis.target, data);
    return { applicable: true, type: 'ZipCrypto', entryName: analysis.target.fileName, valid };
  }
}

if (typeof module !== 'undefined') {
  module.exports = {
    parseZipCentralDirectory, analyzeZip, verifyZipPassword, checkZipCryptoPassword,
    checkWinZipAesPassword, zipCryptoDecryptBytes, zipCryptoEncryptBytes, zipCryptoInitKeys,
    readLocalFileData, parseAesExtraField, deriveAesKeyMaterial
  };
}
