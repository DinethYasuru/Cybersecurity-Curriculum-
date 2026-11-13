/* Office Open XML (.docx/.xlsx/.pptx) password verification for two encryption schemes:
 * - "Standard" (ECMA-376 §2.3.4.6-2.3.4.9, a.k.a. "CryptoAPI"): what LibreOffice (and Office
 *   itself in legacy-compatible mode) actually produce.
 * - "Agile" (MS-OFFCRYPTO 2.3.4.10-2.3.4.12, version 4.4): modern Office's own default since
 *   Office 2010 - this is what a password set via a real, current copy of Excel/Word/
 *   PowerPoint actually uses, so it matters far more in practice than "Standard" does.
 * Depends on: utils.js (concatBytes, u32le, u16le), sha1.js, sha2.js (sha256/sha384/sha512),
 * aes.js (aesEcbDecrypt, aesCbcDecrypt), cfb.js. */

function officeUtf16LeBytes(str) {
  const out = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    out[i * 2] = code & 0xff;
    out[i * 2 + 1] = (code >> 8) & 0xff;
  }
  return out;
}

function officeU32leBytes(n) {
  return Uint8Array.from([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
}

function officeXorRepeating(data, byteVal, totalLen) {
  const out = new Uint8Array(totalLen).fill(byteVal);
  for (let i = 0; i < data.length && i < totalLen; i++) out[i] = data[i] ^ byteVal;
  return out;
}

/** ECMA-376 Standard key derivation (§2.3.4.7): SHA-1, salt+password, then a fixed 50,000
 * iterations, then an HMAC-like 0x36/0x5C padding trick to stretch the 20-byte SHA-1 output
 * up to whatever key size is needed (AES-128/192/256 all fit within the resulting 40 bytes). */
function officeDeriveStandardKey(password, salt, keySizeBits) {
  const ITER_COUNT = 50000;
  let h = sha1(concatBytes(salt, officeUtf16LeBytes(password)));
  for (let i = 0; i < ITER_COUNT; i++) h = sha1(concatBytes(officeU32leBytes(i), h));
  const hFinal = sha1(concatBytes(h, officeU32leBytes(0)));
  const x1 = sha1(officeXorRepeating(hFinal, 0x36, 64));
  const x2 = sha1(officeXorRepeating(hFinal, 0x5c, 64));
  return concatBytes(x1, x2).slice(0, keySizeBits / 8);
}

/* ---------- Agile encryption (MS-OFFCRYPTO 2.3.4.10-2.3.4.12) ---------- */

function officeBase64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Pulls the attribute list out of the first `<[prefix:]localName ...>` tag found, without a
 * full XML parser (DOMParser isn't available inside Web Workers, where candidate search
 * runs). Safe here because the two elements this needs (keyData, encryptedKey) are always
 * simple self-closing elements with plain (unescaped, no nested '>') attribute values -
 * base64 and decimal numbers - in every real Agile EncryptionInfo stream. */
function officeExtractXmlTagAttrs(xmlText, localName) {
  const re = new RegExp('<[A-Za-z0-9]*:?' + localName + '\\b([^>]*)>', 'i');
  const m = xmlText.match(re);
  if (!m) return null;
  const attrs = {};
  const attrRe = /([A-Za-z:_-]+)\s*=\s*"([^"]*)"/g;
  let am;
  while ((am = attrRe.exec(m[1]))) attrs[am[1]] = am[2];
  return attrs;
}

/** Parses the XML descriptor that follows an Agile EncryptionInfo stream's 8-byte header
 * (4-byte version + 4-byte flags). Returns null if the expected <keyData>/<encryptedKey>
 * elements (or their required attributes) aren't found. */
function parseAgileEncryptionXml(xmlBytes) {
  let xmlText;
  try { xmlText = new TextDecoder('utf-8').decode(xmlBytes); } catch (e) { return null; }
  const keyData = officeExtractXmlTagAttrs(xmlText, 'keyData');
  const encKey = officeExtractXmlTagAttrs(xmlText, 'encryptedKey');
  if (!keyData || !encKey) return null;
  if (!encKey.saltValue || !encKey.encryptedVerifierHashInput || !encKey.encryptedVerifierHashValue) return null;
  const hashAlgorithm = (encKey.hashAlgorithm || keyData.hashAlgorithm || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const spinCount = parseInt(encKey.spinCount, 10);
  const keyBits = parseInt(encKey.keyBits, 10);
  const blockSize = parseInt(encKey.blockSize, 10) || 16;
  if (!Number.isFinite(spinCount) || !Number.isFinite(keyBits)) return null;
  try {
    return {
      hashAlgorithm, spinCount, keyBits, blockSize,
      saltValue: officeBase64ToBytes(encKey.saltValue),
      encryptedVerifierHashInput: officeBase64ToBytes(encKey.encryptedVerifierHashInput),
      encryptedVerifierHashValue: officeBase64ToBytes(encKey.encryptedVerifierHashValue),
    };
  } catch (e) { return null; }
}

/** Dispatches to whichever sync hash implementation matches the XML's hashAlgorithm
 * attribute. Returns null for an algorithm this project hasn't implemented (there is no such
 * case in practice - real Agile files use SHA1/SHA256/SHA384/SHA512 - but the spec allows a
 * handler to decline unknown values, so detection-only is the correct fallback, not a crash). */
function officeAgileHash(bytes, algorithm) {
  if (algorithm === 'SHA1') return sha1(bytes);
  if (algorithm === 'SHA256') return (typeof sha256 === 'function') ? sha256(bytes) : null;
  if (algorithm === 'SHA384') return (typeof sha384 === 'function') ? sha384(bytes) : null;
  if (algorithm === 'SHA512') return (typeof sha512 === 'function') ? sha512(bytes) : null;
  return null;
}

/** MS-OFFCRYPTO 2.3.4.12 "DeriveKey": pads a too-short hash with 0x36 bytes, or truncates a
 * too-long one, to exactly the key length an AES-128/192/256 key needs - distinct from the
 * all-zero padding used for the IV (officeAgileZeroPad) below. */
function officeAgileFixKeyLength(hashBytes, targetLen) {
  if (hashBytes.length === targetLen) return hashBytes;
  if (hashBytes.length > targetLen) return hashBytes.slice(0, targetLen);
  const out = new Uint8Array(targetLen).fill(0x36);
  out.set(hashBytes, 0);
  return out;
}

function officeAgileZeroPad(bytes, targetLen) {
  if (bytes.length === targetLen) return bytes;
  if (bytes.length > targetLen) return bytes.slice(0, targetLen);
  const out = new Uint8Array(targetLen); // rest stays zero
  out.set(bytes, 0);
  return out;
}

// MS-OFFCRYPTO 2.3.4.9's three fixed "block keys", mixed into the final hash round so the
// verifier-hash-input key, verifier-hash-value key, and (unused here) the key-value-unwrap
// key all derive to different values from the same password+salt+spinCount.
const OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_INPUT = Uint8Array.from([0xfe,0xa7,0xd2,0x76,0x3b,0x4b,0x9e,0x79]);
const OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_VALUE = Uint8Array.from([0xd7,0xaa,0x0f,0x6d,0x30,0x61,0x34,0x4e]);

/** MS-OFFCRYPTO 2.3.4.11 "Initial Verification Key Generation", generalized for any block
 * key: H0 = Hash(salt || UTF-16LE(password)); Hn = Hash(uint32le(n-1) || Hn-1) for the
 * mandatory spinCount rounds (typically 100,000 - Agile's own brute-force resistance, not a
 * performance bug); Hfinal = Hash(Hspin || blockKey); then DeriveKey-fit to keyBits/8 bytes. */
function officeAgileDeriveKey(password, salt, hashAlgorithm, spinCount, keyBits, blockKey) {
  let h = officeAgileHash(concatBytes(salt, officeUtf16LeBytes(password)), hashAlgorithm);
  for (let i = 0; i < spinCount; i++) h = officeAgileHash(concatBytes(officeU32leBytes(i), h), hashAlgorithm);
  const hFinal = officeAgileHash(concatBytes(h, blockKey), hashAlgorithm);
  return officeAgileFixKeyLength(hFinal, keyBits / 8);
}

/** A candidate password is correct iff decrypting encryptedVerifierHashInput with its own
 * derived key, then hashing the result, equals decrypting encryptedVerifierHashValue with
 * its (separately-derived, different block key) key - matching MS-OFFCRYPTO 2.3.4.9. No
 * document content is decrypted; EncryptedPackage is never touched during this check. */
function officeCheckAgilePassword(password, parsed) {
  if (!officeAgileHash(new Uint8Array(0), parsed.hashAlgorithm)) return null; // unsupported hash alg
  const iv = officeAgileZeroPad(parsed.saltValue, parsed.blockSize);

  const key1 = officeAgileDeriveKey(password, parsed.saltValue, parsed.hashAlgorithm, parsed.spinCount, parsed.keyBits, OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_INPUT);
  const verifierHashInput = aesCbcDecrypt(key1, iv, parsed.encryptedVerifierHashInput);
  const expectedHash = officeAgileHash(verifierHashInput, parsed.hashAlgorithm);

  const key2 = officeAgileDeriveKey(password, parsed.saltValue, parsed.hashAlgorithm, parsed.spinCount, parsed.keyBits, OFFICE_AGILE_BLOCKKEY_VERIFIER_HASH_VALUE);
  const decryptedHashValue = aesCbcDecrypt(key2, iv, parsed.encryptedVerifierHashValue);

  if (expectedHash.length > decryptedHashValue.length) return false;
  for (let i = 0; i < expectedHash.length; i++) if (expectedHash[i] !== decryptedHashValue[i]) return false;
  return true;
}

const OFFICE_ALG_IDS = { 0x660E: 128, 0x660F: 192, 0x6610: 256 };

/** Parses the EncryptionInfo stream for the "Standard" scheme (ECMA-376 §2.3.4.5-6). */
function parseOfficeEncryptionInfoStandard(info) {
  let off = 4; // versionMajor/versionMinor already consumed by the caller
  off += 4; // EncryptionHeaderFlags (duplicated inside the header itself; not needed again)
  const headerSize = u32le(info, off); off += 4;
  const headerStart = off;
  const flags = u32le(info, off); off += 4;
  off += 4; // sizeExtra
  const algId = u32le(info, off); off += 4;
  const algIdHash = u32le(info, off); off += 4;
  const keySizeField = u32le(info, off); off += 4;
  off = headerStart + headerSize; // skip providerType/reserved1/reserved2/cspName - not needed

  const saltSize = u32le(info, off); off += 4;
  const salt = info.slice(off, off + 16); off += 16;
  const encryptedVerifier = info.slice(off, off + 16); off += 16;
  const verifierHashSize = u32le(info, off); off += 4;
  const isAes = (algId & 0xFF00) === 0x6600;
  const verifierHashLen = isAes ? 32 : 20;
  const encryptedVerifierHash = info.slice(off, off + verifierHashLen);

  const keySizeBits = OFFICE_ALG_IDS[algId] || (keySizeField || 40);
  return { algId, algIdHash, isAes, keySizeBits, saltSize, salt, encryptedVerifier, verifierHashSize, encryptedVerifierHash };
}

function officeCheckStandardPassword(password, parsed) {
  if (!parsed.isAes) return null; // RC4 CryptoAPI: not implemented, see capability matrix
  const key = officeDeriveStandardKey(password, parsed.salt, parsed.keySizeBits);
  const verifier = aesEcbDecrypt(key, parsed.encryptedVerifier);
  const expectedHash = sha1(verifier);
  const decryptedVerifierHash = aesEcbDecrypt(key, parsed.encryptedVerifierHash);
  const verifierHash = decryptedVerifierHash.slice(0, 20);
  for (let i = 0; i < 20; i++) if (expectedHash[i] !== verifierHash[i]) return false;
  return true;
}

/** Parses an encrypted Office Open XML file's CFB container and EncryptionInfo stream.
 * Returns null if this isn't a CFB container, or doesn't carry the expected streams. */
function extractOfficeEncryptionInfo(bytes) {
  const cfb = cfbOpen(bytes);
  if (!cfb) return null;
  const info = cfb.readStream('EncryptionInfo');
  const pkg = cfb.readStream('EncryptedPackage');
  if (!info || !pkg) return null;

  const versionMajor = u16le(info, 0);
  const versionMinor = u16le(info, 2);
  if (versionMajor === 4 && versionMinor === 4) {
    // Header is versionMajor(2) + versionMinor(2) + flags(4) = 8 bytes; the rest of the
    // stream is a UTF-8 XML descriptor (MS-OFFCRYPTO 2.3.4.10).
    const agileParsed = parseAgileEncryptionXml(info.slice(8));
    if (!agileParsed) return { scheme: 'agile', versionMajor, versionMinor, parseError: true };
    const hashSupported = !!officeAgileHash(new Uint8Array(0), agileParsed.hashAlgorithm);
    return { scheme: 'agile', versionMajor, versionMinor, ...agileParsed, hashSupported };
  }
  if (versionMinor === 2) {
    const parsed = parseOfficeEncryptionInfoStandard(info);
    return { scheme: 'standard', versionMajor, versionMinor, ...parsed };
  }
  return { scheme: 'unknown', versionMajor, versionMinor };
}

async function verifyOfficePassword(bytes, password) {
  const parsed = extractOfficeEncryptionInfo(bytes);
  if (!parsed) return { applicable: false };
  if (parsed.scheme === 'agile') {
    if (parsed.parseError) return { applicable: true, scheme: 'agile', valid: null, note: 'Could not parse the Agile EncryptionInfo XML descriptor.' };
    if (!parsed.hashSupported) return { applicable: true, scheme: 'agile', valid: null, note: `Unsupported hash algorithm (${parsed.hashAlgorithm || 'unknown'}); detection only.` };
    const valid = officeCheckAgilePassword(password, parsed);
    return { applicable: true, scheme: 'agile', keyBits: parsed.keyBits, valid };
  }
  if (parsed.scheme !== 'standard') {
    return { applicable: true, scheme: parsed.scheme, valid: null, note: 'Detection only for this encryption scheme.' };
  }
  const valid = officeCheckStandardPassword(password, parsed);
  if (valid === null) return { applicable: true, scheme: 'standard', valid: null, note: 'RC4 CryptoAPI not implemented.' };
  return { applicable: true, scheme: 'standard', keyBits: parsed.keySizeBits, valid };
}

if (typeof module !== 'undefined') {
  module.exports = {
    extractOfficeEncryptionInfo, verifyOfficePassword, officeCheckStandardPassword,
    officeDeriveStandardKey, parseOfficeEncryptionInfoStandard,
    parseAgileEncryptionXml, officeCheckAgilePassword, officeAgileDeriveKey, officeAgileHash,
    officeAgileFixKeyLength, officeAgileZeroPad, officeExtractXmlTagAttrs, officeBase64ToBytes
  };
}
