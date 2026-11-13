/* Format identification: magic-byte signatures plus a Shannon-entropy heuristic as a
   fallback signal for unrecognized high-entropy (likely encrypted/compressed) files.
   Depends on: utils.js (shannonEntropy). */

const SIGNATURES = [
  { format: 'PDF', bytes: [0x25,0x50,0x44,0x46,0x2D] },                         // %PDF-
  { format: 'ZIP', bytes: [0x50,0x4B,0x03,0x04] },
  { format: 'ZIP (empty)', bytes: [0x50,0x4B,0x05,0x06] },
  { format: 'ZIP (spanned)', bytes: [0x50,0x4B,0x07,0x08] },
  { format: 'RAR4', bytes: [0x52,0x61,0x72,0x21,0x1A,0x07,0x00] },
  { format: 'RAR5', bytes: [0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00] },
  { format: '7z', bytes: [0x37,0x7A,0xBC,0xAF,0x27,0x1C] },
  { format: 'OLE2 Compound (legacy Office)', bytes: [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1] },
  { format: 'GZIP', bytes: [0x1F,0x8B] },
];

function matchesSignature(bytes, sig) {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) return false;
  return true;
}

function looksLikeAsciiArmoredPgp(bytes) {
  const head = String.fromCharCode(...bytes.slice(0, 40));
  return head.includes('-----BEGIN PGP');
}

/** Binary OpenPGP packets start with a tag byte whose high bit is set. The low bits encode
 * packet type; common first packets for encrypted messages are PKESK (tag 1) or SKESK (tag 3)
 * in old or new packet format. This is a heuristic, not a full parser. */
function looksLikeBinaryPgp(bytes) {
  if (bytes.length < 2) return false;
  const b0 = bytes[0];
  if ((b0 & 0x80) === 0) return false;
  const newFormat = (b0 & 0x40) !== 0;
  const tag = newFormat ? (b0 & 0x3F) : ((b0 >> 2) & 0x0F);
  return tag === 1 || tag === 3 || tag === 18; // PKESK, SKESK, or SEIP
}

function zipEntryNamesFromCentralDir(bytes) {
  try {
    const entries = parseZipCentralDirectory(bytes);
    return entries ? entries.map(e => e.fileName) : [];
  } catch (e) { return []; }
}

async function identifyFile(bytes) {
  for (const sig of SIGNATURES) {
    if (matchesSignature(bytes, sig.bytes)) {
      const result = { format: sig.format, confidence: 'high', encrypted: null, notes: [] };
      if (sig.format.startsWith('ZIP')) refineZipIdentification(bytes, result);
      else if (sig.format === 'PDF') refinePdfIdentification(bytes, result);
      else if (sig.format === 'OLE2 Compound (legacy Office)') refineOleIdentification(bytes, result);
      else if (sig.format === 'RAR4' || sig.format === 'RAR5') { result.notes.push('RAR encryption detection only; no password verification implemented.'); }
      else if (sig.format === '7z') { result.notes.push('7z encryption detection only; no password verification implemented.'); }
      return finalizeResult(bytes, result);
    }
  }
  if (looksLikeAsciiArmoredPgp(bytes)) {
    return finalizeResult(bytes, { format: 'OpenPGP (ASCII-armored)', confidence: 'high', encrypted: true, notes: ['Detection only; no password verification implemented.'] });
  }
  if (looksLikeBinaryPgp(bytes)) {
    return finalizeResult(bytes, { format: 'OpenPGP (binary)', confidence: 'medium', encrypted: true, notes: ['Heuristic packet-tag match; detection only.'] });
  }
  const entropy = shannonEntropy(bytes);
  const result = { format: 'Unknown', confidence: 'low', encrypted: entropy > 7.5 ? true : null, notes: [] };
  if (entropy > 7.5) result.notes.push(`High entropy (${entropy.toFixed(2)} bits/byte) suggests encrypted or compressed content.`);
  else result.notes.push(`Entropy ${entropy.toFixed(2)} bits/byte; no known signature matched.`);
  return finalizeResult(bytes, result);
}

function refinePdfIdentification(bytes, result) {
  const info = (typeof extractPdfEncryptionInfo === 'function') ? extractPdfEncryptionInfo(bytes) : null;
  if (info) {
    result.encrypted = true;
    result.encryptionDetail = { revision: info.R, v: info.V, cfm: info.cfm || (info.R <= 4 ? 'RC4/AESV2' : 'AESV3') };
    result.notes.push(`Standard Security Handler, revision ${info.R}.`);
  } else {
    result.encrypted = false;
    result.notes.push('No /Encrypt dictionary found.');
  }
}

function refineZipIdentification(bytes, result) {
  const analysis = (typeof analyzeZip === 'function') ? analyzeZip(bytes) : { applicable: false };
  if (!analysis.applicable) { result.encrypted = false; result.notes.push('No encrypted entries detected.'); return; }
  result.encrypted = true;
  if (analysis.aesInfo) {
    const bits = analysis.aesInfo.strength === 1 ? 128 : (analysis.aesInfo.strength === 2 ? 192 : 256);
    result.encryptionDetail = { type: 'WinZip AES', bits, aeVersion: analysis.aesInfo.versionNumber };
    result.notes.push(`WinZip AES-${bits} (AE-${analysis.aesInfo.versionNumber}), ${analysis.encryptedEntries} encrypted entr${analysis.encryptedEntries === 1 ? 'y' : 'ies'}.`);
  } else {
    result.encryptionDetail = { type: 'ZipCrypto' };
    result.notes.push(`Classic ZipCrypto (weak), ${analysis.encryptedEntries} encrypted entr${analysis.encryptedEntries === 1 ? 'y' : 'ies'}.`);
  }
  const names = analysis.allEntries.map(e => e.fileName);
  if (names.some(n => n.startsWith('word/')) ) result.format = 'ZIP (Office Open XML - Word)';
  else if (names.some(n => n.startsWith('xl/'))) result.format = 'ZIP (Office Open XML - Excel)';
  else if (names.some(n => n.startsWith('ppt/'))) result.format = 'ZIP (Office Open XML - PowerPoint)';
}

function refineOleIdentification(bytes, result) {
  // Encrypted OOXML (.docx/.xlsx/.pptx) is stored as an OLE2 compound file containing
  // "EncryptionInfo" and "EncryptedPackage" streams.
  const officeInfo = (typeof extractOfficeEncryptionInfo === 'function') ? extractOfficeEncryptionInfo(bytes) : null;
  if (officeInfo) {
    result.encrypted = true;
    result.format = 'Legacy OLE2 container (encrypted Office Open XML payload)';
    if (officeInfo.scheme === 'standard') {
      result.encryptionDetail = { scheme: 'standard', algId: officeInfo.algId.toString(16), keyBits: officeInfo.keySizeBits };
      result.notes.push(`"Standard" (ECMA-376/CryptoAPI) encryption, AES-${officeInfo.keySizeBits}. Password verification available (slow: a mandatory 50,000-round key derivation runs per candidate).`);
    } else if (officeInfo.scheme === 'agile') {
      if (officeInfo.parseError) {
        result.notes.push('"Agile" encryption (Office 2010+ default), but its EncryptionInfo XML descriptor could not be parsed. Detection only.');
      } else if (!officeInfo.hashSupported) {
        result.encryptionDetail = { scheme: 'agile', hashAlgorithm: officeInfo.hashAlgorithm, keyBits: officeInfo.keyBits };
        result.notes.push(`"Agile" encryption (Office 2010+ default), AES-${officeInfo.keyBits}, but its hash algorithm (${officeInfo.hashAlgorithm || 'unknown'}) isn't implemented here. Detection only.`);
      } else {
        result.encryptionDetail = { scheme: 'agile', hashAlgorithm: officeInfo.hashAlgorithm, keyBits: officeInfo.keyBits, spinCount: officeInfo.spinCount };
        result.notes.push(`"Agile" encryption (Office 2010+ default), AES-${officeInfo.keyBits} / ${officeInfo.hashAlgorithm}. Password verification available (very slow: a mandatory ${officeInfo.spinCount.toLocaleString()}-round key derivation runs twice per candidate).`);
      }
    } else {
      result.notes.push('Unrecognized encryption scheme version. Detection only.');
    }
  } else {
    result.encrypted = null;
    result.notes.push('OLE2 compound file (legacy .doc/.xls/.ppt or other CFB-based format); encryption status not determined.');
  }
}

async function finalizeResult(bytes, result) {
  result.size = bytes.length;
  result.entropy = shannonEntropy(bytes);
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    result.sha256 = bytesToHex(digest);
  }
  return result;
}

if (typeof module !== 'undefined') module.exports = { identifyFile, SIGNATURES };
