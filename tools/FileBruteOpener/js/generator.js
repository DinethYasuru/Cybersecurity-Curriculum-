/* Test-file generator: produces encrypted PDF and ZIP files for a *known* password, so the
   verification code paths can be exercised end-to-end against files that also open correctly
   in standard tools (Acrobat/poppler/qpdf for PDF; 7-Zip/WinRAR/unzip for ZIP).
   Depends on: utils.js, md5.js, rc4.js, pdf-auth.js, zip-auth.js. */

function asciiBytes(str) { return Uint8Array.from(str.split('').map(c => c.charCodeAt(0))); }

async function aesCbcPkcs7Encrypt(keyBytes, ivBytes, plaintext) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, plaintext));
}

/* ---------- PDF generation ---------- */

const PDF_PROFILES = {
  'rc4-40': { V: 1, R: 2, keyLenBytes: 5, cfm: null },
  'rc4-128': { V: 2, R: 3, keyLenBytes: 16, cfm: null },
  'aes-128': { V: 4, R: 4, keyLenBytes: 16, cfm: 'AESV2' },
  'aes-256': { V: 5, R: 6, keyLenBytes: 32, cfm: 'AESV3' },
};

async function generateEncryptedPdf(profileName, userPassword, ownerPassword) {
  const profile = PDF_PROFILES[profileName];
  if (!profile) throw new Error('Unknown PDF profile: ' + profileName);
  const userPw = strToBytes(userPassword);
  const ownerPw = strToBytes(ownerPassword || userPassword);
  const idBytes = crypto.getRandomValues(new Uint8Array(16));
  const P = -4;

  let O, U, UE = null, OE = null, fileKey;
  if (profile.R <= 4) {
    O = computeO_R234(ownerPw, userPw, profile.keyLenBytes, profile.R);
    fileKey = computeKeyR234(userPw, O, P, idBytes, profile.keyLenBytes, profile.R, true);
    U = computeU_R234(fileKey, idBytes, profile.R);
  } else {
    fileKey = crypto.getRandomValues(new Uint8Array(32));
    const vals = await computeR6Values(userPw, ownerPw, fileKey);
    U = vals.U; UE = vals.UE; O = vals.O; OE = vals.OE;
  }

  const contentPlain = asciiBytes('BT /F1 16 Tf 72 700 Td (This PDF was encrypted for authorized password-recovery testing.) Tj ET');
  let contentCipher;
  if (profile.cfm === null) {
    const objKey = pdfObjectKey(fileKey, 5, 0, false);
    contentCipher = rc4(objKey, contentPlain);
  } else {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = profile.cfm === 'AESV2' ? pdfObjectKey(fileKey, 5, 0, true) : fileKey;
    contentCipher = concatBytes(iv, await aesCbcPkcs7Encrypt(aesKey, iv, contentPlain));
  }

  const hex = (b) => '<' + bytesToHex(b) + '>';
  let encryptDict;
  if (profile.cfm === null) {
    encryptDict = `<< /Filter /Standard /V ${profile.V} /R ${profile.R} /Length ${profile.keyLenBytes * 8} /O ${hex(O)} /U ${hex(U)} /P ${P} >>`;
  } else if (profile.cfm === 'AESV2') {
    encryptDict = `<< /Filter /Standard /V 4 /R 4 /Length 128 /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >> >> /StmF /StdCF /StrF /StdCF /O ${hex(O)} /U ${hex(U)} /P ${P} /EncryptMetadata true >>`;
  } else {
    encryptDict = `<< /Filter /Standard /V 5 /R 6 /Length 256 /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF /O ${hex(O)} /U ${hex(U)} /OE ${hex(OE)} /UE ${hex(UE)} /P ${P} /EncryptMetadata true >>`;
  }

  const objects = [
    asciiBytes('<< /Type /Catalog /Pages 2 0 R >>'),
    asciiBytes('<< /Type /Pages /Kids [3 0 R] /Count 1 >>'),
    asciiBytes('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'),
    asciiBytes('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'),
    concatBytes(asciiBytes(`<< /Length ${contentCipher.length} >>\nstream\n`), contentCipher, asciiBytes('\nendstream')),
    asciiBytes(encryptDict),
  ];

  const chunks = [asciiBytes('%PDF-1.7\n')];
  let offset = chunks[0].length;
  const offsets = [];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(offset);
    const header = asciiBytes(`${i + 1} 0 obj\n`);
    const footer = asciiBytes('\nendobj\n');
    chunks.push(header, objects[i], footer);
    offset += header.length + objects[i].length + footer.length;
  }
  const xrefOffset = offset;
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) xref += `${String(off).padStart(10, '0')} 00000 n \n`;
  chunks.push(asciiBytes(xref));
  chunks.push(asciiBytes(`trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Encrypt 6 0 R /ID [${hex(idBytes)} ${hex(idBytes)}] >>\nstartxref\n${xrefOffset}\n%%EOF`));

  return concatBytes(...chunks);
}

/* ---------- ZIP generation ---------- */

const DOS_TIME = 0x6000, DOS_DATE = 0x2121; // arbitrary fixed timestamp

function buildZipHeaders({ fileName, method, flags, crc, compSize, uncompSize, extra }) {
  const nameBytes = asciiBytes(fileName);
  const local = new Uint8Array(30 + nameBytes.length + extra.length);
  const lv = new DataView(local.buffer);
  lv.setUint32(0, 0x04034b50, true);
  lv.setUint16(4, 20, true);
  lv.setUint16(6, flags, true);
  lv.setUint16(8, method, true);
  lv.setUint16(10, DOS_TIME, true);
  lv.setUint16(12, DOS_DATE, true);
  lv.setUint32(14, crc, true);
  lv.setUint32(18, compSize, true);
  lv.setUint32(22, uncompSize, true);
  lv.setUint16(26, nameBytes.length, true);
  lv.setUint16(28, extra.length, true);
  local.set(nameBytes, 30);
  local.set(extra, 30 + nameBytes.length);
  return { local, nameBytes };
}

function buildCentralDirEntry({ fileName, method, flags, crc, compSize, uncompSize, extra, localOffset }) {
  const nameBytes = asciiBytes(fileName);
  const cd = new Uint8Array(46 + nameBytes.length + extra.length);
  const dv = new DataView(cd.buffer);
  dv.setUint32(0, 0x02014b50, true);
  dv.setUint16(4, 20, true);
  dv.setUint16(6, 20, true);
  dv.setUint16(8, flags, true);
  dv.setUint16(10, method, true);
  dv.setUint16(12, DOS_TIME, true);
  dv.setUint16(14, DOS_DATE, true);
  dv.setUint32(16, crc, true);
  dv.setUint32(20, compSize, true);
  dv.setUint32(24, uncompSize, true);
  dv.setUint16(28, nameBytes.length, true);
  dv.setUint16(30, extra.length, true);
  dv.setUint32(42, localOffset, true);
  cd.set(nameBytes, 46);
  cd.set(extra, 46 + nameBytes.length);
  return cd;
}

function assembleZip(entriesMeta, dataBlocks) {
  const chunks = [];
  let offset = 0;
  const cdEntries = [];
  for (let i = 0; i < entriesMeta.length; i++) {
    const meta = entriesMeta[i];
    const { local } = buildZipHeaders({ ...meta, localOffset: offset });
    chunks.push(local, dataBlocks[i]);
    cdEntries.push(buildCentralDirEntry({ ...meta, localOffset: offset }));
    offset += local.length + dataBlocks[i].length;
  }
  const cdStart = offset;
  for (const cd of cdEntries) { chunks.push(cd); offset += cd.length; }
  const cdSize = offset - cdStart;
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, entriesMeta.length, true);
  ev.setUint16(10, entriesMeta.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, cdStart, true);
  chunks.push(eocd);
  return concatBytes(...chunks);
}

async function generateZipCryptoZip(password, fileName = 'secret.txt', content = 'This ZIP entry was encrypted for authorized password-recovery testing (ZipCrypto).') {
  const contentBytes = asciiBytes(content);
  const crc = crc32Final(contentBytes);
  const header = new Uint8Array(12);
  crypto.getRandomValues(header);
  header[10] = (crc >>> 16) & 0xff;
  header[11] = (crc >>> 24) & 0xff;
  const encrypted = zipCryptoEncryptBytes(strToBytes(password), concatBytes(header, contentBytes));
  const meta = { fileName, method: 0, flags: 0x0001, crc, compSize: encrypted.length, uncompSize: contentBytes.length, extra: new Uint8Array(0) };
  return assembleZip([meta], [encrypted]);
}

function incrementCounterLE(counter) {
  for (let i = 0; i < counter.length; i++) {
    if (++counter[i] !== 0) break;
  }
}

async function winzipAesCtrEncrypt(encKey, plaintext) {
  const out = new Uint8Array(plaintext.length);
  const counter = new Uint8Array(16);
  counter[0] = 1; // WinZip AE counter starts at 1, little-endian
  let pos = 0;
  while (pos < plaintext.length) {
    const keystreamBlock = await aesCbcNoPadEncrypt(encKey, new Uint8Array(16), counter);
    const n = Math.min(16, plaintext.length - pos);
    for (let i = 0; i < n; i++) out[pos + i] = plaintext[pos + i] ^ keystreamBlock[i];
    pos += n;
    incrementCounterLE(counter);
  }
  return out;
}

async function generateWinZipAesZip(password, strengthBits = 256, fileName = 'secret.txt', content = 'This ZIP entry was encrypted for authorized password-recovery testing (WinZip AES).') {
  const contentBytes = asciiBytes(content);
  const keyLenBytes = strengthBits / 8;
  const saltLen = keyLenBytes / 2;
  const salt = crypto.getRandomValues(new Uint8Array(saltLen));
  const passwordBytes = strToBytes(password);
  const { encKey, authKey, pv } = await deriveAesKeyMaterial(passwordBytes, salt, keyLenBytes);
  const cipherText = await winzipAesCtrEncrypt(encKey, contentBytes);
  const hmacKey = await crypto.subtle.importKey('raw', authKey, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const authCode = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, cipherText)).slice(0, 10);
  const entryData = concatBytes(salt, pv, cipherText, authCode);

  const strengthCode = strengthBits === 128 ? 1 : (strengthBits === 192 ? 2 : 3);
  const extra = new Uint8Array(11);
  const xv = new DataView(extra.buffer);
  xv.setUint16(0, 0x9901, true);
  xv.setUint16(2, 7, true); // data size
  xv.setUint16(4, 2, true); // AE-2
  extra[6] = 0x41; extra[7] = 0x45; // "AE"
  extra[8] = strengthCode;
  xv.setUint16(9, 0, true); // actual compression method: STORE

  const meta = { fileName, method: 99, flags: 0x0001, crc: 0, compSize: entryData.length, uncompSize: contentBytes.length, extra };
  return assembleZip([meta], [entryData]);
}

if (typeof module !== 'undefined') {
  module.exports = { generateEncryptedPdf, generateZipCryptoZip, generateWinZipAesZip, PDF_PROFILES };
}
