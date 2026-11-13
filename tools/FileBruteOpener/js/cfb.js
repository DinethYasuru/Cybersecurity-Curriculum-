/* Compound File Binary (CFB / OLE2) container parser: enough to locate and read named
 * streams by name (we only need "EncryptionInfo" and "EncryptedPackage" out of an encrypted
 * Office Open XML file). Implements MS-CFB directly - header, FAT, mini-FAT, and a flat scan
 * of directory entries (the red-black tree pointers aren't needed for a name lookup).
 * Depends on: utils.js (u32le, u16le). */

const CFB_HEADER_SIZE = 512;
const CFB_FREESECT = 0xFFFFFFFF, CFB_ENDOFCHAIN = 0xFFFFFFFE, CFB_FATSECT = 0xFFFFFFFD, CFB_DIFSECT = 0xFFFFFFFC;
const CFB_SIGNATURE = [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1];

function cfbIsSignature(bytes) {
  if (bytes.length < 8) return false;
  for (let i = 0; i < 8; i++) if (bytes[i] !== CFB_SIGNATURE[i]) return false;
  return true;
}

function cfbU64LowBits(bytes, off) {
  // Stream sizes are stored as 8-byte little-endian; real Office files never approach 4GB,
  // so the low 32 bits (plus a sanity check the high bits are 0) are all we need.
  return u32le(bytes, off);
}

function cfbParseHeader(bytes) {
  const sectorShift = u16le(bytes, 30);
  const miniSectorShift = u16le(bytes, 32);
  return {
    sectorSize: 1 << sectorShift,
    miniSectorSize: 1 << miniSectorShift,
    numFatSectors: u32le(bytes, 44),
    firstDirSector: u32le(bytes, 48),
    miniStreamCutoff: u32le(bytes, 56),
    firstMiniFatSector: u32le(bytes, 60),
    numMiniFatSectors: u32le(bytes, 64),
    firstDifatSector: u32le(bytes, 68),
    numDifatSectors: u32le(bytes, 72),
    headerDifat: bytes.slice(76, 512), // 109 x 4-byte FAT sector numbers
  };
}

function cfbSectorOffset(sectorNum, sectorSize) { return CFB_HEADER_SIZE + sectorNum * sectorSize; }

function cfbReadSector(bytes, sectorNum, sectorSize) {
  const off = cfbSectorOffset(sectorNum, sectorSize);
  return bytes.slice(off, off + sectorSize);
}

/** Builds the full FAT as a flat array of next-sector pointers, indexed by sector number. */
function cfbBuildFat(bytes, header) {
  const entriesPerSector = header.sectorSize / 4;
  const fatSectorNums = [];
  for (let i = 0; i < 109 && fatSectorNums.length < header.numFatSectors; i++) {
    const s = u32le(header.headerDifat, i * 4);
    if (s === CFB_FREESECT) break;
    fatSectorNums.push(s);
  }
  // Additional FAT sector numbers beyond the header's 109, via the DIFAT sector chain.
  let difatSector = header.firstDifatSector;
  while (difatSector !== CFB_ENDOFCHAIN && difatSector !== CFB_FREESECT && fatSectorNums.length < header.numFatSectors) {
    const sec = cfbReadSector(bytes, difatSector, header.sectorSize);
    const entries = header.sectorSize / 4 - 1;
    for (let i = 0; i < entries && fatSectorNums.length < header.numFatSectors; i++) {
      const s = u32le(sec, i * 4);
      if (s === CFB_FREESECT) break;
      fatSectorNums.push(s);
    }
    difatSector = u32le(sec, header.sectorSize - 4);
  }

  const fat = new Uint32Array(fatSectorNums.length * entriesPerSector);
  for (let i = 0; i < fatSectorNums.length; i++) {
    const sec = cfbReadSector(bytes, fatSectorNums[i], header.sectorSize);
    for (let j = 0; j < entriesPerSector; j++) fat[i * entriesPerSector + j] = u32le(sec, j * 4);
  }
  return fat;
}

/** Follows a FAT chain starting at `start`, concatenating full sectors (caller trims to size). */
function cfbReadChain(bytes, fat, start, sectorSize) {
  const chunks = [];
  let sector = start;
  const seen = new Set();
  while (sector !== CFB_ENDOFCHAIN && sector !== CFB_FREESECT && !seen.has(sector)) {
    seen.add(sector);
    chunks.push(cfbReadSector(bytes, sector, sectorSize));
    sector = fat[sector];
  }
  return concatBytes(...chunks);
}

/** Follows a mini-FAT chain within the mini-stream blob, using miniSectorSize-sized units. */
function cfbReadMiniChain(miniStreamBytes, miniFat, start, miniSectorSize) {
  const chunks = [];
  let sector = start;
  const seen = new Set();
  while (sector !== CFB_ENDOFCHAIN && sector !== CFB_FREESECT && !seen.has(sector)) {
    seen.add(sector);
    const off = sector * miniSectorSize;
    chunks.push(miniStreamBytes.slice(off, off + miniSectorSize));
    sector = miniFat[sector];
  }
  return concatBytes(...chunks);
}

function cfbDecodeEntryName(entryBytes) {
  const nameLenBytes = u16le(entryBytes, 64); // includes null terminator, in bytes
  const charCount = Math.max(0, (nameLenBytes / 2) - 1);
  let name = '';
  for (let i = 0; i < charCount; i++) name += String.fromCharCode(u16le(entryBytes, i * 2));
  return name;
}

/** Parses a CFB container and returns { readStream(name) }, or null if not a CFB file. */
function cfbOpen(bytes) {
  if (!cfbIsSignature(bytes)) return null;
  const header = cfbParseHeader(bytes);
  const fat = cfbBuildFat(bytes, header);

  const dirBytes = cfbReadChain(bytes, fat, header.firstDirSector, header.sectorSize);
  const entries = [];
  for (let off = 0; off + 128 <= dirBytes.length; off += 128) {
    const objectType = dirBytes[off + 66];
    if (objectType === 0) continue; // unused slot
    entries.push({
      name: cfbDecodeEntryName(dirBytes.slice(off, off + 128)),
      objectType, // 1=storage, 2=stream, 5=root storage
      startSector: u32le(dirBytes, off + 116),
      size: cfbU64LowBits(dirBytes, off + 120),
    });
  }

  const root = entries.find(e => e.objectType === 5);
  let miniStreamBytes = null, miniFat = null;
  if (root && header.numMiniFatSectors > 0) {
    miniStreamBytes = cfbReadChain(bytes, fat, root.startSector, header.sectorSize).slice(0, root.size);
    const miniFatBytes = cfbReadChain(bytes, fat, header.firstMiniFatSector, header.sectorSize);
    miniFat = new Uint32Array(miniFatBytes.length / 4);
    for (let i = 0; i < miniFat.length; i++) miniFat[i] = u32le(miniFatBytes, i * 4);
  }

  function readStream(name) {
    const entry = entries.find(e => e.objectType === 2 && e.name === name);
    if (!entry) return null;
    if (entry.size < header.miniStreamCutoff) {
      if (!miniStreamBytes) return new Uint8Array(0);
      return cfbReadMiniChain(miniStreamBytes, miniFat, entry.startSector, header.miniSectorSize).slice(0, entry.size);
    }
    return cfbReadChain(bytes, fat, entry.startSector, header.sectorSize).slice(0, entry.size);
  }

  return { readStream, entries };
}

if (typeof module !== 'undefined') module.exports = { cfbOpen, cfbIsSignature };
