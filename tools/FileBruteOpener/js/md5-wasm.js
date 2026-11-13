/* Optional WASM acceleration for md5() (see js/md5.js). This is a from-scratch, freestanding
 * C implementation (source: wasm-src/md5.c - not loaded at runtime, kept so the compiled
 * binary below isn't a black box) compiled with `clang --target=wasm32 -O3 -nostdlib`
 * (see wasm-src/README.md to rebuild). It was validated against Node's
 * crypto module across thousands of random inputs and all MD5 block-boundary edge cases
 * before being embedded, and js/md5.js's pure-JS implementation remains the fallback if
 * WebAssembly is unavailable or instantiation fails for any reason - never load-bearing for
 * correctness, only for speed. On real-world timing, this was roughly 6.5x faster than the
 * already-optimized pure-JS single-block path (which itself was ~6x faster than the original
 * naive implementation), for the realistic case: PDF R3/R4's mandatory key-derivation step
 * calls md5() 50+ times per password candidate, almost always on inputs under 20 bytes.
 *
 * Deliberately NOT used for Office's SHA-1 KDF or ZIP's PBKDF2/HMAC - those already go
 * through native, typically hardware-accelerated implementations (js/sha1.js is synchronous
 * JS by necessity - see its own comment - but isn't the dominant cost for formats that use
 * it), so there's no comparable win available there the way there is for MD5. */

const MD5_WASM_BASE64 =
  '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';

let md5WasmReady = false;

function md5WasmBase64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Attempts to swap the global md5() for a WASM-backed one. Call once, early (both the main
 * thread and each worker do this independently - see app.js and worker-pool.js). Never throws:
 * on any failure, md5() simply stays the pure-JS implementation. */
async function tryEnableMd5Wasm() {
  if (typeof WebAssembly === 'undefined') return false;
  try {
    const wasmBytes = md5WasmBase64ToBytes(MD5_WASM_BASE64);
    const { instance } = await WebAssembly.instantiate(wasmBytes, {});
    const { md5: wasmMd5Fn, get_buffer, memory } = instance.exports;
    const mem = new Uint8Array(memory.buffer);
    const ptr = get_buffer();
    const jsMd5 = md5; // keep the already-tested pure-JS version as the fallback for edge cases
    const OUT_OFFSET = 224, MAX_INPUT_LEN = 200; // must match md5.c's BUF_SIZE/OUT_OFFSET margins
    md5 = function (bytes) {
      if (bytes.length > MAX_INPUT_LEN) return jsMd5(bytes);
      mem.set(bytes, ptr);
      wasmMd5Fn(bytes.length);
      return mem.slice(ptr + OUT_OFFSET, ptr + OUT_OFFSET + 16);
    };
    md5WasmReady = true;
    return true;
  } catch (e) {
    md5WasmReady = false;
    return false;
  }
}

if (typeof module !== 'undefined') module.exports = { tryEnableMd5Wasm, MD5_WASM_BASE64 };
