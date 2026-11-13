/* Optional WASM acceleration for rc4() (see js/rc4.js and js/md5-wasm.js for the same idea
 * applied to MD5). Profiling found that for PDF R3/R4, RC4's own mandatory 256-round key
 * setup - called ~20 times per password candidate in the owner/user verifier chain - is the
 * actual bottleneck, not MD5 (which the WASM MD5 module already addresses but which turned
 * out to be a smaller fraction of total time than expected once accelerated). Source:
 * wasm-src/rc4.c (not loaded at runtime, kept for transparency/rebuilding - see
 * wasm-src/README.md); compiled with `clang --target=wasm32 -O3 -nostdlib`. Validated against
 * three independent published RC4 test vectors and 3000 random trials against the already
 * -tested pure-JS implementation before being embedded. js/rc4.js remains the fallback if
 * WebAssembly is unavailable or instantiation fails - never load-bearing for correctness. */

const RC4_WASM_BASE64 =
  'AGFzbQEAAAABCgJgAAF/YAJ/fwADAwIAAQQFAXABAQEFAwEAAgYIAX8BQcCMBAsHHQMGbWVtb3J5AgAKZ2V0X2J1ZmZlcgAAA3JjNAABCpEDAggAQYCIgIAAC4UDAQV/QQchAgNAIAJBgIiAgABqIAI6AAAgAkH5h4CAAGogAkF5aiIDOgAAIAJB/4eAgABqIANBBmo6AAAgAkH+h4CAAGogA0EFajoAACACQf2HgIAAaiADQQRqOgAAIAJB/IeAgABqIANBA2o6AAAgAkH7h4CAAGogA0ECajoAACACQfqHgIAAaiADQQFqOgAAIAJB/wFHIQMgAkEIaiECIAMNAAtBACEDQQAhAgNAIAJBgIiAgABqIgQgBC0AACIEIANqIAIgAHBBgIqAgABqLQAAaiIDQf8BcUGAiICAAGoiBS0AADoAACAFIAQ6AAAgAkEBaiICQYACRw0ACwJAIAFFDQBBACECQQAhBUEAIQADQCAFQQFqQf8BcSIFQYCIgIAAaiIDIAMtAAAiBCAAaiIAQf8BcUGAiICAAGoiBi0AADoAACAGIAQ6AAAgAkHAioCAAGoiBiAEIAMtAABqQf8BcUGAiICAAGotAAAgBi0AAHM6AAAgASACQQFqIgJHDQALCwsAPQRuYW1lAAkIcmM0Lndhc20BFwIACmdldF9idWZmZXIBCHdhc21fcmM0BxIBAA9fX3N0YWNrX3BvaW50ZXIAOAlwcm9kdWNlcnMBDHByb2Nlc3NlZC1ieQEMVWJ1bnR1IGNsYW5nETE4LjEuMyAoMXVidW50dTEpACwPdGFyZ2V0X2ZlYXR1cmVzAisPbXV0YWJsZS1nbG9iYWxzKwhzaWduLWV4dA==';

let rc4WasmReady = false;

function rc4WasmBase64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Attempts to swap the global rc4() for a WASM-backed one. Call once, early. Never throws:
 * on any failure, rc4() simply stays the pure-JS implementation. */
async function tryEnableRc4Wasm() {
  if (typeof WebAssembly === 'undefined') return false;
  try {
    const wasmBytes = rc4WasmBase64ToBytes(RC4_WASM_BASE64);
    const { instance } = await WebAssembly.instantiate(wasmBytes, {});
    const { rc4: wasmRc4Fn, get_buffer, memory } = instance.exports;
    const mem = new Uint8Array(memory.buffer);
    const ptr = get_buffer();
    const jsRc4 = rc4; // keep the already-tested pure-JS version as the fallback for edge cases
    const KEY_OFF = 256, DATA_OFF = 320, MAX_KEY_LEN = 32, MAX_DATA_LEN = 255; // must match rc4.c
    rc4 = function (key, data) {
      if (key.length > MAX_KEY_LEN || key.length === 0 || data.length > MAX_DATA_LEN) return jsRc4(key, data);
      mem.set(key, ptr + KEY_OFF);
      mem.set(data, ptr + DATA_OFF);
      wasmRc4Fn(key.length, data.length);
      return mem.slice(ptr + DATA_OFF, ptr + DATA_OFF + data.length);
    };
    rc4WasmReady = true;
    return true;
  } catch (e) {
    rc4WasmReady = false;
    return false;
  }
}

if (typeof module !== 'undefined') module.exports = { tryEnableRc4Wasm, RC4_WASM_BASE64 };
