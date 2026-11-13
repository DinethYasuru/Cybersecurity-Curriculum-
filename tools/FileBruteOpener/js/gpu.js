/* WebGPU availability detection and a simple CPU worker-scaling benchmark. The benchmark
   measures real throughput of this app's own MD5-based candidate testing (not a generic
   number), so the dashboard reports numbers that match what a search will actually see. */

async function detectWebGpu() {
  if (!('gpu' in navigator)) return { available: false, reason: 'navigator.gpu is undefined (WebGPU not supported in this browser).' };
  try {
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) return { available: false, reason: 'No WebGPU adapter available.' };
    const info = adapter.info || {};
    return { available: true, vendor: info.vendor || 'unknown', architecture: info.architecture || 'unknown',
      note: 'WebGPU adapter detected. This app does not run password-candidate testing on the GPU; CPU workers are used for correctness and portability across the supported formats.' };
  } catch (e) {
    return { available: false, reason: String(e && e.message || e) };
  }
}

/** Runs a fixed MD5 workload single-threaded for `durationMs`, returning hashes/sec. */
function cpuHashBenchmarkSync(durationMs) {
  const start = performance.now();
  let count = 0;
  const probe = strToBytes('benchmark-probe-password');
  while (performance.now() - start < durationMs) {
    md5(probe);
    count++;
  }
  const elapsed = (performance.now() - start) / 1000;
  return count / elapsed;
}

/** Scales the benchmark across 1..maxWorkers Web Workers (using the shared worker-pool
 * script) and reports aggregate throughput, to show real multi-core scaling. */
async function runCpuScalingBenchmark(maxWorkers, perWorkerMs = 300, onProgress) {
  const results = [];
  for (let n = 1; n <= maxWorkers; n++) {
    const pool = createWorkerPool(n);
    const start = performance.now();
    const counts = await Promise.all(pool.workers.map(w => benchmarkOneWorker(w, perWorkerMs)));
    const elapsed = (performance.now() - start) / 1000;
    const total = counts.reduce((a, b) => a + b, 0);
    const rate = total / elapsed;
    results.push({ workers: n, hashesPerSec: rate });
    pool.terminate();
    if (onProgress) onProgress(n, maxWorkers, rate);
  }
  return results;
}

function benchmarkOneWorker(worker, durationMs) {
  return new Promise((resolve, reject) => {
    const id = 'bench-' + Math.random().toString(36).slice(2);
    const handler = (ev) => {
      if (!ev.data || ev.data.id !== id) return;
      worker.removeEventListener('message', handler);
      if (ev.data.type === 'benchResult') resolve(ev.data.count);
      else if (ev.data.type === 'benchError') reject(new Error(ev.data.message));
    };
    worker.addEventListener('message', handler);
    worker.postMessage({ type: 'bench', id, durationMs });
  });
}

if (typeof module !== 'undefined') module.exports = { detectWebGpu, cpuHashBenchmarkSync, runCpuScalingBenchmark };
