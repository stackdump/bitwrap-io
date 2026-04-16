// bitwrap WASM prover — runs Groth16 proving in a Web Worker to avoid blocking UI.
// Falls back to main-thread execution if Workers are unavailable.

let _worker = null;
let _pending = {};
let _msgId = 0;
let _keyCache = {};
let _initPromise = null;

function sendWorkerMessage(type, payload) {
  return new Promise((resolve, reject) => {
    const id = ++_msgId;
    _pending[id] = { resolve, reject };
    _worker.postMessage({ id, type, payload });
  });
}

// Initialize the prover (Web Worker with WASM).
export async function initProver() {
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    if (typeof Worker !== 'undefined') {
      try {
        _worker = new Worker('./prover-worker.js');
        _worker.onmessage = (e) => {
          const { id, type, result, error } = e.data;
          if (id && _pending[id]) {
            if (type === 'error') {
              _pending[id].reject(new Error(error));
            } else {
              _pending[id].resolve(result);
            }
            delete _pending[id];
          }
        };
        _worker.onerror = (e) => {
          console.warn('Prover worker error, falling back to main thread:', e.message);
          _worker = null;
        };
        // Give the worker a moment to initialize
        await new Promise(r => setTimeout(r, 100));
        return;
      } catch (e) {
        console.warn('Worker creation failed, falling back to main thread:', e);
        _worker = null;
      }
    }

    // Fallback: load on main thread (blocks UI during prove)
    if (typeof Go === 'undefined') {
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = './wasm_exec.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('Failed to load wasm_exec.js'));
        document.head.appendChild(script);
      });
    }

    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(fetch('./prover.wasm'), go.importObject);
    go.run(result.instance);

    for (let i = 0; i < 100; i++) {
      if (typeof bitwrapProver !== 'undefined') return;
      await new Promise(r => setTimeout(r, 50));
    }
    throw new Error('WASM prover did not initialize');
  })();

  return _initPromise;
}

export async function compileCircuit(name) {
  await initProver();
  if (_worker) {
    return sendWorkerMessage('compileCircuit', { name });
  }
  const result = bitwrapProver.compileCircuit(name);
  if (result.error) throw new Error(result.error);
  return result;
}

export async function loadKeys(name, keyUrl) {
  await initProver();
  if (_keyCache[name]) return _keyCache[name];

  const [csResp, pkResp, vkResp] = await Promise.all([
    fetch(`${keyUrl}/${name}.cs`),
    fetch(`${keyUrl}/${name}.pk`),
    fetch(`${keyUrl}/${name}.vk`),
  ]);

  if (!csResp.ok || !pkResp.ok || !vkResp.ok) {
    throw new Error(`Failed to fetch keys for ${name}`);
  }

  const [csBytes, pkBytes, vkBytes] = await Promise.all([
    csResp.arrayBuffer().then(b => new Uint8Array(b)),
    pkResp.arrayBuffer().then(b => new Uint8Array(b)),
    vkResp.arrayBuffer().then(b => new Uint8Array(b)),
  ]);

  if (_worker) {
    const result = await sendWorkerMessage('loadKeys', { name, csBytes, pkBytes, vkBytes });
    _keyCache[name] = result;
    return result;
  }

  const result = bitwrapProver.loadKeys(name, csBytes, pkBytes, vkBytes);
  if (result.error) throw new Error(result.error);
  _keyCache[name] = result;
  return result;
}

// Load only the verifying key for a circuit. Used by the in-browser
// "Verify Proof" button so users don't have to download the proving
// key (which can be many MB for larger circuits). `vkUrl` should point
// to a raw gnark-serialized VerifyingKey — typically /api/vk/{name}.
export async function loadVerifyOnly(name, vkUrl) {
  await initProver();
  const cacheKey = `__verify:${name}`;
  if (_keyCache[cacheKey]) return _keyCache[cacheKey];

  const resp = await fetch(vkUrl);
  if (!resp.ok) {
    throw new Error(`VK fetch for ${name} failed: ${resp.status}`);
  }
  const vkBytes = new Uint8Array(await resp.arrayBuffer());

  if (_worker) {
    const result = await sendWorkerMessage('loadVerifyOnly', { name, vkBytes });
    _keyCache[cacheKey] = result;
    return result;
  }
  const result = bitwrapProver.loadVerifyOnly(name, vkBytes);
  if (result.error) throw new Error(result.error);
  _keyCache[cacheKey] = result;
  return result;
}

// Generate a Groth16 proof — runs in Web Worker (non-blocking).
export async function prove(circuitName, witness) {
  await initProver();
  if (_worker) {
    return sendWorkerMessage('prove', { circuit: circuitName, witness });
  }
  // Fallback: main thread (will block UI)
  const result = bitwrapProver.prove(circuitName, JSON.stringify(witness));
  if (result.error) throw new Error(result.error);
  return { proof: result.proof, publicWitness: result.publicWitness };
}

export async function verify(circuitName, proof, publicWitness) {
  await initProver();
  if (_worker) {
    return sendWorkerMessage('verify', { circuit: circuitName, proof, publicWitness });
  }
  return bitwrapProver.verify(circuitName, proof, publicWitness);
}

export async function mimcHash(...args) {
  await initProver();
  if (_worker) {
    const result = await sendWorkerMessage('mimcHash', { args: args.map(String) });
    return BigInt(result);
  }
  const result = bitwrapProver.mimcHash(...args.map(String));
  if (typeof result === 'object' && result.error) throw new Error(result.error);
  return BigInt(result);
}

export async function listCircuits() {
  await initProver();
  if (_worker) {
    return sendWorkerMessage('listCircuits', {});
  }
  return bitwrapProver.listCircuits();
}
