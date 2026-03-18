// bitwrap WASM prover — client-side Groth16 proving
// Loads prover.wasm and exposes async API over bitwrapProver global

let _ready = null;
let _keyCache = {};

// Initialize the WASM prover. Call once, awaits loading.
export async function initProver(wasmUrl = './prover.wasm', execUrl = './wasm_exec.js') {
  if (_ready) return _ready;

  _ready = (async () => {
    // Load wasm_exec.js if Go runtime not present
    if (typeof Go === 'undefined') {
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = execUrl;
        script.onload = resolve;
        script.onerror = () => reject(new Error('Failed to load wasm_exec.js'));
        document.head.appendChild(script);
      });
    }

    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject);
    go.run(result.instance); // starts the Go main() goroutine

    // Wait for bitwrapProver to be set
    for (let i = 0; i < 100; i++) {
      if (typeof bitwrapProver !== 'undefined') return;
      await new Promise(r => setTimeout(r, 50));
    }
    throw new Error('WASM prover did not initialize');
  })();

  return _ready;
}

// Compile a circuit from scratch (slow — runs trusted setup in WASM).
// Returns { constraints, publicVars, privateVars } or throws.
export async function compileCircuit(name) {
  await initProver();
  const result = bitwrapProver.compileCircuit(name);
  if (result.error) throw new Error(result.error);
  return result;
}

// Load pre-compiled keys from the server (fast — skips compilation).
// Fetches .cs, .pk, .vk from keyUrl/{name}.cs etc.
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

  const result = bitwrapProver.loadKeys(name, csBytes, pkBytes, vkBytes);
  if (result.error) throw new Error(result.error);
  _keyCache[name] = result;
  return result;
}

// Generate a Groth16 proof. Returns { proof: Uint8Array, publicWitness: Uint8Array }.
// witness is an object with string keys and string values (decimal field elements).
export async function prove(circuitName, witness) {
  await initProver();
  const result = bitwrapProver.prove(circuitName, JSON.stringify(witness));
  if (result.error) throw new Error(result.error);
  return {
    proof: result.proof,
    publicWitness: result.publicWitness,
  };
}

// Verify a proof. Returns { valid: boolean, error?: string }.
export async function verify(circuitName, proof, publicWitness) {
  await initProver();
  return bitwrapProver.verify(circuitName, proof, publicWitness);
}

// Compute MiMC hash (convenience — also available in mimc.js without WASM).
export async function mimcHash(...args) {
  await initProver();
  const result = bitwrapProver.mimcHash(...args.map(String));
  if (typeof result === 'object' && result.error) throw new Error(result.error);
  return BigInt(result);
}

// List loaded circuits.
export async function listCircuits() {
  await initProver();
  return bitwrapProver.listCircuits();
}
