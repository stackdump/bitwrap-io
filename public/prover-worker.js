// Web Worker for WASM Groth16 prover — runs off the main thread.
// The main thread communicates via postMessage.

let proverReady = false;

// Load Go WASM runtime inside the worker
importScripts('./wasm_exec.js');

async function initWasm() {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(fetch('./prover.wasm'), go.importObject);
  go.run(result.instance);

  // Wait for bitwrapProver global
  for (let i = 0; i < 100; i++) {
    if (typeof bitwrapProver !== 'undefined') {
      proverReady = true;
      return;
    }
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('WASM prover did not initialize');
}

const initPromise = initWasm().catch(e => {
  postMessage({ type: 'error', error: `WASM init failed: ${e.message}` });
});

onmessage = async function(e) {
  const { id, type, payload } = e.data;

  try {
    await initPromise;
    if (!proverReady) throw new Error('Prover not ready');

    let result;
    switch (type) {
      case 'loadKeys': {
        const { name, csBytes, pkBytes, vkBytes } = payload;
        result = bitwrapProver.loadKeys(name, csBytes, pkBytes, vkBytes);
        if (result.error) throw new Error(result.error);
        postMessage({ id, type: 'loadKeys', result });
        break;
      }

      case 'loadVerifyOnly': {
        const { name, vkBytes } = payload;
        result = bitwrapProver.loadVerifyOnly(name, vkBytes);
        if (result.error) throw new Error(result.error);
        postMessage({ id, type: 'loadVerifyOnly', result });
        break;
      }

      case 'prove': {
        const { circuit, witness } = payload;
        result = bitwrapProver.prove(circuit, JSON.stringify(witness));
        if (result.error) throw new Error(result.error);
        postMessage({ id, type: 'prove', result: {
          proof: result.proof,
          publicWitness: result.publicWitness,
        }});
        break;
      }

      case 'verify': {
        const { circuit, proof, publicWitness } = payload;
        result = bitwrapProver.verify(circuit, proof, publicWitness);
        postMessage({ id, type: 'verify', result });
        break;
      }

      case 'mimcHash': {
        const { args } = payload;
        result = bitwrapProver.mimcHash(...args.map(String));
        if (typeof result === 'object' && result.error) throw new Error(result.error);
        postMessage({ id, type: 'mimcHash', result: String(result) });
        break;
      }

      case 'listCircuits': {
        result = bitwrapProver.listCircuits();
        postMessage({ id, type: 'listCircuits', result });
        break;
      }

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  } catch (err) {
    postMessage({ id, type: 'error', error: err.message });
  }
};
