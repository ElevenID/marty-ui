/**
 * Marty Biometrics WASM bridge.
 *
 * Loads the WASM module built from marty-core/marty-biometrics and exposes
 * a thin JS API for client-side quality assessment and mock verification.
 *
 * Build the WASM package first:
 *   cd marty-core/marty-biometrics
 *   wasm-pack build --target web --features wasm --no-default-features --out-dir ../../marty-ui/ui/src/wasm/marty-biometrics-pkg
 *
 * Usage:
 *   import { getBiometricsWasm } from '../wasm/biometricsWasm';
 *
 *   const wasm = await getBiometricsWasm();
 *   const quality = wasm.assessQuality(base64Image);
 */

let wasmInstance = null;
let wasmLoading = null;

/**
 * Lazily initialise and return the WASM module singleton.
 *
 * Returns `null` if the WASM package has not been built yet (the UI
 * continues to work — quality checks are skipped client-side and
 * performed server-side instead).
 */
export async function getBiometricsWasm() {
  if (wasmInstance) return wasmInstance;
  if (wasmLoading) return wasmLoading;

  wasmLoading = (async () => {
    try {
      // Dynamic import — use a variable so Rollup/Vite won't try to resolve
      // the path at build time (the package may not exist yet).
      const wasmPath = './marty-biometrics-pkg/marty_biometrics.js';
      const pkg = await import(/* @vite-ignore */ wasmPath);
      await pkg.default(); // calls wasm __init (sets panic hook)
      wasmInstance = pkg;
      return wasmInstance;
    } catch {
      console.warn(
        '[biometrics] WASM module not available — client-side quality gate disabled. ' +
        'Build with: wasm-pack build --target web --features wasm --no-default-features'
      );
      return null;
    }
  })();

  return wasmLoading;
}

/**
 * Run a client-side quality check on a captured frame.
 *
 * @param {string} base64Image  Data-URL or raw base64 face image.
 * @returns {Promise<{ok: boolean, score: number, assessment: object}|null>}
 *          `null` if WASM is unavailable.
 */
export async function checkFaceQuality(base64Image, minScore = 0.4) {
  const wasm = await getBiometricsWasm();
  if (!wasm) return null;

  // Use the WasmMockVerifier for now; once WASM ONNX is available this
  // will call the real model.
  const verifier = new wasm.WasmMockVerifier();
  const json = verifier.assessQuality(base64Image);
  const assessment = JSON.parse(json);

  return {
    ok: assessment.overall_score >= minScore,
    score: assessment.overall_score,
    assessment,
  };
}

/**
 * Run a client-side face match (mock in WASM, real match done server-side).
 *
 * @param {string} referenceB64  Base64-encoded reference image.
 * @param {string} probeB64      Base64-encoded probe image.
 * @param {number} [threshold]   Similarity threshold (0.0–1.0).
 * @returns {Promise<object|null>}
 */
export async function verifyFaceMatch(referenceB64, probeB64, threshold = 0.7) {
  const wasm = await getBiometricsWasm();
  if (!wasm) return null;

  const requestJson = wasm.create_verification_request(referenceB64, probeB64, threshold);
  const verifier = new wasm.WasmMockVerifier();
  const resultJson = verifier.verify(requestJson);
  return JSON.parse(resultJson);
}
