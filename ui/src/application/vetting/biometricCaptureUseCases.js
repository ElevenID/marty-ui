import {
  BIOMETRIC_CAPTURE_ERROR_MESSAGE,
  getBiometricCameraConstraints,
  resolveBiometricCaptureSuccess,
  resolveCameraStartFailed,
  resolveCameraStarted,
  resolveCameraStopped,
} from './biometricCaptureFlow';
import { checkFaceQuality } from '../../wasm/biometricsWasm';

export async function startBiometricCaptureCamera({ getUserMedia, constraints = getBiometricCameraConstraints() }) {
  try {
    const stream = await getUserMedia(constraints);
    return resolveCameraStarted(stream);
  } catch (error) {
    return resolveCameraStartFailed(BIOMETRIC_CAPTURE_ERROR_MESSAGE);
  }
}

export function stopBiometricCaptureCamera({ stream }) {
  if (stream) {
    stream.getTracks().forEach((track) => track.stop());
  }

  return resolveCameraStopped();
}

export function captureBiometricSample({ captureFrame, biometricType, stopCamera }) {
  const imageData = captureFrame();
  if (!imageData) return null;

  stopCamera?.();

  return resolveBiometricCaptureSuccess({ imageData, biometricType });
}

/**
 * Capture a biometric sample with an optional WASM-based quality gate.
 *
 * If the WASM module is available, assesses quality client-side before
 * accepting the capture.  Falls through gracefully when WASM is absent.
 *
 * @param {object} params
 * @param {Function} params.captureFrame  Returns a data-URL image string.
 * @param {string}   params.biometricType 'FACIAL' | 'FINGERPRINT' | 'IRIS'
 * @param {Function} [params.stopCamera]
 * @param {number}   [params.minQuality=0.4]  Minimum acceptable quality score.
 * @returns {Promise<{capturedImage, capturePayload, quality?}|null>}
 */
export async function captureBiometricSampleWithQuality({
  captureFrame,
  biometricType,
  stopCamera,
  minQuality = 0.4,
}) {
  const imageData = captureFrame();
  if (!imageData) return null;

  // Client-side quality gate (non-blocking if WASM unavailable)
  const qualityCheck = await checkFaceQuality(imageData, minQuality);
  if (qualityCheck && !qualityCheck.ok) {
    return { capturedImage: imageData, capturePayload: null, quality: qualityCheck };
  }

  stopCamera?.();

  const result = resolveBiometricCaptureSuccess({ imageData, biometricType });
  return { ...result, quality: qualityCheck };
}