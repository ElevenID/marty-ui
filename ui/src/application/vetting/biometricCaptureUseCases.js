import {
  BIOMETRIC_CAPTURE_ERROR_MESSAGE,
  getBiometricCameraConstraints,
  resolveBiometricCaptureSuccess,
  resolveCameraStartFailed,
  resolveCameraStarted,
  resolveCameraStopped,
} from './biometricCaptureFlow';

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