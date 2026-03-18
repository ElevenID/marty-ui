export const DEFAULT_BIOMETRIC_CAMERA_CONSTRAINTS = {
  video: { facingMode: 'user', width: 640, height: 480 },
  audio: false,
};

export const BIOMETRIC_CAPTURE_ERROR_MESSAGE = 'Failed to access camera. Please grant camera permissions.';

export function getBiometricCaptureTitle(biometricType = 'FACIAL') {
  return biometricType === 'FACIAL' ? 'Facial Capture' : `${biometricType} Capture`;
}

export function getBiometricCameraConstraints() {
  return {
    ...DEFAULT_BIOMETRIC_CAMERA_CONSTRAINTS,
    video: { ...DEFAULT_BIOMETRIC_CAMERA_CONSTRAINTS.video },
  };
}

export function resolveCameraStarted(stream) {
  return {
    stream,
    isCapturing: true,
    error: null,
  };
}

export function resolveCameraStartFailed(error = BIOMETRIC_CAPTURE_ERROR_MESSAGE) {
  return {
    stream: null,
    isCapturing: false,
    error,
  };
}

export function resolveCameraStopped() {
  return {
    stream: null,
    isCapturing: false,
  };
}

export function buildBiometricCapturePayload({ imageData, biometricType = 'FACIAL' }) {
  const base64Data = imageData.split(',')[1];

  return {
    biometric_type: biometricType,
    template_data_base64: base64Data,
    image_data_base64: base64Data,
    capture_quality_score: 0.95,
    is_live_capture: true,
  };
}

export function resolveBiometricCaptureSuccess({ imageData, biometricType = 'FACIAL' }) {
  return {
    capturedImage: imageData,
    capturePayload: buildBiometricCapturePayload({ imageData, biometricType }),
  };
}

export function resolveBiometricRetake() {
  return {
    capturedImage: null,
  };
}