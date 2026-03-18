import { describe, expect, it } from 'vitest';

import {
  BIOMETRIC_CAPTURE_ERROR_MESSAGE,
  DEFAULT_BIOMETRIC_CAMERA_CONSTRAINTS,
  buildBiometricCapturePayload,
  getBiometricCameraConstraints,
  getBiometricCaptureTitle,
  resolveBiometricCaptureSuccess,
  resolveBiometricRetake,
  resolveCameraStarted,
  resolveCameraStartFailed,
  resolveCameraStopped,
} from './biometricCaptureFlow';

describe('biometricCaptureFlow helpers', () => {
  it('exposes stable camera defaults and titles', () => {
    expect(DEFAULT_BIOMETRIC_CAMERA_CONSTRAINTS).toEqual({
      video: { facingMode: 'user', width: 640, height: 480 },
      audio: false,
    });

    expect(getBiometricCameraConstraints()).toEqual(DEFAULT_BIOMETRIC_CAMERA_CONSTRAINTS);
    expect(getBiometricCaptureTitle('FACIAL')).toBe('Facial Capture');
    expect(getBiometricCaptureTitle('IRIS')).toBe('IRIS Capture');
  });

  it('builds camera start and stop state', () => {
    const stream = { id: 'stream-1' };

    expect(resolveCameraStarted(stream)).toEqual({
      stream,
      isCapturing: true,
      error: null,
    });

    expect(resolveCameraStartFailed()).toEqual({
      stream: null,
      isCapturing: false,
      error: BIOMETRIC_CAPTURE_ERROR_MESSAGE,
    });

    expect(resolveCameraStopped()).toEqual({
      stream: null,
      isCapturing: false,
    });
  });

  it('builds biometric payloads from captured image data', () => {
    const imageData = 'data:image/jpeg;base64,abc123';

    expect(buildBiometricCapturePayload({ imageData, biometricType: 'FACIAL' })).toEqual({
      biometric_type: 'FACIAL',
      template_data_base64: 'abc123',
      image_data_base64: 'abc123',
      capture_quality_score: 0.95,
      is_live_capture: true,
    });

    expect(resolveBiometricCaptureSuccess({ imageData, biometricType: 'IRIS' })).toEqual({
      capturedImage: imageData,
      capturePayload: {
        biometric_type: 'IRIS',
        template_data_base64: 'abc123',
        image_data_base64: 'abc123',
        capture_quality_score: 0.95,
        is_live_capture: true,
      },
    });

    expect(resolveBiometricRetake()).toEqual({ capturedImage: null });
  });
});
