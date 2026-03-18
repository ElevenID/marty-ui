import { describe, expect, it, vi } from 'vitest';

import {
  captureBiometricSample,
  startBiometricCaptureCamera,
  stopBiometricCaptureCamera,
} from './biometricCaptureUseCases';

describe('biometricCapture use cases', () => {
  it('starts camera access through injected getUserMedia', async () => {
    const stream = { id: 'stream-1' };
    const getUserMedia = vi.fn().mockResolvedValue(stream);

    await expect(startBiometricCaptureCamera({ getUserMedia })).resolves.toEqual({
      stream,
      isCapturing: true,
      error: null,
    });
    expect(getUserMedia).toHaveBeenCalled();
  });

  it('returns a stable error state when camera access fails', async () => {
    const getUserMedia = vi.fn().mockRejectedValue(new Error('denied'));

    await expect(startBiometricCaptureCamera({ getUserMedia })).resolves.toEqual({
      stream: null,
      isCapturing: false,
      error: 'Failed to access camera. Please grant camera permissions.',
    });
  });

  it('stops all media tracks', () => {
    const stop = vi.fn();
    const stream = {
      getTracks: vi.fn().mockReturnValue([{ stop }, { stop }]),
    };

    expect(stopBiometricCaptureCamera({ stream })).toEqual({
      stream: null,
      isCapturing: false,
    });
    expect(stop).toHaveBeenCalledTimes(2);
  });

  it('captures image data through injected frame capture logic', () => {
    const stopCamera = vi.fn();

    expect(captureBiometricSample({
      captureFrame: () => 'data:image/jpeg;base64,abc123',
      biometricType: 'FACIAL',
      stopCamera,
    })).toEqual({
      capturedImage: 'data:image/jpeg;base64,abc123',
      capturePayload: {
        biometric_type: 'FACIAL',
        template_data_base64: 'abc123',
        image_data_base64: 'abc123',
        capture_quality_score: 0.95,
        is_live_capture: true,
      },
    });

    expect(stopCamera).toHaveBeenCalled();
    expect(captureBiometricSample({ captureFrame: () => null, biometricType: 'IRIS' })).toBeNull();
  });
});
