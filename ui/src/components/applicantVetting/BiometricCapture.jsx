import { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Chip, Typography } from '@mui/material';
import {
  CameraAlt as CameraIcon,
  CheckCircle as CheckIcon,
  Face as FaceIcon,
  Fingerprint as FingerprintIcon,
  PhotoCamera as PhotoCameraIcon,
  RemoveRedEye as IrisIcon,
} from '@mui/icons-material';
import {
  captureBiometricSample,
  getBiometricCaptureTitle,
  resolveBiometricRetake,
  startBiometricCaptureCamera,
  stopBiometricCaptureCamera,
} from '../../application/vetting';

/**
 * Component for capturing facial biometrics using webcam.
 * Provides live video preview and capture functionality.
 */
export function BiometricCapture({ onCapture, biometricType = 'FACIAL', disabled = false }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const [stream, setStream] = useState(null);
  const [capturedImage, setCapturedImage] = useState(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [error, setError] = useState(null);

  const startCamera = async () => {
    const result = await startBiometricCaptureCamera({
      getUserMedia: (constraints) => navigator.mediaDevices.getUserMedia(constraints),
    });

    setStream(result.stream);
    setIsCapturing(result.isCapturing);
    setError(result.error);

    if (result.stream && videoRef.current) {
      videoRef.current.srcObject = result.stream;
    }

    if (result.error) {
      console.error('Camera access error:', result.error);
    }
  };

  const stopCamera = useCallback(() => {
    const result = stopBiometricCaptureCamera({ stream });
    setStream(result.stream);
    setIsCapturing(result.isCapturing);
  }, [stream]);

  const captureFrame = () => {
    if (!videoRef.current || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const video = videoRef.current;
    const context = canvas.getContext('2d');

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    context.drawImage(video, 0, 0);

    return canvas.toDataURL('image/jpeg', 0.9);
  };

  const captureImage = () => {
    const result = captureBiometricSample({
      captureFrame,
      biometricType,
      stopCamera,
    });

    if (!result) return;

    setCapturedImage(result.capturedImage);
    onCapture?.(result.capturePayload);
  };

  const retake = () => {
    setCapturedImage(resolveBiometricRetake().capturedImage);
    startCamera();
  };

  useEffect(() => () => {
    stopCamera();
  }, [stopCamera]);

  const getBiometricIcon = () => {
    switch (biometricType) {
      case 'FINGERPRINT':
        return <FingerprintIcon sx={{ fontSize: 48 }} />;
      case 'IRIS':
        return <IrisIcon sx={{ fontSize: 48 }} />;
      default:
        return <FaceIcon sx={{ fontSize: 48 }} />;
    }
  };

  return (
    <Box sx={{ textAlign: 'center' }}>
      <Typography variant="h6" gutterBottom>
        {getBiometricCaptureTitle(biometricType)}
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box
        sx={{
          width: 320,
          height: 240,
          mx: 'auto',
          mb: 2,
          border: '2px solid',
          borderColor: capturedImage ? 'success.main' : 'grey.400',
          borderRadius: 2,
          overflow: 'hidden',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: 'grey.100',
        }}
      >
        {capturedImage ? (
          <img src={capturedImage} alt="Captured" style={{ maxWidth: '100%', maxHeight: '100%' }} />
        ) : isCapturing ? (
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            style={{ maxWidth: '100%', maxHeight: '100%' }}
          />
        ) : (
          <Box sx={{ textAlign: 'center', p: 2 }}>
            {getBiometricIcon()}
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
              Click &quot;Start Camera&quot; to begin capture
            </Typography>
          </Box>
        )}
      </Box>

      <canvas ref={canvasRef} style={{ display: 'none' }} />

      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
        {!isCapturing && !capturedImage && (
          <Button
            variant="contained"
            startIcon={<CameraIcon />}
            onClick={startCamera}
            disabled={disabled}
          >
            Start Camera
          </Button>
        )}
        {isCapturing && (
          <>
            <Button
              variant="contained"
              color="primary"
              startIcon={<PhotoCameraIcon />}
              onClick={captureImage}
            >
              Capture
            </Button>
            <Button variant="outlined" onClick={stopCamera}>
              Cancel
            </Button>
          </>
        )}
        {capturedImage && (
          <>
            <Button variant="outlined" onClick={retake}>
              Retake
            </Button>
            <Chip icon={<CheckIcon />} label="Captured" color="success" />
          </>
        )}
      </Box>
    </Box>
  );
}
