import { useEffect } from "react";
import QRCode from "react-qr-code";
import { useZkAgeVerification } from "../hooks/useZkAgeVerification";
import {
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Typography,
  Alert,
} from "@mui/material";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";

/**
 * Component for proving Age Over 18 via ZK Proof
 */
const ZkVerificationComponent = ({ onVerified }) => {
  const { loading, error, session, verificationResult, startSession, reset } =
    useZkAgeVerification();

  useEffect(() => {
    // Start session on mount
    startSession();
  }, [startSession]);

  useEffect(() => {
    if (verificationResult?.valid && onVerified) {
      onVerified(verificationResult);
    }
  }, [verificationResult, onVerified]);

  const handleRetry = () => {
    reset();
    startSession();
  };

  if (loading && !session) {
    return <CircularProgress />;
  }

  if (error) {
    return (
      <Card
        variant="outlined"
        sx={{ maxWidth: 400, m: 2, textAlign: "center" }}
      >
        <CardContent>
          <ErrorIcon color="error" sx={{ fontSize: 60, mb: 2 }} />
          <Typography variant="h6" color="error" gutterBottom>
            Verification Error
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            {error}
          </Typography>
          <Button variant="contained" onClick={handleRetry}>
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (verificationResult) {
    return (
      <Card
        variant="outlined"
        sx={{ maxWidth: 400, m: 2, textAlign: "center" }}
      >
        <CardContent>
          {verificationResult.valid ? (
            <>
              <CheckCircleIcon color="success" sx={{ fontSize: 60, mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                Verified Over 18
              </Typography>
              <Alert severity="success" sx={{ mt: 2 }}>
                Zero-Knowledge Proof Validated
              </Alert>
            </>
          ) : (
            <>
              <ErrorIcon color="error" sx={{ fontSize: 60, mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                Verification Failed
              </Typography>
              <Alert severity="error" sx={{ mt: 2 }}>
                {verificationResult.error || "Proof invalid"}
              </Alert>
              <Button variant="outlined" onClick={handleRetry} sx={{ mt: 2 }}>
                Try Again
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card variant="outlined" sx={{ maxWidth: 400, m: 2, textAlign: "center" }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Verify Age with mDL
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Scan this QR code with your Marty Authenticator app to prove you are
          over 18 without revealing your date of birth.
        </Typography>

        {session && (
          <Box
            sx={{
              p: 2,
              bgcolor: "white",
              display: "inline-block",
              borderRadius: 2,
            }}
          >
            <QRCode
              value={JSON.stringify({
                type: "zk_challenge",
                session_id: session.session_id,
                nonce: session.nonce,
                host: window.location.origin,
              })}
              size={200}
            />
          </Box>
        )}

        <Box sx={{ mt: 2 }}>
          {loading ? (
            <CircularProgress size={24} />
          ) : (
            <Typography variant="caption" color="text.secondary">
              Waiting for scan...
            </Typography>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default ZkVerificationComponent;
