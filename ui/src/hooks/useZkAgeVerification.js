import { useState, useCallback } from "react";
import {
  createZkChallenge,
  verifyZkProof,
} from "../services/zkVerificationApi";

/**
 * Hook for managing ZK Age Verification flow
 */
export const useZkAgeVerification = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [session, setSession] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);

  /**
   * Start a new verification session
   * @param {string} doctype - Document type (default: mDL)
   */
  const startSession = useCallback(
    async (doctype = "org.iso.18013.5.1.mDL") => {
      setLoading(true);
      setError(null);
      setVerificationResult(null);
      try {
        const result = await createZkChallenge({ doctype });
        setSession(result);
        return result;
      } catch (err) {
        setError(err.message || "Failed to start ZK session");
        setSession(null);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  /**
   * Submit proof for verification
   * @param {string} proof - Base64 proof
   * @param {string} mso - Base64 MSO
   */
  const verifyProof = useCallback(
    async (proof, mso) => {
      if (!session) {
        setError("No active session");
        return;
      }

      setLoading(true);
      setError(null);
      try {
        const result = await verifyZkProof({
          session_id: session.session_id,
          proof,
          mso,
        });
        setVerificationResult(result);
        return result;
      } catch (err) {
        setError(err.message || "Failed to verify proof");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [session],
  );

  /**
   * Reset state
   */
  const reset = useCallback(() => {
    setLoading(false);
    setError(null);
    setSession(null);
    setVerificationResult(null);
  }, []);

  return {
    loading,
    error,
    session,
    verificationResult,
    startSession,
    verifyProof,
    reset,
  };
};
