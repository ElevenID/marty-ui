import { useState, useCallback } from 'react';
import {
    DEFAULT_DC_API_PROTOCOL,
    formatDigitalCredentialError,
    requestOpenId4VpCredential,
    runOpenId4VpDigitalCredentialFlow,
    submitDigitalCredentialResponse,
    supportsDigitalCredentials,
} from '../services/digitalCredentialsApi';

export const useGoogleDigitalCredentials = () => {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [proof, setProof] = useState(null);

    const runCredentialRequest = useCallback(async ({
        requestUrl,
        submitUrl,
        requestJwt,
        protocol = DEFAULT_DC_API_PROTOCOL,
        fetchImpl,
    } = {}) => {
        setLoading(true);
        setError(null);
        try {
            if (requestUrl && submitUrl) {
                const result = await runOpenId4VpDigitalCredentialFlow({
                    requestUrl,
                    submitUrl,
                    protocol,
                    fetchImpl,
                });
                setProof(result);
                return result;
            }

            if (requestJwt) {
                const supported = await supportsDigitalCredentials(protocol);
                if (!supported) {
                    throw new Error('Digital Credentials API is not available in this browser.');
                }
                const credential = await requestOpenId4VpCredential({ requestJwt, protocol });
                if (!submitUrl) {
                    setProof(credential);
                    return credential;
                }
                const result = await submitDigitalCredentialResponse({
                    submitUrl,
                    credential,
                    protocol,
                    fetchImpl,
                });
                setProof(result);
                return result;
            }

            throw new Error('OpenID4VP requestUrl/submitUrl or requestJwt is required.');

        } catch (err) {
            setError(formatDigitalCredentialError(err));
            throw err;
        } finally {
            setLoading(false);
        }
    }, []);

    const requestAgeProof = useCallback(async (requestOrNonce, options = {}) => {
        const params = typeof requestOrNonce === 'object' && requestOrNonce !== null
            ? requestOrNonce
            : options;
        return runCredentialRequest(params);
    }, [runCredentialRequest]);

    return {
        requestAgeProof,
        runCredentialRequest,
        loading,
        error,
        proof
    };
};
