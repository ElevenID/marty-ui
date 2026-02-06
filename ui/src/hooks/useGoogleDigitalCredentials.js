import { useState, useCallback } from 'react';

export const useGoogleDigitalCredentials = () => {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [proof, setProof] = useState(null);

    const requestAgeProof = useCallback(async (nonce) => {
        setLoading(true);
        setError(null);
        try {
            if (!navigator.identity || !navigator.identity.get) {
                throw new Error('Digital Credentials API not supported in this browser');
            }

            const request = {
                digital: {
                    providers: [{
                        protocol: 'openid4vp', // or specific google protocol
                        request: {
                            // This structure depends on the specific Draft for Digital Credentials API
                            // Mapping to what "Longfellow" integration expects
                            selector: {
                                format: ['mdoc'],
                                doctype: 'org.iso.18013.5.1.mDL',
                                fields: [
                                    {
                                        name: 'age_over_18',
                                        intent_to_retain: false
                                    }
                                ]
                            },
                            nonce: nonce
                        }
                    }]
                },
                mediation: 'required'
            };

            const credential = await navigator.identity.get(request);
            
            // Credential will contain the ZK proof in the response
            setProof(credential);
            return credential;

        } catch (err) {
            setError(err.message);
            throw err;
        } finally {
            setLoading(false);
        }
    }, []);

    return {
        requestAgeProof,
        loading,
        error,
        proof
    };
};
