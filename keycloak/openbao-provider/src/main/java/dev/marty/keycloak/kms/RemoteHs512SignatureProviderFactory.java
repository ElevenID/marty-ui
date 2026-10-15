package dev.marty.keycloak.kms;

import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Sends Keycloak's HS512 operations to a versioned OpenBao HMAC key. */
public final class RemoteHs512SignatureProviderFactory implements SignatureProviderFactory {
    @Override
    public String getId() {
        return "HS512";
    }

    @Override
    public int order() {
        return 1;
    }

    @Override
    public SignatureProvider create(KeycloakSession session) {
        return new SignatureProvider() {
            @Override
            public SignatureSignerContext signer() {
                RealmModel realm = realm();
                return signer(session.keys().getActiveKey(realm, KeyUse.SIG, "HS512"));
            }

            @Override
            public SignatureSignerContext signer(KeyWrapper key) {
                TransitKey transit = bound(key);
                return new SignatureSignerContext() {
                    @Override public String getKid() { return key.getKid(); }
                    @Override public String getAlgorithm() { return "HS512"; }
                    @Override public String getHashAlgorithm() { return "SHA-512"; }
                    @Override public byte[] sign(byte[] input) {
                        try {
                            return transit.hmac(input);
                        } catch (IllegalStateException error) {
                            throw new SignatureException("Remote HS512 signing unavailable", error);
                        }
                    }
                };
            }

            @Override
            public SignatureVerifierContext verifier(String kid) throws VerificationException {
                return verifier(session.keys().getKey(realm(), kid, KeyUse.SIG, "HS512"));
            }

            @Override
            public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
                TransitKey transit = bound(key);
                return new SignatureVerifierContext() {
                    @Override public String getKid() { return key.getKid(); }
                    @Override public String getAlgorithm() { return "HS512"; }
                    @Override public boolean verify(byte[] input, byte[] signature) {
                        return transit.verifyHmac(input, signature);
                    }
                };
            }

            @Override
            public boolean isAsymmetricAlgorithm() {
                return false;
            }

            private RealmModel realm() {
                RealmModel realm = session.getContext().getRealm();
                if (realm == null) {
                    throw new SignatureException("Remote HS512 realm is missing");
                }
                return realm;
            }

            private TransitKey bound(KeyWrapper key) {
                if (key == null || !"HS512".equals(key.getAlgorithm())
                        || key.getSecretKey() != null) {
                    throw new SignatureException("Remote HS512 key is unavailable");
                }
                TransitKey transit = TransitKey.forRealm(realm().getName(), "hs512");
                if (!transit.kid().equals(key.getKid())) {
                    throw new SignatureException("Remote HS512 key binding is invalid");
                }
                return transit;
            }
        };
    }
}
