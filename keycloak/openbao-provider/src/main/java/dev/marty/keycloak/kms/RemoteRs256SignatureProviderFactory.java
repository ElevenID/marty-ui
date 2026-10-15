package dev.marty.keycloak.kms;

import java.security.PublicKey;
import java.util.Arrays;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.AsymmetricSignatureProvider;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Replaces Keycloak's local RS256 signer while retaining public verification. */
public final class RemoteRs256SignatureProviderFactory implements SignatureProviderFactory {
    @Override
    public String getId() {
        return "RS256";
    }

    @Override
    public int order() {
        return 1;
    }

    @Override
    public SignatureProvider create(KeycloakSession session) {
        return new SignatureProvider() {
            private final AsymmetricSignatureProvider verifier =
                    new AsymmetricSignatureProvider(session, "RS256");

            @Override
            public SignatureSignerContext signer() {
                RealmModel realm = session.getContext().getRealm();
                if (realm == null) {
                    throw new SignatureException("Remote RS256 realm is missing");
                }
                return signer(session.keys().getActiveKey(realm, KeyUse.SIG, "RS256"));
            }

            @Override
            public SignatureSignerContext signer(KeyWrapper key) {
                RealmModel realm = session.getContext().getRealm();
                if (realm == null || key == null || !(key.getPublicKey() instanceof PublicKey publicKey)
                        || key.getPrivateKey() != null || !"RS256".equals(key.getAlgorithm())) {
                    throw new SignatureException("Remote RS256 key is unavailable");
                }
                TransitKey transit = TransitKey.forRealm(realm.getName(), "rs256");
                if (!transit.kid().equals(key.getKid())
                        || !Arrays.equals(transit.publicKey().getEncoded(), publicKey.getEncoded())) {
                    throw new SignatureException("Remote RS256 key binding is invalid");
                }
                return new SignatureSignerContext() {
                    @Override
                    public String getKid() {
                        return key.getKid();
                    }

                    @Override
                    public String getAlgorithm() {
                        return "RS256";
                    }

                    @Override
                    public String getHashAlgorithm() {
                        return "SHA-256";
                    }

                    @Override
                    public byte[] sign(byte[] input) {
                        try {
                            return transit.sign(input, publicKey);
                        } catch (IllegalStateException error) {
                            throw new SignatureException("Remote RS256 signing unavailable", error);
                        }
                    }
                };
            }

            @Override
            public SignatureVerifierContext verifier(String kid) throws VerificationException {
                return verifier.verifier(kid);
            }

            @Override
            public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
                return verifier.verifier(key);
            }

            @Override
            public boolean isAsymmetricAlgorithm() {
                return true;
            }
        };
    }
}
