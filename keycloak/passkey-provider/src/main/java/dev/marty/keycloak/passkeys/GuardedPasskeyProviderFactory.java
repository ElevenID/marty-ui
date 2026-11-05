package dev.marty.keycloak.passkeys;

import java.util.Map;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

/** Keep the native implementation and replace only its credential-removal policy. */
public final class GuardedPasskeyProviderFactory extends WebAuthnPasswordlessCredentialProviderFactory
        implements ServerInfoAwareProviderFactory {
    @Override
    public Map<String, String> getOperationalInfo() {
        return Map.of("martyPasskeyLifecycleGuard", "1");
    }

    @Override
    public int order() {
        return 100;
    }

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new GuardedPasskeyProvider(session, getMetadataService(), createOrGetObjectConverter());
    }
}
