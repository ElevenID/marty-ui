package dev.marty.keycloak.kms;

import java.util.List;
import java.util.stream.Stream;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Overrides generated providers without making private material. Unimplemented
 * algorithms advertise no keys, causing callers to fail without local fallback.
 */
abstract class FailClosedKeyFactory implements KeyProviderFactory<KeyProvider> {
    private final String id;

    FailClosedKeyFactory(String id) {
        this.id = id;
    }

    @Override
    public final String getId() {
        return id;
    }

    @Override
    public final int order() {
        return 1;
    }

    @Override
    public final String getHelpText() {
        return "Remote KMS custody required";
    }

    @Override
    public final List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        return () -> Stream.<KeyWrapper>empty();
    }
}
