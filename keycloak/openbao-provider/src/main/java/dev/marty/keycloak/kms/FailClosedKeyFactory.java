package dev.marty.keycloak.kms;

import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Bootstrap probe: overrides Keycloak's generated providers without making
 * private material. Until remote operations are implemented, key use fails.
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
    public final KeyProvider create(KeycloakSession session, ComponentModel model) {
        throw new IllegalStateException(
                "Remote KMS key provider is not configured; local keys are forbidden");
    }
}
