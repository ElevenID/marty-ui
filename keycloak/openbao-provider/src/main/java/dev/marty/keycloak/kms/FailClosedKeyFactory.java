package dev.marty.keycloak.kms;

import java.util.List;
import java.util.stream.Stream;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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
    public final void validateConfiguration(KeycloakSession session, RealmModel realm,
                                            ComponentModel model) {
        requireSafeConfig(model);
    }

    protected final void requireSafeConfig(ComponentModel model) {
        if (model.getConfig() == null) {
            return;
        }
        for (var entry : model.getConfig().entrySet()) {
            if (entry.getValue() == null || entry.getValue().size() != 1
                    || !safeValue(entry.getKey(), entry.getValue().get(0))) {
                throw new ComponentValidationException("Remote key providers reject local key configuration");
            }
        }
    }

    private boolean safeValue(String name, String value) {
        if (name == null || value == null) {
            return false;
        }
        return switch (name) {
            case "priority" -> value.matches("-?[0-9]{1,4}");
            case "active", "enabled" -> value.equals("true") || value.equals("false");
            case "keyUse" -> (id.equals("rsa-generated") && value.equals("SIG"))
                    || (id.equals("rsa-enc-generated") && value.equals("ENC"));
            case "algorithm" -> (id.equals("rsa-generated") && value.equals("RS256"))
                    || (id.equals("rsa-enc-generated") && value.equals("RSA-OAEP"))
                    || (id.equals("hmac-generated") && value.equals("HS512"))
                    || (id.equals("aes-generated") && value.equals("A256GCM"));
            default -> false;
        };
    }

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        requireSafeConfig(model);
        return () -> Stream.<KeyWrapper>empty();
    }
}
