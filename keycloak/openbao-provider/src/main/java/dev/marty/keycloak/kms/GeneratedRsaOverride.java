package dev.marty.keycloak.kms;

import java.util.stream.Stream;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public final class GeneratedRsaOverride extends FailClosedKeyFactory {
    public GeneratedRsaOverride() {
        super("rsa-generated");
    }

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        requireSafeConfig(model);
        RealmModel realm = session.realms().getRealm(model.getParentId());
        if (realm == null) {
            throw new IllegalStateException("Remote RS256 realm is missing");
        }
        TransitKey transit = TransitKey.forRealm(realm.getName(), "rs256");
        KeyWrapper key = new KeyWrapper();
        key.setProviderId(model.getId());
        key.setProviderPriority(model.get("priority", 100));
        key.setKid(transit.kid());
        key.setUse(KeyUse.SIG);
        key.setType("RSA");
        key.setAlgorithm("RS256");
        key.setStatus(KeyStatus.from(model.get("active", true),
                model.get("enabled", true)));
        var publicKey = transit.publicKey();
        key.setPublicKey(publicKey);
        key.setCertificate(transit.certificate(publicKey));
        return () -> Stream.of(key);
    }
}
